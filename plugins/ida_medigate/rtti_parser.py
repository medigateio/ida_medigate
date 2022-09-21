import logging

import ida_name
import ida_struct
import idaapi
import idautils
import idc
from idaapi import BADADDR

from . import cpp_utils
from . import utils


class RTTIParser(object):
    RTTI_OBJ_STRUC_NAME = "rtti_obj"

    @classmethod
    def init_parser(cls):
        logging.basicConfig(
            filename="/tmp/cpp.log",
            filemode="a",
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        cls.found_classes = set()

    @classmethod
    def extract_rtti_info_from_data(cls, ea=None):
        if ea is None:
            ea = idc.here()
        typeinfo = cls.parse_rtti_header(ea)
        return cls.extract_rtti_info_from_typeinfo(typeinfo)

    @classmethod
    def extract_rtti_info_from_typeinfo(cls, typeinfo):
        if typeinfo in cls.found_classes:
            return
        rtti_obj = cls.parse_typeinfo(typeinfo)
        if rtti_obj is None:
            return
        logging.info("%s: Parsed typeinfo", rtti_obj.name)
        cls.found_classes.add(rtti_obj.typeinfo)
        for parent_typeinfo, _, offset in rtti_obj.raw_parents:
            parent_updated_name = None
            parent_rtti_obj = cls.extract_rtti_info_from_typeinfo(parent_typeinfo)
            if parent_rtti_obj:
                parent_updated_name = parent_rtti_obj.name
            else:
                built_rtti_obj_name = ida_name.get_ea_name(parent_typeinfo)
                if built_rtti_obj_name.endswith(cls.RTTI_OBJ_STRUC_NAME):
                    parent_updated_name = built_rtti_obj_name.rstrip(
                        "_" + cls.RTTI_OBJ_STRUC_NAME
                    )
            if parent_updated_name is not None:
                rtti_obj.updated_parents.append((parent_updated_name, offset))

        logging.debug("%s: Finish setup parents", rtti_obj.name)
        if not rtti_obj.create_structs():
            return False
        rtti_obj.make_rtti_obj_pretty()
        rtti_obj.find_vtables()
        return rtti_obj

    def __init__(self, parents, typeinfo):
        self.raw_parents = []
        self.updated_parents = []
        self.typeinfo = typeinfo
        self.orig_name = self.name = self.get_typeinfo_name(self.typeinfo)
        for parent_typeinf, parent_offset in parents:
            parent_name = self.get_typeinfo_name(parent_typeinf)
            if parent_name is not None:
                self.raw_parents.append((parent_typeinf, parent_name, parent_offset))
        self.struct_id = None
        self.struct_ptr = None

    def create_structs(self):
        self.name, self.struct_id = utils.add_struc_retry(self.name)
        if self.struct_id == BADADDR or self.name is None:
            return False
        self.struct_ptr = ida_struct.get_struc(self.struct_id)
        if self.struct_ptr is None:
            logging.exception("self.struct_ptr is None at %s", self.name)
        previous_parent_offset = 0
        previous_parent_size = 0
        previous_parent_struct_id = BADADDR
        for parent_name, parent_offset in self.updated_parents:
            if (
                parent_offset - previous_parent_offset > previous_parent_size
                and previous_parent_struct_id != BADADDR
            ):
                utils.expand_struct(
                    previous_parent_struct_id, parent_offset - previous_parent_offset
                )
            baseclass_id = ida_struct.get_struc_id(parent_name)
            baseclass_size = ida_struct.get_struc_size(baseclass_id)
            if baseclass_id == BADADDR or baseclass_size == 0:
                logging.warning(
                    "bad struct id or size: %s(0x%x:%s) - %s, %d",
                    self.name,
                    parent_offset,
                    parent_name,
                    baseclass_id,
                    baseclass_size,
                )

            cpp_utils.add_baseclass(self.name, parent_name, parent_offset)
            previous_parent_offset = parent_offset
            previous_parent_size = baseclass_size
            previous_parent_struct_id = baseclass_id
        if self.updated_parents:
            utils.refresh_struct(self.struct_ptr)

        return True

    def find_vtables(self):
        is_vtable_found = False
        for xref in utils.get_drefs(self.typeinfo):
            if self.try_parse_vtable(xref) is not None:
                is_vtable_found = True
        if not is_vtable_found:
            logging.debug(
                "find_vtable(%s): Couldn't find any vtable ->" " Interface!", self.name
            )
            if len(self.updated_parents) == 0:
                cpp_utils.install_vtables_union(self.name)
                pass

    def try_parse_vtable(self, ea):
        pass

    def create_vtable_struct(self, vtable_offset):
        return cpp_utils.create_vtable_struct(self.struct_ptr, self.name, vtable_offset)

    def make_rtti_obj_pretty(self):
        pass

    @classmethod
    def parse_rtti_header(cls, ea):
        pass

    @classmethod
    def parse_typeinfo(cls, typeinfo):
        pass

    def get_typeinfo_name(self, typeinfo):
        pass


class GccRTTIParser(RTTIParser):
    VMI = "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
    SI = "_ZTVN10__cxxabiv120__si_class_type_infoE"
    NONE = "_ZTVN10__cxxabiv117__class_type_infoE"
    OFFSET_FROM_TYPEINF_SYM = 2 * utils.WORD_LEN

    RECORD_TYPEINFO_OFFSET = utils.WORD_LEN
    # class_type_info consts
    CLASS_TYPE_TYPEINFO_OFFSET = 0
    CLASS_TYPE_NAME_OFFSET = utils.WORD_LEN
    CLASS_TYPE_SIZE = 2 * utils.WORD_LEN

    # si_class_type_info consts
    SI_TYPEINFO_BASE_OFFSET = CLASS_TYPE_SIZE

    # vmi_class_type_info consts
    VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET = CLASS_TYPE_SIZE + 4
    VMI_TYPEINFO_BASE_CLASSES_OFFSET = VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET + 4

    # base_class vmi helper
    BASE_CLASS_TYPEINFO_OFFSET = 0
    BASE_CLASS_ATTRS_OFFSET = BASE_CLASS_TYPEINFO_OFFSET + utils.WORD_LEN
    BASE_CLASS_SIZE = utils.WORD_LEN * 2

    pure_virtual_name = "__cxa_pure_virtual"

    @classmethod
    def init_parser(cls):
        super(GccRTTIParser, cls).init_parser()
        cls.type_vmi = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.VMI) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.type_si = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.SI) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.type_none = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.NONE) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.types = (cls.type_vmi, cls.type_si, cls.type_none)

    @classmethod
    def build_all(cls):
        for class_type in cls.types:
            logging.debug("Starting :%s %s" % (class_type, hex(class_type)))
            cls.build_class_type(class_type)
            logging.info("Done %s", class_type)

    @classmethod
    @utils.batchmode
    def build_class_type(cls, class_type):
        idx = 0
        for xref in idautils.XrefsTo(class_type - cls.OFFSET_FROM_TYPEINF_SYM):
            if (idx + 1) % 200 == 0:
                # idc.batch(0)
                logging.info("\t Done %s", idx)
                # ida_loader.save_database(None, 0)
                # idc.batch(1)
            if utils.get_ptr(xref.frm) != class_type:
                continue
            try:
                cls.extract_rtti_info_from_typeinfo(xref.frm)
            except Exception as e:
                logging.exception("Exception at 0x%x:", xref.frm)
            idx += 1

    @classmethod
    def parse_rtti_header(cls, ea):
        # offset = cls.read_offset(ea)
        typeinfo = cls.get_typeinfo_ea(ea)
        return typeinfo

    @classmethod
    def parse_typeinfo(cls, typeinfo):
        typeinfo_type = utils.get_ptr(typeinfo + cls.CLASS_TYPE_TYPEINFO_OFFSET)
        if typeinfo_type == cls.type_none:
            parents = []
        elif typeinfo_type == cls.type_si:
            parents = cls.parse_si_typeinfo(typeinfo)
        elif typeinfo_type == cls.type_vmi:
            parents = cls.parse_vmi_typeinfo(typeinfo)
        else:
            return None
        return GccRTTIParser(parents, typeinfo)

    @classmethod
    def parse_si_typeinfo(cls, typeinfo_ea):
        parent_typinfo_ea = utils.get_ptr(typeinfo_ea + cls.SI_TYPEINFO_BASE_OFFSET)
        return [(parent_typinfo_ea, 0)]

    @classmethod
    def parse_vmi_typeinfo(cls, typeinfo_ea):
        base_classes_num = idaapi.get_32bit(
            typeinfo_ea + cls.VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET
        )
        parents = []
        for i in range(base_classes_num):
            base_class_desc_ea = (
                typeinfo_ea
                + cls.VMI_TYPEINFO_BASE_CLASSES_OFFSET
                + i * cls.BASE_CLASS_SIZE
            )
            parent_typeinfo_ea = utils.get_ptr(
                base_class_desc_ea + cls.BASE_CLASS_TYPEINFO_OFFSET
            )
            parent_attrs = utils.get_word(
                base_class_desc_ea + cls.BASE_CLASS_ATTRS_OFFSET
            )
            parent_offset_in_cls = parent_attrs >> 8
            parents.append((parent_typeinfo_ea, parent_offset_in_cls))
        return parents

    @classmethod
    def get_typeinfo_ea(cls, ea):
        return utils.get_ptr(ea + cls.RECORD_TYPEINFO_OFFSET)

    @classmethod
    def get_typeinfo_name(cls, typeinfo_ea):
        name_ea = utils.get_ptr(typeinfo_ea + cls.CLASS_TYPE_NAME_OFFSET)
        if name_ea is None or name_ea == BADADDR:
            mangled_class_name = ida_name.get_ea_name(typeinfo_ea)
        else:
            mangled_class_name = "_Z" + idc.get_strlit_contents(name_ea).decode()
        class_name = ida_name.demangle_name(mangled_class_name, idc.INF_LONG_DN)
        return cls.strip_class_name(class_name)

    @classmethod
    def strip_class_name(cls, cls_name):
        pre_dict = {"`typeinfo for": ":"}
        words_dict = {
            "`anonymous namespace'": "ANONYMOUS",
            "`anonymous_namespace'": "ANONYMOUS",
            "`typeinfo for'": "",
        }
        chars_dict = {
            "<": "X",
            ">": "Z",
            "&": "A",
            "*": "P",
            " ": "_",
            ",": "C",
            "'": "U",
            "`": "T",
            "[": "O",
            "]": "P",
        }
        for target, strip in words_dict.items():
            cls_name = cls_name.replace(target, strip)
        for target, strip in chars_dict.items():
            cls_name = cls_name.replace(target, strip)
        return cls_name

    def try_parse_vtable(self, ea):
        functions_ea = ea + utils.WORD_LEN
        func_ea, _ = cpp_utils.get_vtable_line(
            functions_ea,
            ignore_list=self.types,
            pure_virtual_name=self.pure_virtual_name,
        )
        if func_ea is None:
            return
        vtable_offset = utils.get_signed_int(ea - utils.WORD_LEN) * (-1)
        vtable_struct, this_type = self.create_vtable_struct(vtable_offset)
        cpp_utils.update_vtable_struct(
            functions_ea,
            vtable_struct,
            self.name,
            this_type,
            ignore_list=self.types,
            pure_virtual_name=self.pure_virtual_name,
        )
        return vtable_struct
