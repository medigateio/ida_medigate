import logging

import ida_name
import ida_struct
import idautils
import idc
import idaapi
from idaapi import BADADDR

from . import cpp_utils
from . import utils

log = logging.getLogger("ida_medigate")


class RTTIParser(object):
    RTTI_OBJ_STRUC_NAME = "rtti_obj"

    def __init__(self, parents, typeinfo_ea):
        self.raw_parents = []
        self.updated_parents = []
        self.typeinfo_ea = typeinfo_ea
        self.orig_name = self.name = self.get_typeinfo_name(self.typeinfo_ea)
        for parent_typeinfo_ea, parent_offset in parents:
            parent_name = self.get_typeinfo_name(parent_typeinfo_ea)
            if parent_name is not None:
                self.raw_parents.append((parent_typeinfo_ea, parent_name, parent_offset))
        self.struct_id = None
        self.struct_ptr = None

    @classmethod
    def init_parser(cls):
        cls.found_classes = set()

    @classmethod
    def extract_rtti_info_from_data(cls, ea=None):
        if ea is None:
            ea = idc.here()
        typeinfo_ea = cls.parse_rtti_header(ea)
        return cls.extract_rtti_info_from_typeinfo(typeinfo_ea)

    @classmethod
    def extract_rtti_info_from_typeinfo(cls, typeinfo_ea):
        if typeinfo_ea in cls.found_classes:
            return None
        rtti_obj = cls.parse_typeinfo(typeinfo_ea)
        if rtti_obj is None:
            return None
        log.info("%s: Parsed typeinfo", rtti_obj.name)
        cls.found_classes.add(rtti_obj.typeinfo_ea)
        for parent_typeinfo_ea, _, offset in rtti_obj.raw_parents:
            parent_updated_name = None
            parent_rtti_obj = cls.extract_rtti_info_from_typeinfo(parent_typeinfo_ea)
            if parent_rtti_obj:
                parent_updated_name = parent_rtti_obj.name
            else:
                built_rtti_obj_name = ida_name.get_ea_name(parent_typeinfo_ea)
                if built_rtti_obj_name.endswith(cls.RTTI_OBJ_STRUC_NAME):
                    parent_updated_name = built_rtti_obj_name.rstrip("_" + cls.RTTI_OBJ_STRUC_NAME)
            if parent_updated_name is not None:
                rtti_obj.updated_parents.append((parent_updated_name, offset))

        log.debug("%s: Finish setup parents", rtti_obj.name)
        if not rtti_obj.create_structs():
            return None
        rtti_obj.make_rtti_obj_pretty()
        rtti_obj.find_vtables()
        return rtti_obj

    def create_structs(self):
        self.struct_id = utils.add_struc_retry(self.name)
        if self.struct_id == BADADDR:
            return False
        self.name = idc.get_struc_name(self.struct_id)
        self.struct_ptr = ida_struct.get_struc(self.struct_id)
        if self.struct_ptr is None:
            log.exception("self.struct_ptr is None at %s", self.name)
        previous_parent_offset = 0
        previous_parent_size = 0
        previous_parent_struct_id = BADADDR
        for parent_name, parent_offset in self.updated_parents:
            if (
                parent_offset - previous_parent_offset > previous_parent_size
                and previous_parent_struct_id != BADADDR
            ):
                utils.expand_struct(
                    previous_parent_struct_id,
                    parent_offset - previous_parent_offset,
                )
            baseclass_id = ida_struct.get_struc_id(parent_name)
            baseclass_size = ida_struct.get_struc_size(baseclass_id)
            if baseclass_id == BADADDR or baseclass_size == 0:
                log.warning(
                    "bad struct id or size: %s(0x%X:%s) - 0x%X, %d",
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
        for xref in utils.drefs_to(self.typeinfo_ea):
            if self.try_parse_vtable(xref) is not None:
                is_vtable_found = True
        if not is_vtable_found:
            log.debug(
                "find_vtable(%s): Couldn't find any vtable ->" " Interface!",
                self.name,
            )
            if not self.updated_parents:
                cpp_utils.install_vtables_union(self.name)

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
    def parse_typeinfo(cls, typeinfo_ea):
        pass

    def get_typeinfo_name(self, typeinfo_ea):
        pass


def get_OFFSET_FROM_TYPEINF_SYM():
    return 2 * utils.get_word_len()

def get_RECORD_TYPEINFO_OFFSET():
    return utils.get_word_len()

# class_type_info consts
def get_CLASS_TYPE_TYPEINFO_OFFSET():
    return 0

def get_CLASS_TYPE_NAME_OFFSET():
    return utils.get_word_len()

def get_CLASS_TYPE_SIZE():
    return 2 * utils.get_word_len()

# si_class_type_info consts
def get_SI_TYPEINFO_BASE_OFFSET():
    return get_CLASS_TYPE_SIZE()

# vmi_class_type_info consts
def get_VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET():
    return get_CLASS_TYPE_SIZE() + 4

def get_VMI_TYPEINFO_BASE_CLASSES_OFFSET():
    return get_VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET() + 4

# base_class vmi helper
def get_BASE_CLASS_TYPEINFO_OFFSET():
    return 0

def get_BASE_CLASS_ATTRS_OFFSET():
    return get_BASE_CLASS_TYPEINFO_OFFSET() + utils.get_word_len()

def get_BASE_CLASS_SIZE():
    return utils.get_word_len() * 2


class GccRTTIParser(RTTIParser):
    VMI = "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
    SI = "_ZTVN10__cxxabiv120__si_class_type_infoE"
    NONE = "_ZTVN10__cxxabiv117__class_type_infoE"

    pure_virtual_name = "__cxa_pure_virtual"

    @classmethod
    def init_parser(cls):
        super(GccRTTIParser, cls).init_parser()
        cls.type_vmi = ida_name.get_name_ea(idaapi.BADADDR, cls.VMI) + get_OFFSET_FROM_TYPEINF_SYM()
        cls.type_si = ida_name.get_name_ea(idaapi.BADADDR, cls.SI) + get_OFFSET_FROM_TYPEINF_SYM()
        cls.type_none = ida_name.get_name_ea(idaapi.BADADDR, cls.NONE) + get_OFFSET_FROM_TYPEINF_SYM()
        cls.types = (cls.type_vmi, cls.type_si, cls.type_none)

    @classmethod
    def build_all(cls):
        for class_type in cls.types:
            log.debug("Starting :%s %s", class_type, hex(class_type))
            cls.build_class_type(class_type)
            log.info("Done %s", class_type)

    @classmethod
    @utils.batchmode
    def build_class_type(cls, class_type):
        idx = 0
        for xref in idautils.XrefsTo(class_type - get_OFFSET_FROM_TYPEINF_SYM()):
            if (idx + 1) % 200 == 0:
                # idc.batch(0)
                log.info("\t Done %d", idx)
                # ida_loader.save_database(None, 0)
                # idc.batch(1)
            if utils.get_ptr(xref.frm) != class_type:
                continue
            try:
                cls.extract_rtti_info_from_typeinfo(xref.frm)
            except Exception as ex:  # pylint: disable=broad-except
                log.exception("Exception at %08X: %s", xref.frm, ex)
            idx += 1

    @classmethod
    def parse_rtti_header(cls, ea):
        # offset = cls.read_offset(ea)
        typeinfo_ea = cls.get_typeinfo_ea(ea)
        return typeinfo_ea

    @classmethod
    def parse_typeinfo(cls, typeinfo_ea):
        typeinfo_type = utils.get_ptr(typeinfo_ea + get_CLASS_TYPE_TYPEINFO_OFFSET())
        if typeinfo_type == cls.type_none:
            parents = []
        elif typeinfo_type == cls.type_si:
            parents = cls.parse_si_typeinfo(typeinfo_ea)
        elif typeinfo_type == cls.type_vmi:
            parents = cls.parse_vmi_typeinfo(typeinfo_ea)
        else:
            return None
        return GccRTTIParser(parents, typeinfo_ea)

    @classmethod
    def parse_si_typeinfo(cls, typeinfo_ea):
        parent_typinfo_ea = utils.get_ptr(typeinfo_ea + get_SI_TYPEINFO_BASE_OFFSET())
        return [(parent_typinfo_ea, 0)]

    @classmethod
    def parse_vmi_typeinfo(cls, typeinfo_ea):
        base_classes_num = idaapi.get_32bit(typeinfo_ea + get_VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET())
        parents = []
        for i in range(base_classes_num):
            base_class_desc_ea = (
                typeinfo_ea + get_VMI_TYPEINFO_BASE_CLASSES_OFFSET() + i * get_BASE_CLASS_SIZE()
            )
            parent_typeinfo_ea = utils.get_ptr(base_class_desc_ea + get_BASE_CLASS_TYPEINFO_OFFSET())
            parent_attrs = utils.get_word(base_class_desc_ea + get_BASE_CLASS_ATTRS_OFFSET())
            parent_offset_in_cls = parent_attrs >> 8
            parents.append((parent_typeinfo_ea, parent_offset_in_cls))
        return parents

    @classmethod
    def get_typeinfo_ea(cls, ea):
        return utils.get_ptr(ea + get_RECORD_TYPEINFO_OFFSET())

    def get_typeinfo_name(self, typeinfo_ea):
        name_ea = utils.get_ptr(typeinfo_ea + get_CLASS_TYPE_NAME_OFFSET())
        if name_ea is None or name_ea == BADADDR:
            mangled_class_name = ida_name.get_ea_name(typeinfo_ea)
        else:
            mangled_class_name = "_Z" + idc.get_strlit_contents(name_ea).decode()
        class_name = ida_name.demangle_name(mangled_class_name, idc.INF_LONG_DN)
        return GccRTTIParser.strip_class_name(class_name)

    @staticmethod
    def strip_class_name(class_name):
        # pre_dict = {"`typeinfo for": ":"}
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
            class_name = class_name.replace(target, strip)
        for target, strip in chars_dict.items():
            class_name = class_name.replace(target, strip)
        return class_name

    def try_parse_vtable(self, ea):
        functions_ea = ea + utils.get_word_len()
        func_ea, _ = cpp_utils.get_vtable_line(
            functions_ea,
            ignore_list=self.types,
            pure_virtual_name=self.pure_virtual_name,
        )
        if func_ea is None:
            return None
        vtable_offset = utils.get_signed_int(ea - utils.get_word_len()) * (-1)
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
