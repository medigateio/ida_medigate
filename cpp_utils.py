import logging

import ida_bytes
import ida_hexrays
import ida_name
import ida_struct
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc
from idaapi import BADADDR
from . import utils
from .utils import batchmode

VTABLE_KEYWORD = "vtbl"
VTABLE_UNION_KEYWORD = "VTABLES"
# VTABLES_UNION_VTABLE_FIELD_POSTFIX = "_vtable"
VTABLES_UNION_VTABLE_FIELD_POSTFIX = ""
VTABLE_DELIMITER = "::"
VTABLE_POSTFIX = "_vtbl"
VTABLE_FIELD_NAME = "__vftable"  # Name For vtable * field
VTABLE_INSTANCE_DELIMITER = VTABLE_DELIMITER
VTABLE_INSTANCE_KEYWORD = "vtable"
VTABLE_INSTANCE_POSTFIX = VTABLE_INSTANCE_DELIMITER + VTABLE_INSTANCE_KEYWORD


def get_vtable_instance_name(class_name, parent_name=None):
    name = class_name + VTABLE_INSTANCE_POSTFIX
    if parent_name is not None:
        name += VTABLE_INSTANCE_DELIMITER + parent_name
    return name


def get_base_member_name(parent_name, offset):
    return "baseclass_%x" % offset


def get_vtable_line(ea, ignore_list=None, pure_virtual_name=None):
    if ignore_list is None:
        ignore_list = []
    func_ea = utils.get_ptr(ea)
    if utils.is_func(func_ea) and (
        func_ea not in ignore_list
        or (
            pure_virtual_name is not None
            and idc.GetDisasm(ea).endswith(pure_virtual_name)
        )
    ):
        return func_ea
    return None


def is_valid_vtable_name(member_name):
    return VTABLE_FIELD_NAME in member_name


def is_valid_vtable_type(member, member_type):
    if member_type.is_ptr():
        struct = utils.deref_struct_from_tinfo(member_type)
        return is_struct_vtable(struct)
    return False


def is_member_vtable(member):
    member_type = utils.get_member_tinfo(member)
    member_name = ida_struct.get_member_name(member.id)
    if not is_valid_vtable_name(member_name):
        return False
    if not is_valid_vtable_type(member, member_type):
        return False
    return True


def is_struct_vtable(struct):
    if struct is None:
        return False
    struct_name = ida_struct.get_struc_name(struct.id)
    return VTABLE_POSTFIX in struct_name


def is_vtables_union(union):
    if union is None:
        return False
    if not union.is_union():
        return False
    union_name = ida_struct.get_struc_name(union.id)
    return is_vtables_union_name(union_name)


def is_vtables_union_name(union_name):
    return union_name.endswith(VTABLE_UNION_KEYWORD)


def find_vtable_at_offset(struct_ptr, vtable_offset):
    current_struct = struct_ptr
    current_offset = 0
    member = ida_struct.get_member(current_struct, vtable_offset)
    if member is None:
        return None
    parents_vtables_classes = []
    current_offset += member.get_soff()
    while current_offset < vtable_offset and member is not None:
        current_struct = utils.get_member_substruct(member)
        if current_struct is None:
            return
        parents_vtables_classes.append(
            [
                ida_struct.get_struc_name(current_struct.id),
                vtable_offset - current_offset,
            ]
        )
        member = ida_struct.get_member(current_struct, vtable_offset - current_offset)
        if member is None:
            logging.exception(
                "Couldn't find vtable at offset %d for %d",
                vtable_offset - current_offset,
                struct_ptr.id,
            )
        current_offset += member.get_soff()

    if current_offset != vtable_offset:
        return None

    while member is not None:
        if is_member_vtable(member):
            return member, current_struct, parents_vtables_classes
        current_struct = utils.get_member_substruct(member)
        if current_struct is None:
            return None
        parents_vtables_classes.append(
            [ida_struct.get_struc_name(current_struct.id), 0]
        )
        member = ida_struct.get_member(current_struct, 0)

    return None


def get_class_vtable_struct_name(class_name, vtable_offset_in_class):
    if vtable_offset_in_class == 0:
        return class_name + "_vtbl"
    return "%s_%04X_vtbl" % (class_name, vtable_offset_in_class)


def get_class_vtable_field_name(class_name):
    return VTABLE_FIELD_NAME


def get_class_vtables_union_name(class_name):
    return class_name + VTABLE_DELIMITER + VTABLE_UNION_KEYWORD


def get_class_vtables_field_name(child_name):
    return child_name + VTABLES_UNION_VTABLE_FIELD_POSTFIX


def get_interface_empty_vtable_name():
    return "INTERFACE"


def install_vtables_union(
    class_name, class_vtable_member=None, vtable_member_tinfo=None, offset=None
):
    logging.debug(
        "install_vtables_union(%s, %s, %s)",
        class_name,
        class_vtable_member,
        str(vtable_member_tinfo),
    )
    old_vtable_sptr = None
    if class_vtable_member and vtable_member_tinfo:
        old_vtable_sptr = utils.extract_struct_from_tinfo(vtable_member_tinfo)
        old_vtable_class_name = ida_struct.get_struc_name(old_vtable_sptr.id)
    elif offset is not None:
        old_vtable_class_name = get_class_vtable_struct_name(class_name, offset)
        old_vtable_sptr = utils.get_sptr_by_name(old_vtable_class_name)
    vtables_union_name = old_vtable_class_name
    if old_vtable_sptr and not ida_struct.set_struc_name(
        old_vtable_sptr.id, old_vtable_class_name + "_orig"
    ):
        logging.exception(
            f"Failed changing {old_vtable_class_name}->"
            f"{old_vtable_class_name+'orig'}"
        )
        return -1
    vtables_union_id = ida_struct.add_struc(BADADDR, vtables_union_name, True)
    vtable_member_tinfo = utils.get_typeinf(old_vtable_class_name + "_orig")
    if vtables_union_id == BADADDR:
        logging.exception(
            f"Cannot create union vtable for {class_name}(){vtables_union_name}"
        )
        return -1

    vtables_union = ida_struct.get_struc(vtables_union_id)
    if not vtables_union:
        logging.exception(f"Could retrieve vtables union for {class_name}")
    if vtable_member_tinfo is not None:
        vtables_union_vtable_field_name = get_class_vtables_field_name(class_name)
    else:
        vtables_union_vtable_field_name = get_interface_empty_vtable_name()
    utils.push_ptr_member_to_struct(
        vtables_union, vtables_union_vtable_field_name, vtable_member_tinfo
    )
    parent_struct = utils.get_sptr_by_name(class_name)
    vtables_union_ptr_type = utils.get_typeinf_ptr(vtables_union_name)
    if class_vtable_member is not None:
        ida_struct.set_member_tinfo(
            parent_struct,
            class_vtable_member,
            0,
            vtables_union_ptr_type,
            idaapi.TINFO_DEFINITE,
        )
    return vtables_union


def add_child_vtable(parent_name, child_name, child_vtable_id, offset):
    logging.debug(
        "add_child_vtable (%s, %s, %s)",
        parent_name,
        child_name,
        child_vtable_id,
    )
    parent_vtable_member = ida_struct.get_member(utils.get_sptr_by_name(parent_name), offset)
    vtable_member_tinfo = utils.get_member_tinfo(parent_vtable_member)
    parent_vtable_struct = utils.get_sptr_by_name(
        get_class_vtable_struct_name(parent_name, offset))
    if parent_vtable_struct is None:
        return None
    pointed_struct = utils.extract_struct_from_tinfo(vtable_member_tinfo)
    logging.debug("pointed_struct: %s", str(pointed_struct))
    if (pointed_struct is None) or (not is_struct_vtable(pointed_struct)) or (
            parent_vtable_struct.id != pointed_struct.id):
        parent_vtable_member = None
        logging.debug("Not a struct vtable: %s", str(vtable_member_tinfo))

    # TODO: Check that struct is a valid vtable by name
    if not parent_vtable_struct.is_union():
        logging.debug("%s vtable isn't union -> unionize it!", parent_name)
        parent_vtable_struct = install_vtables_union(parent_name, parent_vtable_member,
                                                     vtable_member_tinfo, offset)

    child_vtable_name = ida_struct.get_struc_name(child_vtable_id)
    child_vtable = utils.get_typeinf(child_vtable_name)
    logging.debug(
        "push_ptr_member_to_struct %s %s", parent_vtable_struct.id, str(child_vtable)
    )
    if ida_struct.get_struc_size(child_vtable_id) == 0:
        utils.push_ptr_member_to_struct(
            ida_struct.get_struc(child_vtable_id), "dummy", None
        )
    new_member = utils.push_ptr_member_to_struct(
        parent_vtable_struct, get_class_vtables_field_name(child_name), child_vtable
    )
    ida_xref.add_dref(
        new_member.id, child_vtable_id, ida_xref.XREF_USER | ida_xref.dr_O
    )


def update_func_name_with_class(func_ea, class_name):
    name = ida_name.get_ea_name(func_ea)
    if name.startswith("sub_"):
        new_name = class_name + "::" + name
        return utils.set_func_name(func_ea, new_name), True
    return name, False


def update_func_this(func_ea, this_type):
    functype = None
    try:
        func_details = utils.get_func_details(func_ea)
        if func_details is None or len(func_details) == 0:
            return None
        func_details[0].name = "this"
        func_details[0].type = this_type
        functype = utils.update_func_details(func_ea, func_details)
    except ida_hexrays.DecompilationFailure as e:
        logging.exception("Couldn't decompile 0x%x", func_ea)
    return functype


def add_class_vtable(struct_ptr, vtable_name, offset=BADADDR, vtable_field_name=None):
    if vtable_field_name is None:
        class_name = ida_struct.get_struc_name(struct_ptr.id)
        vtable_field_name = get_class_vtable_field_name(class_name)
    vtable_id = ida_struct.get_struc_id(vtable_name)
    vtable_type_ptr = utils.get_typeinf_ptr(vtable_name)
    new_member = utils.push_ptr_member_to_struct(
        struct_ptr, vtable_field_name, vtable_type_ptr, offset
    )
    if new_member is None:
        logging.warning(
            "vtable of %s couldn't added at offset %d", str(vtable_type_ptr), offset
        )
    else:
        ida_xref.add_dref(new_member.id, vtable_id, ida_xref.XREF_USER | ida_xref.dr_O)


@batchmode
def post_func_name_change(new_name, ea):
    xrefs = idautils.XrefsTo(ea, ida_xref.XREF_USER)
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    args_list = []
    for xref in xrefs:
        member, old_name, struct = ida_struct.get_member_by_id(xref.frm)
        if member is not None and struct is not None:
            args_list.append([struct, member.get_soff(), new_name])

    return utils.set_member_name, args_list


def post_struct_member_name_change(member, new_name):
    xrefs = idautils.XrefsFrom(member.id)
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    for xref in xrefs:
        if utils.is_func(xref.to):
            utils.set_func_name(xref.to, new_name)


def post_struct_member_type_change(member):
    xrefs = idautils.XrefsFrom(member.id)
    xrefs = filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs)
    for xref in xrefs:
        if utils.is_func(xref.to):
            function_ptr_tinfo = idaapi.tinfo_t()
            ida_struct.get_member_tinfo(function_ptr_tinfo, member)
            if function_ptr_tinfo.is_funcptr():
                function_tinfo = function_ptr_tinfo.get_pointed_object()
                if function_tinfo is not None:
                    ida_typeinf.apply_tinfo(
                        xref.to, function_tinfo, idaapi.TINFO_DEFINITE
                    )


@batchmode
def post_func_type_change(pfn):
    ea = pfn.start_ea
    xrefs = idautils.XrefsTo(ea, ida_xref.XREF_USER)
    xrefs = list(filter(lambda x: x.type == ida_xref.dr_I and x.user == 1, xrefs))
    args_list = []
    if len(xrefs) == 0:
        return None, []
    try:
        xfunc = ida_hexrays.decompile(ea)
        func_ptr_typeinf = utils.get_typeinf_ptr(xfunc.type)
        for xref in xrefs:
            member, old_name, struct = ida_struct.get_member_by_id(xref.frm)
            if member is not None and struct is not None:
                args_list.append(
                    [struct, member, 0, func_ptr_typeinf, idaapi.TINFO_DEFINITE]
                )
    except Exception:
        pass
    return ida_struct.set_member_tinfo, args_list


def update_vtable_struct(
    functions_ea,
    vtable_struct,
    class_name,
    this_type=None,
    ignore_list=None,
    pure_virtual_name=None,
):
    is_first_member = True
    if this_type is None:
        this_type = utils.get_typeinf_ptr(class_name)
    idx = 0
    func = get_vtable_line(functions_ea, ignore_list, pure_virtual_name)
    while func is not None:
        new_func_name, is_name_changed = update_func_name_with_class(func, class_name)
        func_type = None
        if is_name_changed:
            func_type = update_func_this(func, this_type)
        if func_type is not None:
            func_ptr = utils.get_typeinf_ptr(func_type)
        else:
            func_ptr = None
        if is_first_member:
            # We did an hack for vtables contained in union vtable with one dummy member
            ptr_member = utils.push_ptr_member_to_struct(
                vtable_struct, new_func_name, func_ptr, 0, overwrite=True
            )
            is_first_member = False
        else:
            ptr_member = utils.push_ptr_member_to_struct(
                vtable_struct, new_func_name, func_ptr
            )
        if ptr_member is None:
            logging.exception(
                "Couldn't add %s(%s) to %d",
                new_func_name,
                str(func_ptr),
                vtable_struct.id,
            )
        ida_xref.add_dref(ptr_member.id, func, ida_xref.XREF_USER | ida_xref.dr_I)
        idx += utils.WORD_LEN
        func = get_vtable_line(functions_ea + idx, ignore_list, pure_virtual_name)

    vtable_size = ida_struct.get_struc_size(vtable_struct)

    ida_bytes.del_items(functions_ea, ida_bytes.DELIT_SIMPLE, vtable_size)
    ida_bytes.create_struct(functions_ea, vtable_size, vtable_struct.id)

    parent = utils.deref_struct_from_tinfo(this_type)
    parent_name = ida_struct.get_struc_name(parent.id)
    if parent_name == class_name:
        parent_name = None
    ida_name.set_name(functions_ea, get_vtable_instance_name(class_name, parent_name))


def is_valid_func_char(c):
    ALLOWED_CHARS = [":", "_"]
    return c.isalnum() or c in ALLOWED_CHARS


def find_valid_cppname_in_line(line, idx):
    end_idx = idx
    start_idx = idx
    if len(line) < idx:
        return None
    while start_idx >= 0 and is_valid_func_char(line[start_idx]):
        start_idx -= 1
    while end_idx < len(line) and is_valid_func_char(line[end_idx]):
        end_idx += 1
    if end_idx > start_idx:
        return line[start_idx + 1 : end_idx]
    return None


def get_overriden_func_names(union_name, offset, get_not_funcs_members=False):
    sptr = utils.get_sptr_by_name(union_name)
    res = []
    if not sptr.is_union:
        return res

    for i in range(ida_struct.get_max_offset(sptr)):
        member = ida_struct.get_member(sptr, i)
        cls = ida_struct.get_member_name(member.id)
        tinfo = utils.get_member_tinfo(member)
        logging.debug("Trying %s", cls)
        if cls == get_interface_empty_vtable_name() or not tinfo.is_ptr():
            continue
        pointed_obj = tinfo.get_pointed_object()
        if not pointed_obj.is_struct():
            continue
        vtable_sptr = utils.get_sptr_by_name(pointed_obj.get_final_type_name())
        if ida_struct.get_max_offset(vtable_sptr) <= offset:
            continue
        funcptr_member = ida_struct.get_member(vtable_sptr, offset)
        funcptr_type = utils.get_member_tinfo(funcptr_member)
        func_name = ida_struct.get_member_name(funcptr_member.id)
        if not funcptr_type.is_funcptr() and not get_not_funcs_members:
            continue
        res.append((cls, func_name))
    return res


def set_polymorhpic_func_name(union_name, offset, name, force=False):
    for _, func_name in get_overriden_func_names(union_name, offset):
        func_name_splitted = func_name.split("::")
        local_func_name = func_name_splitted[-1]
        if local_func_name != name and (force or local_func_name.startswith("sub_")):
            ea = utils.get_func_ea_by_name(func_name)
            if ea != BADADDR:
                new_func_name = "::".join(func_name_splitted[:-1])
                if new_func_name != "":
                    new_func_name += "::"
                new_func_name += name
                logging.debug("0x%x -> %s", ea, new_func_name)
                utils.set_func_name(ea, new_func_name)


def create_class(class_name, has_vtable, parent_class=None):
    class_id = ida_struct.add_struc(BADADDR, class_name)
    class_ptr = ida_struct.get_struc(class_id)
    # if parent class ->
    # if has_vtable-> if not parent- create vtable, if parent - install vtable
    return class_ptr
