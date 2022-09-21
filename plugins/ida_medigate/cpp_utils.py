import logging
from functools import partial

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
VTABLE_DELIMITER = "__"
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


def get_vtable_line(ea, stop_ea=None, ignore_list=None, pure_virtual_name=None):
    if ignore_list is None:
        ignore_list = []
    func_ea = utils.get_ptr(ea)
    if (
        utils.is_func(func_ea)
        and (stop_ea is None or ea < stop_ea)
        and (
            func_ea not in ignore_list
            or (
                pure_virtual_name is not None
                and idc.GetDisasm(ea).endswith(pure_virtual_name)
            )
        )
    ):
        return func_ea, ea + utils.WORD_LEN
    return None, 0


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
    class_name, class_vtable_member=None, vtable_member_tinfo=None, offset=0
):
    logging.debug(
        "install_vtables_union(%s, %s, %s)",
        class_name,
        class_vtable_member,
        str(vtable_member_tinfo),
    )
    if class_vtable_member and vtable_member_tinfo:
        old_vtable_sptr = utils.extract_struct_from_tinfo(vtable_member_tinfo)
        old_vtable_class_name = ida_struct.get_struc_name(old_vtable_sptr.id)
    else:
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
    vtables_union_id = utils.get_or_create_struct_id(vtables_union_name, True)
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
    utils.add_to_struct(
        vtables_union, vtables_union_vtable_field_name, vtable_member_tinfo
    )
    parent_struct = utils.get_sptr_by_name(class_name)
    flag = idaapi.FF_STRUCT
    mt = idaapi.opinfo_t()
    mt.tid = vtables_union_id
    struct_size = ida_struct.get_struc_size(vtables_union_id)
    vtables_union_ptr_type = utils.get_typeinf_ptr(vtables_union_name)
    if class_vtable_member:
        member_ptr = class_vtable_member
    else:
        member_id = ida_struct.add_struc_member(
            parent_struct,
            get_class_vtable_field_name(class_name),
            offset,
            flag,
            mt,
            struct_size,
        )
        member_ptr = ida_struct.get_member_by_id(member_id)
    ida_struct.set_member_tinfo(
        parent_struct, member_ptr, 0, vtables_union_ptr_type, idaapi.TINFO_DEFINITE
    )
    return vtables_union


def add_child_vtable(parent_name, child_name, child_vtable_id, offset):
    logging.debug(
        "add_child_vtable (%s, %s, %s)",
        parent_name,
        child_name,
        child_vtable_id,
    )
    parent_vtable_member = ida_struct.get_member(
        utils.get_sptr_by_name(parent_name), offset
    )
    vtable_member_tinfo = utils.get_member_tinfo(parent_vtable_member)
    parent_vtable_struct = utils.get_sptr_by_name(
        get_class_vtable_struct_name(parent_name, offset)
    )
    if parent_vtable_struct is None:
        return None
    pointed_struct = utils.extract_struct_from_tinfo(vtable_member_tinfo)
    logging.debug("pointed_struct: %s", str(pointed_struct))
    if (
        (pointed_struct is None)
        or (not is_struct_vtable(pointed_struct))
        or (parent_vtable_struct.id != pointed_struct.id)
    ):
        parent_vtable_member = None
        logging.debug("Not a struct vtable: %s", str(vtable_member_tinfo))

    # TODO: Check that struct is a valid vtable by name
    if not parent_vtable_struct.is_union():
        logging.debug("%s vtable isn't union -> unionize it!", parent_name)
        parent_vtable_struct = install_vtables_union(
            parent_name, parent_vtable_member, vtable_member_tinfo, offset
        )

    child_vtable_name = ida_struct.get_struc_name(child_vtable_id)
    child_vtable = utils.get_typeinf(child_vtable_name)
    logging.debug(
        "add_to_struct %s %s", parent_vtable_struct.id, str(child_vtable)
    )
    if ida_struct.get_struc_size(child_vtable_id) == 0:
        utils.add_to_struct(
            ida_struct.get_struc(child_vtable_id), "dummy", None
        )
    new_member = utils.add_to_struct(
        parent_vtable_struct, get_class_vtables_field_name(child_name), child_vtable
    )
    ida_xref.add_dref(
        new_member.id, child_vtable_id, ida_xref.XREF_USER | ida_xref.dr_O
    )


def update_func_name_with_class(func_ea, class_name):
    name = ida_name.get_ea_name(func_ea)
    if name.startswith("sub_"):
        new_name = class_name + VTABLE_DELIMITER + name
        return utils.set_func_name(func_ea, new_name), True
    return name, False


def update_func_this(func_ea, this_type=None):
    functype = None
    try:
        func_details = utils.get_func_details(func_ea)
        if func_details is None:
            return None
        if this_type:
            if len(func_details) > 0:
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
    new_member = utils.add_to_struct(
        struct_ptr, vtable_field_name, vtable_type_ptr, offset, overwrite=True
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


def make_funcptr_pt(func, this_type):
    return utils.get_typeinf(f"void (*)({str(this_type)} *)")


def update_vtable_struct(
    functions_ea,
    vtable_struct,
    class_name,
    this_type=None,
    get_next_func_callback=get_vtable_line,
    vtable_head=None,
    ignore_list=None,
    add_dummy_member=False,
    pure_virtual_name=None,
    parent_name=None,
    add_func_this=True,
):
    is_first_member = True
    if this_type is None:
        this_type = utils.get_typeinf_ptr(class_name)
    if not add_func_this:
        this_type = None
    func, next_func = get_next_func_callback(
        functions_ea, ignore_list=ignore_list, pure_virtual_name=pure_virtual_name
    )
    dummy_i = 1
    while func is not None:
        new_func_name, is_name_changed = update_func_name_with_class(func, class_name)
        func_ptr = None
        if ida_hexrays.init_hexrays_plugin():
            if is_name_changed:
                func_type = update_func_this(func, this_type)
            else:
                func_type = update_func_this(func, None)
            if func_type is not None:
                func_ptr = utils.get_typeinf_ptr(func_type)
        else:
            func_ptr = make_funcptr_pt(func, this_type)
        if add_dummy_member:
            utils.add_to_struct(vtable_struct, f"dummy_{dummy_i}", func_ptr)
            dummy_i += 1
        if is_first_member:
            # We did an hack for vtables contained in union vtable with one dummy member
            ptr_member = utils.add_to_struct(
                vtable_struct, new_func_name, func_ptr, 0, overwrite=True
            )
            is_first_member = False
        else:
            ptr_member = utils.add_to_struct(
                vtable_struct, new_func_name, func_ptr, is_offset=True
            )
        if ptr_member is None:
            logging.exception(
                "Couldn't add %s(%s) to %d",
                new_func_name,
                str(func_ptr),
                vtable_struct.id,
            )
        ida_xref.add_dref(ptr_member.id, func, ida_xref.XREF_USER | ida_xref.dr_I)
        func, next_func = get_next_func_callback(
            next_func, ignore_list=ignore_list, pure_virtual_name=pure_virtual_name
        )

    vtable_size = ida_struct.get_struc_size(vtable_struct)

    if vtable_head is None:
        vtable_head = functions_ea
    ida_bytes.del_items(vtable_head, ida_bytes.DELIT_SIMPLE, vtable_size)
    ida_bytes.create_struct(vtable_head, vtable_size, vtable_struct.id)
    if parent_name is None and this_type:
        parent = utils.deref_struct_from_tinfo(this_type)
        parent_name = ida_struct.get_struc_name(parent.id)
        if parent_name == class_name:
            parent_name = None
    utils.set_name_retry(vtable_head, get_vtable_instance_name(class_name, parent_name))


def is_valid_func_char(c):
    ALLOWED_CHARS = [":", "_"]
    return c.isalnum() or c in ALLOWED_CHARS


def find_valid_cppname_in_line(line, idx):
    end_idx = idx
    start_idx = idx
    if len(line) < idx:
        return None
    while start_idx >= 0 and is_valid_func_char(line[start_idx]):
        if line[start_idx] == ":":
            if line[start_idx - 1] == ":":
                start_idx -= 1
            else:
                break
        start_idx -= 1
    while end_idx < len(line) and is_valid_func_char(line[end_idx]):
        if line[end_idx] == ":":
            if line[end_idx + 1] == ":":
                end_idx += 1
            else:
                break
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
        func_name_splitted = func_name.split(VTABLE_DELIMITER)
        local_func_name = func_name_splitted[-1]
        if local_func_name != name and (force or local_func_name.startswith("sub_")):
            ea = utils.get_func_ea_by_name(func_name)
            if ea != BADADDR:
                new_func_name = VTABLE_DELIMITER.join(func_name_splitted[:-1])
                if new_func_name != "":
                    new_func_name += VTABLE_DELIMITER
                new_func_name += name
                logging.debug("0x%x -> %s", ea, new_func_name)
                utils.set_func_name(ea, new_func_name)


def create_class(class_name, has_vtable, parent_class=None):
    class_id = ida_struct.add_struc(BADADDR, class_name)
    class_ptr = ida_struct.get_struc(class_id)
    # if parent class ->
    # if has_vtable-> if not parent- create vtable, if parent - install vtable
    return class_ptr


def create_vtable_struct(sptr, name, vtable_offset, parent_name=None):
    logging.debug("create_vtable_struct(%s, %d)", name, vtable_offset)
    vtable_details = find_vtable_at_offset(sptr, vtable_offset)
    parent_vtable_member = None
    parent_vtable_struct = None
    parent_name = None
    parents_chain = None
    if vtable_details is not None:
        logging.debug("Found parent vtable %s %d", name, vtable_offset)
        parent_vtable_member, parent_vtable_struct, parents_chain = vtable_details
    else:
        logging.debug("Couldn't found parent vtable %s %d", name, vtable_offset)
    if parent_vtable_member is not None:
        parent_name = ida_struct.get_struc_name(parent_vtable_struct.id)
    vtable_name = get_class_vtable_struct_name(name, vtable_offset)
    if vtable_offset == 0:
        this_type = utils.get_typeinf_ptr(name)
    else:
        this_type = utils.get_typeinf_ptr(parent_name)
    if vtable_name is None:
        logging.exception(
            "create_vtable_struct(%s, %d): vtable_name is" " None", name, vtable_offset
        )
    vtable_id = ida_struct.add_struc(BADADDR, vtable_name, False)
    if vtable_id == BADADDR:
        logging.exception("Couldn't create struct %s", vtable_name)
    vtable_struct = ida_struct.get_struc(vtable_id)
    if parents_chain:
        for parent_name, offset in parents_chain:
            add_child_vtable(parent_name, name, vtable_id, offset)
    else:
        add_class_vtable(sptr, vtable_name, vtable_offset)

    return vtable_struct, this_type


def make_vtable(
        class_name,
        vtable_ea=None,
        vtable_ea_stop=None,
        offset_in_class=0,
        parent_name=None,
        add_func_this=True,
        _get_vtable_line=get_vtable_line,
):
    if not vtable_ea and not vtable_ea_stop:
        vtable_ea, vtable_ea_stop = utils.get_selected_range_or_line()
    vtable_struct, this_type = create_vtable_struct(
        utils.get_or_create_struct(class_name), class_name, offset_in_class,
        parent_name=parent_name
    )
    update_vtable_struct(
        vtable_ea,
        vtable_struct,
        class_name,
        this_type=this_type,
        get_next_func_callback=partial(_get_vtable_line, stop_ea=vtable_ea_stop),
        parent_name=parent_name,
        add_func_this=add_func_this,
    )


def add_baseclass(class_name, baseclass_name, baseclass_offset=0, to_refresh=False):
    member_name = get_base_member_name(baseclass_name, baseclass_offset)
    struct_ptr = utils.get_sptr_by_name(class_name)
    baseclass_ptr = utils.get_sptr_by_name(baseclass_name)
    if not struct_ptr or not baseclass_ptr:
        return False
    member = utils.add_to_struct(struct_ptr, member_name,
                                 member_type=utils.get_typeinf(baseclass_name),
                                 offset=baseclass_offset,
                                 overwrite=True)
    if not member:
        logging.debug(f"add_baseclass({class_name}. {baseclass_name}): member not found")
        return False
    member.props |= ida_struct.MF_BASECLASS
    if to_refresh:
        utils.refresh_struct(struct_ptr)
    return True
