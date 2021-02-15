import logging
import random

import ida_bytes
import ida_enum
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_search
import ida_struct
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc

from idc import BADADDR

# WORD length in bytes
WORD_LEN = None


def update_word_len(code, old=0):
    global WORD_LEN
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        logging.debug("is 32 bit")
        WORD_LEN = 8
    elif info.is_32bit():
        logging.debug("is 32 bit")
        WORD_LEN = 4


idaapi.notify_when(idaapi.NW_OPENIDB, update_word_len)


def get_word(ea):
    if WORD_LEN == 4:
        return idaapi.get_32bit(ea)
    elif WORD_LEN == 8:
        return idaapi.get_64bit(ea)
    return None


def get_ptr(ea):
    return get_word(ea)


def make_word(ea):
    if WORD_LEN == 4:
        return ida_bytes.create_dword(ea, 4)
    elif WORD_LEN == 8:
        return ida_bytes.create_qword(ea, 8)
    return None


def make_ptr(ea):
    return make_word(ea)


def is_func(ea):
    func = ida_funcs.get_func(ea)
    if func is not None and func.start_ea == ea:
        return True
    return None


def get_funcs_list():
    pass


def get_drefs(ea):
    xref = ida_xref.get_first_dref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_dref_to(ea, xref)


def get_typeinf(typestr):
    tif = idaapi.tinfo_t()
    tif.get_named_type(idaapi.get_idati(), typestr)
    return tif


def get_typeinf_ptr(typeinf):
    old_typeinf = typeinf
    if isinstance(typeinf, str):
        typeinf = get_typeinf(typeinf)
    if typeinf is None:
        logging.warning("Couldn't find typeinf %s", old_typeinf or typeinf)
        return None
    tif = idaapi.tinfo_t()
    tif.create_ptr(typeinf)
    return tif


def get_func_details(func_ea):
    xfunc = ida_hexrays.decompile(func_ea)
    if xfunc is None:
        return None
    func_details = idaapi.func_type_data_t()
    xfunc.type.get_func_details(func_details)
    return func_details


def update_func_details(func_ea, func_details):
    function_tinfo = idaapi.tinfo_t()
    function_tinfo.create_func(func_details)
    if not ida_typeinf.apply_tinfo(func_ea, function_tinfo, idaapi.TINFO_DEFINITE):
        return None
    return function_tinfo


def add_to_struct(
    struct,
    member_name,
    member_type=None,
    offset=BADADDR,
    is_offset=False,
    overwrite=False,
):
    mt = None
    flag = idaapi.FF_DWORD
    member_size = WORD_LEN
    if member_type is not None and (member_type.is_struct() or member_type.is_union()):
        logging.debug("Is struct!")
        substruct = extract_struct_from_tinfo(member_type)
        if substruct is not None:
            flag = idaapi.FF_STRUCT
            mt = ida_nalt.opinfo_t()
            mt.tid = substruct.id
            logging.debug(
                f"Is struct: {ida_struct.get_struc_name(substruct.id)}/{substruct.id}"
            )
            member_size = ida_struct.get_struc_size(substruct.id)
    elif WORD_LEN == 4:
        flag = idaapi.FF_DWORD
    elif WORD_LEN == 8:
        flag = idaapi.FF_QWORD
    if is_offset:
        flag |= idaapi.FF_0OFF
        mt = ida_nalt.opinfo_t()
        r = ida_nalt.refinfo_t()
        r.init(ida_nalt.get_reftype_by_size(WORD_LEN) | ida_nalt.REFINFO_NOBASE)
        mt.ri = r

    new_member_name = member_name
    member_ptr = ida_struct.get_member(struct, offset)
    if overwrite and member_ptr:
        if ida_struct.get_member_name(member_ptr.id) != member_name:
            logging.debug("Overwriting!")
            ret_val = ida_struct.set_member_name(struct, offset, member_name)
            i = 0
            while ret_val == ida_struct.STRUC_ERROR_MEMBER_NAME:
                new_member_name = "%s_%d" % (member_name, i)
                i += 1
                if i > 250:
                    logging.debug("failed change name")
                    return
                ret_val = ida_struct.set_member_name(struct, offset, new_member_name)

    else:
        ret_val = ida_struct.add_struc_member(
            struct, new_member_name, offset, flag, mt, member_size
        )
        i = 0
        while ret_val == ida_struct.STRUC_ERROR_MEMBER_NAME:
            new_member_name = "%s_%d" % (member_name, i)
            i += 1
            if i > 250:
                return
            ret_val = ida_struct.add_struc_member(
                struct, new_member_name, offset, flag, mt, member_size
            )
        if ret_val != 0:
            logging.debug(f"ret_val: {ret_val}")
        member_ptr = ida_struct.get_member_by_name(struct, new_member_name)
    if member_type is not None and member_ptr is not None:
        ida_struct.set_member_tinfo(
            struct, member_ptr, 0, member_type, idaapi.TINFO_DEFINITE
        )
    return member_ptr


def set_func_name(func_ea, func_name):
    counter = 0
    new_name = func_name
    while not ida_name.set_name(func_ea, new_name):
        new_name = func_name + "_%d" % counter
        counter += 1
    return new_name


def deref_tinfo(tinfo):
    pointed_obj = None
    if tinfo.is_ptr():
        pointed_obj = tinfo.get_pointed_object()
    return pointed_obj


def get_struc_from_tinfo(struct_tinfo):

    if ida_hexrays.init_hexrays_plugin() and (
        not (struct_tinfo.is_struct() or struct_tinfo.is_union())
    ):
        return None
    struct_id = ida_struct.get_struc_id(struct_tinfo.get_type_name())
    if struct_id == BADADDR:
        return None
    struct = ida_struct.get_struc(struct_id)
    return struct


def deref_struct_from_tinfo(tinfo):
    struct_tinfo = deref_tinfo(tinfo)
    if struct_tinfo is None:
        return None
    return get_struc_from_tinfo(struct_tinfo)


def extract_struct_from_tinfo(tinfo):
    struct = get_struc_from_tinfo(tinfo)
    if struct is None:
        struct = deref_struct_from_tinfo(tinfo)
    return struct


def get_member_tinfo(member, member_typeinf=None):
    if member_typeinf is None:
        member_typeinf = idaapi.tinfo_t()
    ida_struct.get_member_tinfo(member_typeinf, member)
    return member_typeinf


def get_sptr_by_name(struct_name):
    s_id = ida_struct.get_struc_id(struct_name)
    return ida_struct.get_struc(s_id)


def get_member_substruct(member):
    member_type = get_member_tinfo(member)
    if member_type is not None and member_type.is_struct():
        current_struct_id = ida_struct.get_struc_id(member_type.get_type_name())
        return ida_struct.get_struc(current_struct_id)
    elif member.flag & idaapi.FF_STRUCT == idaapi.FF_STRUCT:
        return ida_struct.get_sptr(member)
    return None


def set_member_name(struct, offset, new_name):
    i = 0
    ret_val = ida_struct.set_member_name(struct, offset, new_name)
    while not ret_val:
        formatted_new_name = "%s_%d" % (new_name, i)
        i += 1
        if i > 250:
            return False
        ret_val = ida_struct.set_member_name(struct, offset, formatted_new_name)
    return True


def get_or_create_struct_id(struct_name, is_union=False):
    struct_id = ida_struct.get_struc_id(struct_name)
    if struct_id != BADADDR:
        return struct_id
    struct_id = ida_struct.add_struc(BADADDR, struct_name, is_union)
    return struct_id


def get_or_create_struct(struct_name):
    struct_id = get_or_create_struct_id(struct_name)
    return ida_struct.get_struc(struct_id)


def get_signed_int(ea):
    x = idaapi.get_dword(ea)
    if x & (1 << 31):
        return ((1 << 32) - x) * (-1)
    return x


def expand_struct(struct_id, new_size):
    struct = ida_struct.get_struc(struct_id)
    if struct is None:
        logging.warning("Struct id 0x%x wasn't found", struct_id)
        return
    logging.debug(
        "Expanding struc %s 0x%x -> 0x%x",
        ida_struct.get_struc_name(struct_id),
        ida_struct.get_struc_size(struct_id),
        new_size,
    )
    if ida_struct.get_struc_size(struct_id) > new_size - WORD_LEN:
        return
    fix_list = []
    xrefs = idautils.XrefsTo(struct.id)
    for xref in xrefs:
        if xref.type == ida_xref.dr_R and xref.user == 0 and xref.iscode == 0:
            member, full_name, x_struct = ida_struct.get_member_by_id(xref.frm)
            if x_struct is not None:
                old_name = ida_struct.get_member_name(member.id)
                offset = member.soff
                marker_name = "marker_%d" % random.randint(0, 0xFFFFFF)
                idc.add_struc_member(
                    x_struct.id,
                    marker_name,
                    member.soff + new_size,
                    idaapi.FF_DATA | idaapi.FF_BYTE,
                    -1,
                    0,
                )
                logging.debug(
                    "Delete member (0x%x-0x%x)", member.soff, member.soff + new_size - 1
                )
                ida_struct.del_struc_members(
                    x_struct, member.soff, member.soff + new_size - 1
                )
                fix_list.append(
                    [
                        x_struct.id,
                        old_name,
                        offset,
                        idaapi.FF_STRUCT | idaapi.FF_DATA,
                        struct_id,
                        new_size,
                    ]
                )
            else:
                logging.warning("Xref wasn't struct_member 0x%x", xref.frm)

    ret = add_to_struct(
        ida_struct.get_struc(struct_id), None, None, new_size - WORD_LEN
    )
    logging.debug("Now fix args:")
    for fix_args in fix_list:
        ret = idc.add_struc_member(*fix_args)
        logging.debug("%s = %d", fix_args, ret)
        x_struct_id = fix_args[0]
        idc.del_struc_member(x_struct_id, ida_struct.get_struc_size(x_struct_id))


def get_curline_striped_from_viewer(viewer):
    line = ida_kernwin.get_custom_viewer_curline(viewer, False)
    line = ida_lines.tag_remove(line)
    return line


strings = None


def refresh_strings():
    global strings
    strings = idautils.Strings()


def get_strings():
    if strings is None:
        refresh_strings()
    return strings


def get_xrefs_for_string(s, filter_func=None):
    """filter_func(x,s) choose x if True for magic str (s)"""
    if filter_func is None:

        def filter_func(x, string):
            return str(x) == string

    filtered_strings = filter(lambda x: filter_func(x, s), get_strings())
    strings_xrefs = []
    for s in filtered_strings:
        xrefs = []
        xref = ida_xref.get_first_dref_to(s.ea)
        while xref != BADADDR:
            xrefs.append(xref)
            xref = ida_xref.get_next_dref_to(s.ea, xref)
        strings_xrefs.append([str(s), xrefs])
    return strings_xrefs


def get_func_ea_by_name(name):
    loc = idc.get_name_ea_simple(name)
    func = ida_funcs.get_func(loc)
    if func is None:
        return BADADDR
    return func.start_ea


def get_funcs_contains_string(s):
    def filter_func(x, string):
        return string in str(x)

    strings_xrefs = get_xrefs_for_string(s, filter_func)
    strings_funcs = []
    for found_str, xrefs in strings_xrefs:
        funcs = set()
        for xref in xrefs:
            contained_func = ida_funcs.get_func(xref)
            if contained_func is not None:
                funcs.add(contained_func)
        strings_funcs.append([found_str, funcs])
    return strings_funcs


def batchmode(func):
    def wrapper(*args, **kwargs):
        old_batch = idc.batch(1)
        try:
            val = func(*args, **kwargs)
        except Exception:
            raise
        finally:
            idc.batch(old_batch)
        return val

    return wrapper


def get_code_xrefs(ea):
    xref = ida_xref.get_first_cref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_cref_to(ea, xref)


def get_enum_const_name(enum_name, const_val):
    enum = ida_enum.get_enum(enum_name)
    if enum != BADADDR:
        const = ida_enum.get_const(enum, const_val, 0, BADADDR)
        if const != BADADDR:
            return ida_enum.get_const_name(const)
    return None


def find_hex_string(start_ea, stop_ea, hex_string):
    curr_ea = ida_search.find_binary(
        start_ea, stop_ea, hex_string, 16, ida_search.SEARCH_DOWN
    )
    while curr_ea != BADADDR:
        yield curr_ea
        curr_ea = ida_search.find_binary(
            curr_ea + len(hex_string), stop_ea, hex_string, 16, ida_search.SEARCH_DOWN
        )


def force_make_struct(ea, struct_name):
    sptr = get_sptr_by_name(struct_name)
    if sptr == BADADDR:
        return False
    s_size = ida_struct.get_struc_size(sptr)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, s_size)
    return ida_bytes.create_struct(ea, s_size, sptr.id)


@batchmode
def set_name_retry(ea, name, name_func=ida_name.set_name, max_attempts=100):
    i = 0
    suggested_name = name
    while not name_func(ea, suggested_name):
        suggested_name = name + "_" + str(i)
        i += 1
        if i == max_attempts:
            return None
    return suggested_name


def add_struc_retry(name, max_attempts=100):
    i = 0
    suggested_name = name
    sid = ida_struct.add_struc(BADADDR, suggested_name)
    while sid == BADADDR:
        suggested_name = name + "_" + str(i)
        sid = ida_struct.add_struc(BADADDR, suggested_name)
        i += 1
        if i == max_attempts:
            return None, sid
    return suggested_name, sid


def get_selected_range_or_line():
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
    if selection:
        return startaddr, endaddr
    else:
        return ida_kernwin.get_screen_ea(), None


def refresh_struct(sptr):
    #  Hack: need to refresh structure so MF_BASECLASS will be updated
    member_ptr = add_to_struct(sptr, "dummy")
    ida_struct.del_struc_member(sptr, member_ptr.soff)

