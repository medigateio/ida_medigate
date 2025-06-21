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
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc

from idc import BADADDR

# WORD length in bytes
WORD_LEN = None
NOT_UNION = 0

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
    struct: ida_typeinf.tinfo_t,
    member_name: str,
    member_type: ida_typeinf.tinfo_t=None,
    offset=BADADDR,
    is_offset=False,
    overwrite=False,
) -> tuple[int, ida_typeinf.udm_t] | None:
    mt = None
    flag = idaapi.FF_DWORD
    member_size = WORD_LEN
    if member_type is not None and (member_type.is_struct() or member_type.is_union()):
        logging.debug("Is struct!")
        substruct = extract_struct_from_tinfo(member_type)
        if substruct is not None:
            flag = idaapi.FF_STRUCT
            mt = ida_nalt.opinfo_t()
            substruct_tid = substruct.get_tid()
            mt.tid = substruct_tid
            logging.debug(
                f"Is struct: {ida_typeinf.get_tid_name(substruct_tid)}/{substruct_tid}"
            )
            member_size = substruct.get_size()
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
    member: ida_typeinf.udm_t = struct.get_udm_by_offset(offset)
    if overwrite and member:
        if member.name != member_name:
            logging.debug("Overwriting!")
            ret_val = struct.rename_udm(offset, member_name)
            while not ret_val:
                formatted_member_name = f"{member_name}_{i}"
                i += 1
                if i > 250:
                    return None
                ret_val = struct.rename_udm(offset, formatted_member_name)

    else:
        ret_val = struct.add_udm(type=mt, offset=offset, etf_flags=flag)
        member: ida_typeinf.udm_t = struct.get_udm_by_offset(offset)
        logging.debug("Overwriting!")
        ret_val = struct.rename_udm(offset, member_name)
        while not ret_val:
            formatted_member_name = f"{member_name}_{i}"
            i += 1
            if i > 250:
                return None
            ret_val = struct.rename_udm(offset, formatted_member_name)

    return struct.get_udm(name=new_member_name)
    


def set_func_name(func_ea, func_name):
    counter = 0
    new_name = func_name
    while not ida_name.set_name(func_ea, new_name):
        new_name = func_name + "_%d" % counter
        counter += 1
    return new_name


def deref_tinfo(tinfo: ida_typeinf.tinfo_t):
    pointed_obj = None
    if tinfo.is_ptr():
        pointed_obj = tinfo.get_pointed_object()
    return pointed_obj


def deref_struct_from_tinfo(tinfo: ida_typeinf.tinfo_t):
    struct_tinfo = deref_tinfo(tinfo)
    if struct_tinfo is None:
        return None
    return struct_tinfo


def extract_struct_from_tinfo(tinfo: ida_typeinf.tinfo_t):
    struct = tinfo
    if struct is None:
        struct = deref_struct_from_tinfo(tinfo)
    return struct


def get_member_tinfo(member: ida_typeinf.udm_t, member_typeinf: ida_typeinf.tinfo_t=None):
    if member_typeinf is None:
        member_typeinf = idaapi.tinfo_t()
    member_typeinf = member.type
    return member_typeinf


def get_sptr(udm: ida_typeinf.udm_t):
    tif = udm.type
    if tif.is_udt() and tif.is_struct():
        return tif
    else:
        return None


def get_sptr_by_name(struct_name: str):
    return ida_typeinf.tinfo_t(name=struct_name)


def get_member_substruct(member: ida_typeinf.udm_t):
    member_type = get_member_tinfo(member)
    if member_type is not None and member_type.is_struct():
        return member_type.get_type_name()
    elif member.flag & idaapi.FF_STRUCT == idaapi.FF_STRUCT:
        return get_sptr(member)
    return None


def set_member_name(struct: ida_typeinf.tinfo_t, offset: int, new_name: str):
    i = 0
    ret_val = struct.rename_udm(offset, new_name)
    while not ret_val:
        formatted_new_name = f"{new_name}_{i}"
        i += 1
        if i > 250:
            return False
        ret_val = struct.rename_udm(offset, formatted_new_name)
    return True


def get_or_create_struct_id(struct_name, is_union=False):
    try:
        return ida_typeinf.tinfo_t(name=struct_name).get_tid()
    except ValueError as e:
        udt = ida_typeinf.udt_type_data_t()
        type_info = ida_typeinf.tinfo_t()
        udt.is_union = is_union
        if (
            type_info.create_udt(udt) and
            type_info.set_named_type(None, struct_name) == ida_typeinf.TERR_OK
        ):
            return type_info.get_tid()


def get_or_create_struct(struct_name):
    struct_id = get_or_create_struct_id(struct_name)
    return ida_typeinf.tinfo_t(tid=struct_id)


def get_signed_int(ea):
    x = idaapi.get_dword(ea)
    if x & (1 << 31):
        return ((1 << 32) - x) * (-1)
    return x


def expand_struct(struct_id: int, new_size: int):
    try:
        struct = ida_typeinf.tinfo_t(tid=struct_id)
    except ValueError:
        logging.warning("Struct id 0x%x wasn't found", struct_id)
        return
    logging.debug(
        "Expanding struc %s 0x%x -> 0x%x",
        ida_typeinf.get_tid_name(struct_id),
        struct.get_size(),
        new_size,
    )
    if struct.get_size() > new_size - WORD_LEN:
        return
    fix_list = []
    xrefs = idautils.XrefsTo(struct.get_tid())
    for xref in xrefs:
        if xref.type == ida_xref.dr_R and xref.user == 0 and xref.iscode == 0:
            member = ida_typeinf.udm_t()
            struct.get_udm_by_tid(member, xref.frm)
            x_struct = ida_typeinf.tinfo_t(tid=xref.frm)
            if x_struct is not None:
                old_name: str = member.name
                offset: int = member.offset
                marker_name = "marker_{random.randint(0, 0xFFFFFF)}"
                x_struct.add_udm(
                    name=marker_name,
                    type=ida_typeinf.BTF_VOID,
                    offset=member.soff + new_size,
                    etf_flags=idaapi.FF_DATA | idaapi.FF_BYTE,
                )
                logging.debug(
                    "Delete member (0x%x-0x%x)", member.soff, member.soff + new_size - 1
                )
                x_struct.del_udms(member.soff, member.soff + new_size)
                fix_list.append(
                    [
                        x_struct.get_tid(),
                        old_name,
                        struct_id,
                        offset,
                        idaapi.FF_STRUCT | idaapi.FF_DATA,
                    ]
                )
            else:
                logging.warning("Xref wasn't struct_member 0x%x", xref.frm)

    ret = add_to_struct(
        struct, None, None, new_size - WORD_LEN
    )
    logging.debug("Now fix args:")
    for fix_args in fix_list:
        x_struct = ida_typeinf.tinfo_t(tid=fix_args[0])
        ret = x_struct.add_udm(
            name=fix_args[1],
            type=ida_typeinf.tinfo_t(fix_args[2]),
            offset=fix_args[3],
            etf_flags=fix_args[4]
        )
        logging.debug(f"{fix_args} = {ret}")
        temp_udm_index, _ = x_struct.get_udm_by_offset(x_struct.get_size())
        x_struct.del_udm(temp_udm_index)


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
    s_size = sptr.get_size()
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
    udt = ida_typeinf.udt_type_data_t()
    type_info = ida_typeinf.tinfo_t()
    udt.is_union = NOT_UNION
    type_info.create_udt(udt)
    while type_info.set_named_type(None, suggested_name) == ida_typeinf.TERR_OK:
        suggested_name = name + "_" + str(i)
        i += 1
        if i == max_attempts:
            return None, type_info.get_tid()
    return suggested_name, type_info.get_tid()


def get_selected_range_or_line():
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
    if selection:
        return startaddr, endaddr
    else:
        return ida_kernwin.get_screen_ea(), None


def refresh_struct(sptr: ida_typeinf.tinfo_t):
    #  Hack: need to refresh structure so MF_BASECLASS will be updated
    member_ptr = add_to_struct(sptr, "dummy")
    sptr.del_udm(index=member_ptr[0])

