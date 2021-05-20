import logging
import random
import platform
import tempfile

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

MAX_MEMBER_INDEX = 250

def get_word_len():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 8
    elif info.is_32bit():
        return 4
    raise Exception("Unknown address size")


# FIXME: it's not enough to just update WORD_LEN,
# we also need to update all the global vars and class vars,
# that are calculated using WORD_LEN
# We shouldn't store word length in global var at all.
# Instead we should have a getter func, eg. get_word_len()
# and call it each time we need word length
# And we must get rid of all the global and class vars, that depend on word length
# Insead use instance classes
# WORD length in bytes
WORD_LEN = get_word_len()

if WORD_LEN == 4:
    logging.debug("is 32 bit")
elif WORD_LEN == 8:
    logging.debug("is 64 bit")
else:
    logging.error("Unknown address size")


def get_word(ea):
    info = idaapi.get_inf_structure()
    if info.is_32bit():
        return idaapi.get_32bit(ea)
    elif info.is_64bit():
        return idaapi.get_64bit(ea)
    return BADADDR


def get_ptr(ea):
    return get_word(ea)


def make_word(ea):
    info = idaapi.get_inf_structure()
    if info.is_32bit():
        return ida_bytes.create_dword(ea, 4)
    elif info.is_64bit():
        return ida_bytes.create_qword(ea, 8)
    return False


def make_ptr(ea):
    return make_word(ea)


def is_func_start(ea):
    func = ida_funcs.get_func(ea)
    return func is not None and func.start_ea == ea


def get_funcs_list():
    raise Exception("Not implemented")


def enum_drefs_to(ea):
    xref = ida_xref.get_first_dref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_dref_to(ea, xref)


def enum_drefs_from(ea):
    xref = ida_xref.get_first_dref_from(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_dref_from(ea, xref)


def enum_crefs_to(ea):
    xref = ida_xref.get_first_cref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_cref_to(ea, xref)


def enum_crefs_from(ea):
    xref = ida_xref.get_first_cref_from(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_cref_from(ea, xref)


def get_typeinf(typestr):
    if not typestr:
        # Passing None to tinfo_t.get_named_type() can crash IDA
        return None
    tif = idaapi.tinfo_t()
    if not tif.get_named_type(idaapi.get_idati(), typestr):
        return None
    return tif


def get_typeinf_ptr(typeinf):
    if typeinf is None:
        return None
    old_typeinf = typeinf
    if isinstance(typeinf, str):
        typeinf = get_typeinf(typeinf)
    if typeinf is None:
        logging.warning("Couldn't find typeinf %s", old_typeinf or typeinf)
        return None
    tif = idaapi.tinfo_t()
    if not tif.create_ptr(typeinf):
        logging.warning("Couldn't create ptr for typeinf %s", old_typeinf or typeinf)
        return None
    return tif


def get_func_details(func_ea):
    xfunc = ida_hexrays.decompile(func_ea)
    if xfunc is None:
        return None
    func_details = idaapi.func_type_data_t()
    if not xfunc.type.get_func_details(func_details):
        logging.warning("Couldn't get func type details %X", func_ea)
        return None
    return func_details


def update_func_details(func_ea, func_details):
    function_tinfo = idaapi.tinfo_t()
    if not function_tinfo.create_func(func_details):
        logging.warning("Couldn't create func from details %X", func_ea)
        return None
    if not ida_typeinf.apply_tinfo(func_ea, function_tinfo, idaapi.TINFO_DEFINITE):
        logging.warning("Couldn't apply func tinfo %X", func_ea)
        return None
    return function_tinfo


# TODO: refactor
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
                if i > MAX_MEMBER_INDEX:
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
            if i > MAX_MEMBER_INDEX:
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


def set_func_name(func_ea, new_name):
    if not idc.set_name(func_ea, new_name, ida_name.SN_CHECK | ida_name.SN_FORCE):
        logging.warn("Couldn't set func name '%s' at %X", new_name, func_ea)
    return idc.get_name(func_ea)


def deref_tinfo(tinfo):
    if not tinfo:
        return None
    if not tinfo.is_ptr():
        return None
    return tinfo.get_pointed_object()


def is_struct_or_union(tinfo):
    return tinfo.is_struct() or tinfo.is_union()


def get_struc_from_tinfo(struct_tinfo):
    if not struct_tinfo:
        return None
    if not is_struct_or_union(struct_tinfo):
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


def get_member_tinfo(member):
    member_typeinf = idaapi.tinfo_t()
    if not ida_struct.get_member_tinfo(member_typeinf, member):
        logging.warn("Couldn't get member type info")
        return None
    return member_typeinf


def get_sptr_by_name(struct_name):
    sid = idc.get_struc_id(struct_name)
    return ida_struct.get_struc(sid)


def get_member_substruct(member):
    member_type = get_member_tinfo(member)
    if member_type is not None and member_type.is_struct():
        return get_sptr_by_name(member_type.get_type_name())
    elif member.flag & idaapi.FF_STRUCT == idaapi.FF_STRUCT:
        return ida_struct.get_sptr(member)
    return None


def set_member_name(struct, offset, new_name):
    if ida_struct.set_member_name(struct, offset, new_name):
        return True
    for i in range(MAX_MEMBER_INDEX):
        if ida_struct.set_member_name(struct, offset, new_name + "_%d" % i):
            return True
    return False


def get_or_create_struct_id(struct_name, is_union=False):
    """
    @return: struct id or BADADDR if couldn't create struct
    """
    sid = idc.get_struc_id(struct_name)
    if sid != BADADDR:
        return sid
    return idc.add_struc(-1, struct_name, is_union)


def get_or_create_struct(struct_name):
    """
    @return: struct ptr or None if couldn't create struct
    """
    struct_id = get_or_create_struct_id(struct_name)
    return ida_struct.get_struc(struct_id)


def get_signed_int(ea):
    x = idc.get_wide_dword(ea)
    if x & (1 << 31):
        return ((1 << 32) - x) * (-1)
    return x


# TODO: refactor
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
    return ida_lines.tag_remove(ida_kernwin.get_custom_viewer_curline(viewer, False))


#TODO: refactor
strings = None


#TODO: refactor
def refresh_strings():
    global strings
    strings = idautils.Strings()


#TODO: refactor
def get_strings():
    if strings is None:
        refresh_strings()
    return strings


#TODO: refactor
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


def get_func_ea(func_name):
    func = ida_funcs.get_func(idc.get_name_ea_simple(func_name))
    if func is None:
        return BADADDR
    return func.start_ea


#TODO: refactor
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
            return func(*args, **kwargs)
        finally:
            idc.batch(old_batch)

    return wrapper


def get_enum_const_name(enum_name, const_value):
    """ Name of the constant value of the enum or empty string if enum or const does not exist """
    if not enum_name:
        return ""
    enum_id = idc.get_enum(enum_name)
    if enum_id == BADADDR:
        logging.warn("Enum not found %s", enum_name)
        return ""
    const_id = idc.get_enum_member(enum_id, const_value, 0, ida_enum.DEFMASK)
    if const_id == BADADDR:
        logging.warn("Enum const not found %s, %X", enum_name, const_value)
        return ""
    return idc.get_enum_member_name(const_id)


def find_hex_string(start_ea, stop_ea, hex_string):
    ea = ida_search.find_binary(
        start_ea, stop_ea, hex_string, 16, ida_search.SEARCH_DOWN
    )
    while ea != BADADDR:
        yield ea
        ea = ida_search.find_binary(
            ea, stop_ea, hex_string, 16, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
        )


def force_make_struct(ea, struct_name):
    """@return: True on success, False on failure"""
    sid = idc.get_struc_id(struct_name)
    if sid == BADADDR:
        logging.warn("Structure not found: %s", struct_name)
        return False
    size = idc.get_struc_size(sid)
    if not size:
        logging.warn("Structure with zero size: %s", struct_name)
        return False
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
        logging.warn("Failed to delete structure items: %s", struct_name)
        return False
    return ida_bytes.create_struct(ea, size, sid)


def add_struc_retry(name, max_attempts=100, is_union=False):
    """@return structure id on success or BADADDR on failure"""
    sid = idc.add_struc(-1, name, is_union)
    if sid != BADADDR:
        return sid
    for i in range(max_attempts):
        suggested_name = "%s_%i" % (name, i)
        sid = idc.add_struc(-1, suggested_name, is_union)
        if sid != BADADDR:
            return sid
    return BADADDR


def get_selected_range_or_line():
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
    if selection:
        return startaddr, endaddr
    else:
        return ida_kernwin.get_screen_ea(), None


def refresh_struct(sptr):
    #  Hack: the only way to update MF_BASECLASS is to add dummy field at the end of the struct
    if not sptr:
        return False
    member_ptr = add_to_struct(sptr, "dummy")
    if not member_ptr:
        logging.warn("Failed to add dummy field to struct %d", sptr.id)
        return False
    if not ida_struct.del_struc_member(sptr, member_ptr.soff):
        logging.error("Failed to delete dummy member at the end of struct %d", sptr.id)
        return False
    return True


def get_tempdir():
    # In OSX Darwin tempfile.gettempdir() returns private user temp dir, instead of /tmp
    return "/tmp" if platform.system() == "Darwin" else tempfile.gettempdir()
