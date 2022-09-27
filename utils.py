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

log = logging.getLogger("ida_medigate")

MIN_MEMBER_INDEX = 1
MAX_MEMBER_INDEX = 250

# better to use something other than "_"
# to be able to distinguish function indexes from member indexes
MEMBER_INDEX_SPLITTER = "$_"


def get_word_len():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 8
    elif info.is_32bit():
        return 4
    raise Exception("Unknown address size")

try:
    if get_word_len() == 4:
        log.debug("is 32 bit")
    elif get_word_len() == 8:
        log.debug("is 64 bit")
    else:
        log.warn("Unexpected address size: %d", get_word_len())
except Exception as ex:
    log.debug(ex)


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


def is_func(ea):
    func = ida_funcs.get_func(ea)
    return func is not None


def get_func_start(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return BADADDR
    return func.start_ea


def get_funcs_list():
    raise Exception("Not implemented")


def drefs_to(ea):
    xref = ida_xref.get_first_dref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_dref_to(ea, xref)


def drefs_from(ea):
    xref = ida_xref.get_first_dref_from(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_dref_from(ea, xref)


def crefs_to(ea):
    xref = ida_xref.get_first_cref_to(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_cref_to(ea, xref)


def crefs_from(ea):
    xref = ida_xref.get_first_cref_from(ea)
    while xref != BADADDR:
        yield xref
        xref = ida_xref.get_next_cref_from(ea, xref)


def get_typeinf(typestr):
    if not typestr:
        # Passing None to tinfo_t.get_named_type() can crash IDA
        return None
    tif = idaapi.tinfo_t()
    if tif.get_named_type(idaapi.get_idati(), typestr):
        return tif
    PT_SILENT = 1  # in IDA7.0 idc.PT_SILENT=2, which is incorrect
    py_type = idc.parse_decl(typestr, PT_SILENT)
    if not py_type:
        return None
    return deserialize_tinfo(py_type[1:])


def deserialize_tinfo(py_type):
    """@param py_type: tuple(type, fields) """
    # tif.deserialize(None, xtype, None) is fine
    # tif.deserialize(None, None, fields) returns None
    # tif.deserialize(None, None, None) crashes IDA (tested on IDA7.0 and IDA7.5 SP3)
    if py_type is None:
        return None
    xtype, fields = py_type
    if xtype is None:
        return None
    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(None, xtype, fields):
        return None
    return tif


def get_typeinf_ptr(typeinf):
    if typeinf is None:
        return None
    old_typeinf = typeinf
    if isinstance(typeinf, str):
        typeinf = get_typeinf(typeinf)
    if typeinf is None:
        log.warning("Couldn't find typeinf %s", old_typeinf or typeinf)
        return None
    tif = idaapi.tinfo_t()
    if not tif.create_ptr(typeinf):
        log.warning("Couldn't create ptr for typeinf %s", old_typeinf or typeinf)
        return None
    return tif


def create_funcptr(py_type):
    tif = deserialize_tinfo(py_type)
    if not tif:
        return None
    if tif.is_funcptr():
        return py_type
    if not tif.is_func():
        raise RuntimeError("type is not a func: %s" % tif)
    tif.create_ptr(tif)
    assert tif.is_funcptr(), tif
    return tif.serialize()[:-1]


def get_func_type(funcea):
    """
    Try to get decompiled func type.
    If can't decompile func, try to get tinfo from funcea,
    And if funcaa doesn't have associated tinfo, try to guess type at funcea
    @return: tuple(type, fnames)
    """
    if not is_func(funcea):
        log.warn("%08X is not a func", funcea)
        return None
    funcea = get_func_start(funcea)
    try:
        xfunc = ida_hexrays.decompile(funcea)
        return xfunc.type.serialize()[:-1]
    except ida_hexrays.DecompilationFailure as ex:
        log.warn(
            "Couldn't decompile func at %08X: %s, getting or guessing func type from ea", funcea, ex
        )
        return get_or_guess_tinfo(funcea)


def get_func_tinfo(funcea):
    return deserialize_tinfo(get_func_type(funcea))


def get_func_details(funcea):
    """@return: func_type_data_t"""
    func_tif = deserialize_tinfo(get_func_type(funcea))
    if func_tif is None:
        log.warning("%08X Couldn't get func type", funcea)
        return None
    func_details = idaapi.func_type_data_t()
    if not func_tif.get_func_details(func_details):
        log.warning("%08X Couldn't get func type details", funcea)
        return None
    return func_details


def apply_func_details(func_ea, func_details, flags=idaapi.TINFO_DEFINITE):
    func_tif = idaapi.tinfo_t()
    if not func_tif.create_func(func_details):
        log.warning("%08X Couldn't create func from details", func_ea)
        return False
    if not ida_typeinf.apply_tinfo(func_ea, func_tif, flags):
        log.warning("%08X Couldn't apply new func details", func_ea)
        return False
    return True


def get_member_params(member_tif, is_offs):
    """@return: tuple(flag, mt, member_size)"""

    substruct_ptr = get_struc_from_tinfo(member_tif)
    if substruct_ptr:
        flag = idaapi.FF_STRUCT
        mt = ida_nalt.opinfo_t()
        mt.tid = substruct_ptr.id
        member_size = ida_struct.get_struc_size(substruct_ptr.id)
    else:
        flag = idaapi.FF_QWORD if get_word_len() == 8 else idaapi.FF_DWORD
        mt = None
        member_size = get_word_len()

    if is_offs:
        flag |= idaapi.FF_0OFF
        mt = ida_nalt.opinfo_t()
        r = ida_nalt.refinfo_t()
        r.init(ida_nalt.get_reftype_by_size(get_word_len()) | ida_nalt.REFINFO_NOBASE)
        mt.ri = r

    return flag, mt, member_size


def set_member_name_retry(member_ptr, new_name):
    """@return: True/False"""
    assert member_ptr
    assert new_name
    struct_ptr = get_sptr_by_member_id(member_ptr.id)
    offset = member_ptr.get_soff()
    if ida_struct.set_member_name(struct_ptr, offset, new_name):
        return True
    index = MIN_MEMBER_INDEX
    while index <= MAX_MEMBER_INDEX:
        if ida_struct.set_member_name(
            struct_ptr, offset, "%s%s%d" % (new_name, MEMBER_INDEX_SPLITTER, index)
        ):
            return True
    return False


def add_struc_member_retry(struct_ptr, member_name, offset, flag, mt, member_size):
    """
    @return: tuple(error_code, member_ptr)
    @note: use print_struc_error(error_code) to get error message
    """
    assert struct_ptr, offset
    assert member_name, offset
    assert member_size, offset

    error_code = ida_struct.add_struc_member(struct_ptr, member_name, offset, flag, mt, member_size)
    i = 0
    member_base_name = member_name
    while error_code == ida_struct.STRUC_ERROR_MEMBER_NAME:
        member_name = "%s%s%d" % (member_base_name, MEMBER_INDEX_SPLITTER, i)
        i += 1
        if i > MAX_MEMBER_INDEX:
            return None
        error_code = ida_struct.add_struc_member(
            struct_ptr, member_name, offset, flag, mt, member_size
        )

    if error_code == ida_struct.STRUC_ERROR_MEMBER_OK:
        member_ptr = ida_struct.get_member_by_name(struct_ptr, member_name)
        assert member_ptr, offset
    else:
        member_ptr = None

    return error_code, member_ptr


def set_member_tinfo(struct_ptr, member_ptr, new_tif, flags=idaapi.TINFO_DEFINITE):
    """@param new_tif: if None, member type will be deleted"""
    assert struct_ptr and member_ptr

    old_tif = get_member_tinfo(member_ptr)
    if old_tif is None and new_tif is None:
        return True
    if old_tif and new_tif and new_tif == old_tif:
        return True

    if new_tif is None:
        if not ida_struct.del_member_tinfo(struct_ptr, member_ptr):
            return ida_struct.SMT_FAILED
        return ida_struct.SMT_OK

    return ida_struct.set_member_tinfo(struct_ptr, member_ptr, 0, new_tif, flags)


def _remove_member_index(name):
    if not name:
        return name
    if MEMBER_INDEX_SPLITTER in name:
        # remove only the last occurance of index splitter
        return MEMBER_INDEX_SPLITTER.join(name.split(MEMBER_INDEX_SPLITTER)[:-1])
    return name


def _update_member_name(member_ptr, new_member_name, overwrite):
    assert member_ptr
    assert new_member_name

    old_member_name = _remove_member_index(ida_struct.get_member_name(member_ptr.id))
    if old_member_name == new_member_name:
        return True

    if not overwrite:
        log.error("There is already a member at offset 0x%X", member_ptr.get_soff())
        return False

    log.debug("Overwriting member at offset 0x%X!", member_ptr.get_soff())

    if not set_member_name_retry(member_ptr, new_member_name):
        log.error(
            "Failed to overwrite member name with '%s' at offset 0x%X",
            new_member_name,
            member_ptr.get_soff(),
        )
        return False

    return True


def _add_new_member(struct_ptr, offset, member_name, member_tif, is_offs):
    flag, mt, member_size = get_member_params(member_tif, is_offs)
    error_code, member_ptr = add_struc_member_retry(
        struct_ptr, member_name, offset, flag, mt, member_size
    )
    if error_code != ida_struct.STRUC_ERROR_MEMBER_OK:
        log.error(
            "Failed to add member '%s' at offset 0x%X: %s",
            member_name,
            offset,
            print_struc_error(error_code),
        )
        return None
    assert member_ptr, offset
    return member_ptr


def _update_member_type(struct_ptr, member_ptr, member_tif):
    assert struct_ptr
    assert member_ptr
    smt_code = set_member_tinfo(struct_ptr, member_ptr, member_tif)
    if smt_code != ida_struct.SMT_OK:
        log.warn(
            "Failed to %s type%s for member %s at offset 0x%X: %s",
            "set" if member_tif else "delete",
            " '%s'" % member_tif if member_tif else "",
            ida_struct.get_member_name(member_ptr.id),
            member_ptr.get_soff(),
            print_smt_error(smt_code),
        )


def add_to_struct(
    struct_ptr,
    member_name,
    member_tif=None,
    offset=BADADDR,
    is_offs=False,
    overwrite=False,
):
    """@return: member_ptr, or None if failed"""
    member_ptr = ida_struct.get_member(struct_ptr, offset)

    if member_ptr:
        # pylint: disable=too-many-function-args
        if not _update_member_name(member_ptr, member_name, overwrite):
            return None
    else:
        member_ptr = _add_new_member(struct_ptr, offset, member_name, member_tif, is_offs)
        if not member_ptr:
            return None

    _update_member_type(struct_ptr, member_ptr, member_tif)

    return member_ptr


def set_func_name(func_ea, new_name):
    if not idc.set_name(func_ea, new_name, ida_name.SN_CHECK | ida_name.SN_FORCE):
        log.warn("%08X Couldn't set func name '%s'", func_ea, new_name)
    return idc.get_name(func_ea)


def deref_tinfo(tif):
    if not tif:
        return None
    if not tif.is_ptr():
        return tif
    return tif.get_pointed_object()


def guess_tinfo(ea):
    """@return: tuple(type, fields) just like idc.get_tinfo()"""
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.guess_tinfo(tif, ea):
        return tif.serialize()[:-1]
    return None


def get_or_guess_tinfo(ea):
    """@return: tuple(type, fields) just like idc.get_tinfo()"""
    py_type = idc.get_tinfo(ea)
    if py_type:
        return py_type
    return guess_tinfo(ea)


def remove_pointer(py_type):
    """If given type is not a pointer, return given type."""
    tif = deserialize_tinfo(py_type)
    if not tif:
        return None
    return ida_typeinf.remove_pointer(tif).serialize()[:-1]


def is_struct_or_union(tinfo):
    return tinfo.is_struct() or tinfo.is_union()


def get_struc_from_tinfo(struct_tif):
    if not struct_tif:
        return None
    if not is_struct_or_union(struct_tif):
        return None
    struct_id = ida_struct.get_struc_id(struct_tif.get_type_name())
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


def get_member_tinfo(mptr):
    if not mptr:
        return None
    member_tif = idaapi.tinfo_t()
    if not ida_struct.get_member_tinfo(member_tif, mptr):
        return None
    return member_tif


def get_mptr_by_member_id(mid):
    if mid is None or mid == BADADDR:
        return None
    res = ida_struct.get_member_by_id(mid)
    if not res:
        return None
    return res[0]


def get_sptr_by_member_id(mid):
    if mid is None or mid == BADADDR:
        return None
    mptr = get_mptr_by_member_id(mid)
    if not mptr:
        return None
    return ida_struct.get_member_struc(ida_struct.get_member_fullname(mptr.id))


def get_member_by_id(mid):
    # Replacement for the ida_struct.get_member_by_id(),
    # which in IDA7.0 returns incorrect sptr
    res = ida_struct.get_member_by_id(mid)
    if not res:
        return None
    mptr, member_fullname, _ = res
    sptr = ida_struct.get_member_struc(ida_struct.get_member_fullname(mptr.id))
    return mptr, member_fullname, sptr


def print_smt_error(smt_code):
    return {
        ida_struct.SMT_OK: "success: changed the member type",
        ida_struct.SMT_BADARG: "bad parameters",
        ida_struct.SMT_NOCOMPAT: "the new type is not compatible with the old type",
        ida_struct.SMT_WORSE: "the new type is worse than the old type",
        ida_struct.SMT_SIZE: "the new type is incompatible with the member size",
        ida_struct.SMT_ARRAY: "arrays are forbidden as function arguments",
        ida_struct.SMT_OVERLAP: "member would overlap with members that can not be deleted",
        ida_struct.SMT_FAILED: "failed to set new member type",
        ida_struct.SMT_KEEP: "no need to change the member type, the old type is better",
    }.get(smt_code, "unknown smt code: %d" % smt_code)


def print_struc_error(struc_error):
    return {
        ida_struct.STRUC_ERROR_MEMBER_OK: "success",
        ida_struct.STRUC_ERROR_MEMBER_NAME: "already has member with this name (bad name)",
        ida_struct.STRUC_ERROR_MEMBER_OFFSET: "already has member at this offset",
        ida_struct.STRUC_ERROR_MEMBER_SIZE: "bad number of bytes or bad sizeof(type)",
        ida_struct.STRUC_ERROR_MEMBER_TINFO: "bad typeid parameter",
        ida_struct.STRUC_ERROR_MEMBER_STRUCT: "bad struct id (the 1st argument)",
        ida_struct.STRUC_ERROR_MEMBER_UNIVAR: "unions can't have variable sized members",
        ida_struct.STRUC_ERROR_MEMBER_VARLAST: "variable sized member should be the last member "
        "in the structure",
        ida_struct.STRUC_ERROR_MEMBER_NESTED: "recursive structure nesting is forbidden",
    }.get(struc_error, "unknown struc error: %d" % struc_error)


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
        log.warning("Struct id 0x%X wasn't found", struct_id)
        return
    log.debug(
        "Expanding struc %s, size: 0x%X -> 0x%X",
        ida_struct.get_struc_name(struct_id),
        ida_struct.get_struc_size(struct_id),
        new_size,
    )
    if ida_struct.get_struc_size(struct_id) > new_size - get_word_len():
        return
    fix_list = []
    xrefs = idautils.XrefsTo(struct.id)
    for xref in xrefs:
        if xref.type == ida_xref.dr_R and xref.user == 0 and xref.iscode == 0:
            res = ida_struct.get_member_by_id(xref.frm)
            if not res or not res[0]:
                log.warning("Xref from %08X wasn't struct_member", xref.frm)
                continue
            member = res[0]
            x_struct = ida_struct.get_member_struc(ida_struct.get_member_fullname(member.id))
            assert x_struct
            old_name = ida_struct.get_member_name(member.id)
            offset = member.soff
            # FIXME: why use random here?
            marker_name = "marker_%d" % random.randint(0, 0xFFFFFF)
            # FIXME: check if add_struc_member actually added a member
            idc.add_struc_member(
                x_struct.id,
                marker_name,
                member.soff + new_size,
                idaapi.FF_DATA | idaapi.FF_BYTE,
                -1,
                0,
            )
            log.debug(
                "Delete member (0x%X-0x%X)",
                member.soff,
                member.soff + new_size - 1,
            )
            # FIXME: check if struc member actually deleted
            ida_struct.del_struc_members(x_struct, member.soff, member.soff + new_size - 1)
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

    ret = add_to_struct(ida_struct.get_struc(struct_id), None, None, new_size - get_word_len())
    log.debug("Now fix args:")
    for fix_args in fix_list:
        ret = idc.add_struc_member(*fix_args)
        log.debug("%s = %d", fix_args, ret)
        x_struct_id = fix_args[0]
        idc.del_struc_member(x_struct_id, ida_struct.get_struc_size(x_struct_id))


def get_curline_striped_from_viewer(viewer):
    return ida_lines.tag_remove(ida_kernwin.get_custom_viewer_curline(viewer, False))


# strings dictionary significantly speads up string search in IDA database
strings = None  # dict(str, StringItem)


def refresh_strings():
    # pylint: disable=global-statement
    global strings
    strings = {}
    for i in idautils.Strings():
        s = str(i)
        if s not in strings:
            strings[s] = [i]
        else:
            strings[s].append(i)


def get_strings(s):
    if strings is None:
        refresh_strings()
    return strings.get(s, [])


def get_strings_xrefs(s, filter_func=None):
    """filter_func(x,s) choose x if True for magic str (s)"""

    def default_filter_func(x, string):
        return str(x) == string

    if filter_func is None:
        filter_func = default_filter_func

    xrefs = set()
    for i in get_strings(s):
        xrefs |= set(drefs_to(i.ea))

    return list(xrefs)


def get_funcs_with_string(s):
    funcs = set(map(ida_funcs.get_func, get_strings_xrefs(s)))
    return list(funcs - {None})


def get_func_ea(func_name):
    func = ida_funcs.get_func(idc.get_name_ea_simple(func_name))
    if func is None:
        return BADADDR
    return func.start_ea


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
        log.warn("Enum not found %s", enum_name)
        return ""
    const_id = idc.get_enum_member(enum_id, const_value, 0, ida_enum.DEFMASK)
    if const_id == BADADDR:
        log.warn("Enum const not found %s, 0x%X", enum_name, const_value)
        return ""
    return idc.get_enum_member_name(const_id)


def find_hex_string(start_ea, stop_ea, hex_string):
    ea = ida_search.find_binary(start_ea, stop_ea, hex_string, 16, ida_search.SEARCH_DOWN)
    while ea != BADADDR:
        yield ea
        ea = ida_search.find_binary(
            ea,
            stop_ea,
            hex_string,
            16,
            ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT,
        )


def force_make_struct(ea, struct_name):
    """@return: True on success, False on failure"""
    sid = idc.get_struc_id(struct_name)
    if sid == BADADDR:
        log.warn("Structure not found: %s", struct_name)
        return False
    size = idc.get_struc_size(sid)
    if not size:
        log.warn("Structure with zero size: %s", struct_name)
        return False
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
        log.warn("Failed to delete structure items: %s", struct_name)
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
    return ida_kernwin.get_screen_ea(), None


def refresh_struct(sptr):
    #  Hack: the only way to update MF_BASECLASS is to add dummy field at the end of the struct
    if not sptr:
        return False
    member_ptr = add_to_struct(sptr, "dummy")
    if not member_ptr:
        log.warn("Failed to add dummy field to struct 0x%X", sptr.id)
        return False
    if not ida_struct.del_struc_member(sptr, member_ptr.soff):
        log.error("Failed to delete dummy member at the end of struct 0x%X", sptr.id)
        return False
    return True


def get_tempdir():
    # In OSX Darwin tempfile.gettempdir() returns private user temp dir, instead of /tmp
    return "/tmp" if platform.system() == "Darwin" else tempfile.gettempdir()
