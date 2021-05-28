import logging
import ida_idp
import ida_struct
import ida_xref
import idautils
import ida_typeinf
import idc

from .. import utils
from ..utils import batchmode

log = logging.getLogger("ida_medigate")


""" IDA7.0 API bugs

ida_struct.get_member_by_id()  @return: tuple(mptr, member_fullname, sptr)
    IDA7.0:
        sptr points to some wrong struct. Attempts to access this struct lead to IDA crash
    In IDA7.5 SP3:
        sptr points to a proper struct
"""

""" IDB_Hooks events order in IDA7.0 and IDA7.5 SP3

Struct member renamed:
    IDA7.0 and IDA7.5:
        renaming_struc_member
            - happens even when name is duplicate
            - doesn't happen if name has incorrect symbols)
            - get_member_name(mptr.id) returns OLD member name
            - new_name contains NEW name
        renamed (struct member)
            - happens only if struct member was successfully renamed
            - get_member_name(ea) returns NEW member name

Struct member type changed:
    IDA7.0:
        struct_member_changed
            - happens before ti_changed
            - get_tinfo(mptr.id) returns OLD member type! (IDA7.0 bug)
        ti_changed (struct member)
            - happens after struct_member_changed
            - get_tinfo(ea) returns NEW member type
    IDA7.5 SP3:
        ti_changed (struct member)
            - happens before struct_member_changed
            - get_tinfo(ea) returns NEW member type
        struct_member_changed
            - happens after ti_changed
            - get_tinfo(mptr.id) returns NEW member type

Function renamed (N on the function):
    IDA7.0 and IDA7.5:
        renamed (func)
            - happens after function was successfully renamed

Function type changed (Y on the function):
    IDA7.0 and IDA7.5:
        ti_changed (func)
            - get_tinfo(ea) returns NEW func type
        func_udpated
        [if function has frame args that are linked to function definition, then for each such frame member]:
            [renaming_struc_member (function frame member)]
            [renamed (function frame member)]

Function arg type changed in decompiler (Y on the function arg):
    IDA7.0:
        ti_changed (func)
            - get_tinfo(ea) retuns NEW func type
        struct_member_changed (arg)
            - get_tinfo(mptr.id) returns OLD arg type! (IDA7.0 bug)
        ti_changed (arg)
            - get_tinfo(mptr.id) returns NEW arg type
        [maybe bunch of renamed with empty new_name]
        func_udpated
    IDA7.5
        ti_changed (func)
            - get_tinfo(ea) returns NEW func type
        ti_changed (arg)
            - get_tinfo(mptr.id) returns NEW arg type
        struct_member_changed:
            - get_tinfo(mptr.id) returns NEW arg type
        [maybe bunch of renamed with empty new_name]
        func_updated

Function arg renamed in decompiler (N on the function arg):
    IDA7.0 and IDA7.5:
        renaming_struc_member (arg)
            - new_name contains NEW arg name
            - get_member_name(mptr.id) returns OLD arg name
        renamed (arg)
            - happens only if arg was successfully renamed
            - new_name contains NEW arg name
            - get_member_name(mptr.id) returns NEW arg name
        ti_changed (func)
            - get_tinfo(ea) returns NEW func type
"""


def enum_linked_members(funcea):
    for xref in idautils.XrefsTo(funcea, ida_xref.XREF_USER):
        if xref.user and xref.type == ida_xref.dr_I:
            if ida_struct.is_member_id(xref.frm):
                yield xref.frm


def has_linked_members(funcea):
    return any(enum_linked_members(funcea))


def enum_linked_funcs(mid):
    for xref in idautils.XrefsFrom(mid, ida_xref.XREF_USER):
        if xref.user and xref.type == ida_xref.dr_I:
            if utils.is_func_start(xref.to):
                yield xref.to


def has_linked_funcs(mid):
    return any(enum_linked_funcs(mid))


def rename_linked_member(mid, new_name):
    if ida_struct.get_member_name(mid) == new_name:
        log.debug(
            "%08X %s: linked member already has name '%s'",
            mid,
            ida_struct.get_member_fullname(mid),
            new_name,
        )
        return
    if ida_struct.is_special_member(mid):
        # special member with the name beginning with ' '?
        log.warn(
            "%08X %s: linked member is a special member", mid, ida_struct.get_member_fullname(mid)
        )
        return
    sptr = utils.get_sptr_by_member_id(mid)
    if not sptr:
        log.warn("%08X: failed to get linked member sptr", mid)
        return
    if sptr.is_frame():
        log.warn(
            "%08X %s: linked member is an arg in function frame",
            mid,
            ida_struct.get_member_name(mid),
        )
        return
    mptr = utils.get_mptr_by_member_id(mid)
    if not mptr:
        log.warn("%08X: failed to get linked member mptr", mid)
        return
    if not ida_struct.set_member_name(sptr, mptr.get_soff(), new_name):
        log.warn(
            "%08X %s: failed to rename linked member to '%s'",
            mid,
            ida_struct.get_member_fullname(mid),
            new_name,
        )
        return
    log.debug(
        "%08X %s: renamed linked member to '%s'", mid, ida_struct.get_member_fullname(mid), new_name
    )


def rename_linked_func(funcea, new_name):
    # TODO: replace "__" with "::" in new_name?
    if idc.get_name(funcea) == new_name:
        log.debug(
            "%08X %s: linked func already has name '%s'", funcea, idc.get_name(funcea), new_name
        )
        return
    if not idc.set_name(funcea, new_name):
        log.warn(
            "%08X %s: failed to rename linked func to '%s'",
            funcea,
            idc.get_name(funcea),
            new_name,
        )
        return
    log.debug("%08X %s: renamed linked func to '%s'", funcea, idc.get_name(funcea), new_name)


def change_linked_member_type(mid, new_member_tif):
    if idc.get_tinfo(mid) == new_member_tif.serialize()[:-1]:
        log.debug(
            "%08X %s: linked member already has type %s",
            mid,
            ida_struct.get_member_fullname(mid),
            new_member_tif,
        )
        return
    mptr, _, sptr = utils.get_member_by_id(mid)
    smt_code = ida_struct.set_member_tinfo(
        sptr, mptr, 0, new_member_tif, ida_typeinf.TINFO_DEFINITE
    )
    if smt_code != ida_struct.SMT_OK:
        log.warn(
            "%08X %s: failed to change linked member type to %s: %s",
            mid,
            ida_struct.get_member_fullname(mid),
            new_member_tif,
            utils.print_smt_code(smt_code),
        )
        return
    log.debug(
        "%08X %s: changed linked member type to %s",
        mid,
        ida_struct.get_member_fullname(mid),
        new_member_tif,
    )


def change_linked_func_type(funcea, new_func_tif):
    if idc.get_tinfo(funcea) == new_func_tif.serialize()[:-1]:
        log.debug(
            "%08X %s: linked func already has type %s", funcea, idc.get_name(funcea), new_func_tif
        )
        return
    if not ida_typeinf.apply_tinfo(funcea, new_func_tif, ida_typeinf.TINFO_DEFINITE):
        log.warn(
            "%08X %s: failed to change linked func type to %s",
            funcea,
            idc.get_name(funcea),
            new_func_tif,
        )
        return
    log.debug("%08X %s: changed linked func type to %s", funcea, idc.get_name(funcea), new_func_tif)


@batchmode
def rename_linked_members(funcea, new_name):
    # TODO: replace "::" with "__" in new_name?
    for mid in enum_linked_members(funcea):
        rename_linked_member(mid, new_name)


@batchmode
def change_linked_members_type(funcea, new_func_tif):
    assert new_func_tif.is_func()
    new_member_tif = utils.get_typeinf_ptr(new_func_tif)
    assert new_member_tif.is_funcptr()
    for mid in enum_linked_members(funcea):
        change_linked_member_type(mid, new_member_tif)


def rename_linked_funcs(mid, new_name):
    # there should be only one such func
    linked_funcs = list(enum_linked_funcs(mid))
    assert len(linked_funcs) == 1, "vtable member points to more than one func"
    funcea = linked_funcs[0]
    rename_linked_func(funcea, new_name)


def change_linked_funcs_type(mid, new_member_tif):
    # there should be only one such func
    assert new_member_tif.is_funcptr()
    new_func_tif = utils.deref_tinfo(new_member_tif)
    assert new_func_tif.is_func()
    linked_funcs = list(enum_linked_funcs(mid))
    assert len(linked_funcs) == 1, "vtable member points to more than one func"
    funcea = linked_funcs[0]
    change_linked_func_type(funcea, new_func_tif)


class CPPHooks(ida_idp.IDB_Hooks):
    def struc_member_renamed(self, sptr, mptr):
        if sptr.is_frame():
            # function argument was renamed, not interested
            return 0
        member_tif = utils.get_member_tinfo(mptr)
        if not member_tif:
            log.warn("%08X: failed to get member tinfo", mptr.id)
            return 0
        if not member_tif.is_funcptr():
            return 0
        if not has_linked_funcs(mptr.id):
            return 0
        new_name = ida_struct.get_member_name(mptr.id)
        if not new_name:
            log.warn("%08X: failed to get member name", mptr.id)
            return
        log.debug(
            "%08X %s: member renamed to '%s', renaming linked func",
            mptr.id,
            ida_struct.get_member_fullname(mptr.id),
            new_name,
        )
        rename_linked_funcs(mptr.id, new_name)
        return 0

    def renamed(self, ea, new_name, local_name):
        # This event happens when anything is renamed,
        # including struct members and function arguments.
        # Here we only interested if function was renamed.
        # And for struct members we have separate event handler.
        if not utils.is_func_start(ea):
            return 0
        if not has_linked_members(ea):
            return 0
        log.debug("%08X: func renamed to '%s', renaming linked members", ea, new_name)
        self.unhook()
        try:
            rename_linked_members(ea, new_name)
        finally:
            self.hook()
        return 0

    def ti_changed(self, ea, type, fnames):
        if utils.is_func_start(ea):
            self._func_type_changed(ea, type, fnames)
        elif ida_struct.is_member_id(ea):
            self._struc_member_type_changed(ea, type, fnames)
        return 0

    def _func_type_changed(self, funcea, type, fnames):
        assert utils.is_func_start(funcea)
        if not has_linked_members(funcea):
            return
        new_tif = utils.deserialize_typeinf(type, fnames)
        if not new_tif:
            logging.warn("%08X %s: failed to deserialize func type", funcea, idc.get_name(funcea))
            return
        log.debug(
            "%08X %s: func type changed to %s, updating linked members type",
            funcea,
            idc.get_name(funcea),
            new_tif,
        )
        self.unhook()
        try:
            change_linked_members_type(funcea, new_tif)
        finally:
            self.hook()

    def _struc_member_type_changed(self, mid, type, fnames):
        assert ida_struct.is_member_id(mid)
        sptr = utils.get_sptr_by_member_id(mid)
        if sptr.is_frame():
            # Func arg type or name has changed and this ti_change() relates to the
            # changed argument itself. We are not interested in it.
            # There will be a separate ti_changed() for the whole function.
            return
        new_member_tif = utils.deserialize_typeinf(type, fnames)
        if not new_member_tif:
            logging.warn(
                "%08X %s: failed to deserialize member type"
                % (mid, ida_struct.get_member_fullname(mid))
            )
            return
        if not new_member_tif.is_funcptr():
            return
        if not has_linked_funcs(mid):
            return
        log.debug(
            "%08X %s: member type changed to %s, updating linked func type",
            mid,
            ida_struct.get_member_fullname(mid),
            new_member_tif,
        )
        change_linked_funcs_type(mid, new_member_tif)
