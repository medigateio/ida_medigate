import logging
import ida_idp
import ida_xref
import idautils
import ida_typeinf
import ida_struct
import idc

from .. import utils

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

Function renamed (press N on the function):
    IDA7.0 and IDA7.5:
        renamed (func)
            - happens after function was successfully renamed

Function type changed (press Y on the function):
    IDA7.0 and IDA7.5:
        ti_changed (func)
            - get_tinfo(ea) returns NEW func type
        func_udpated
        [if function has frame args that are linked to function definition, then for each such frame member]:
            [renaming_struc_member (function frame member)]
            [renamed (function frame member)]

Function arg type changed in decompiler (press Y on the function arg):
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

Function arg renamed in decompiler (press N on the function arg):
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
    assert funcea and utils.is_func_start(funcea)
    for xref in idautils.XrefsTo(funcea, ida_xref.XREF_USER):
        if xref.user and xref.type == ida_xref.dr_I:
            if ida_struct.is_member_id(xref.frm):
                yield xref.frm


def has_linked_members(funcea):
    return any(enum_linked_members(funcea))


def get_linked_func(mid):
    assert mid and ida_struct.is_member_id(mid)
    # each member should have only one linked func
    for xref in idautils.XrefsFrom(mid, ida_xref.XREF_USER):
        if xref.user and xref.type == ida_xref.dr_I:
            if utils.is_func_start(xref.to):
                return xref.to
    return None


def rename_member(mid, new_name):
    assert mid and ida_struct.is_member_id(mid)
    assert new_name
    assert new_name, mid
    old_name = ida_struct.get_member_name(mid)
    assert old_name, mid
    if old_name == new_name:
        return
    assert not ida_struct.is_special_member(mid), mid  # special member name begins with ' '
    mptr, _, sptr = utils.get_member_by_id(mid)
    assert sptr, mid
    assert mptr, mid
    assert not sptr.is_frame(), mid  # linked member cannot be arg in function frame
    if not ida_struct.set_member_name(sptr, mptr.get_soff(), new_name):
        log.warn("Failed to rename member %08X %s to '%s'", mid, old_name, new_name)
        return
    log.debug("Renamed member %08X %s to '%s'", mid, old_name, new_name)


def rename_func(funcea, new_name):
    assert funcea and utils.is_func_start(funcea)
    assert new_name
    old_name = idc.get_name(funcea)
    if old_name == new_name:
        return
    if not idc.set_name(funcea, new_name):
        log.warn("Failed to rename func %08X %s to '%s'", funcea, old_name, new_name)
        return
    log.debug("Renamed func %08X %s to '%s'", funcea, old_name, new_name)


def apply_member_type(mid, py_type):
    """@param py_type: tuple(type, fields), if None, member's type will be deleted"""
    assert mid and ida_struct.is_member_id(mid)
    if not idc.apply_type(mid, py_type, flags=ida_typeinf.TINFO_DEFINITE):
        log.warn("Failed to apply new type to member %08X %s", mid, ida_struct.get_member_name(mid))
        return
    log.debug(
        "%s type for member %08X %s",
        "Applied new" if py_type else "Deleted",
        mid,
        ida_struct.get_member_name(mid),
    )


def apply_func_type(funcea, py_type):
    """@param py_type: tuple(type, fields), if None, func type will be deleted"""
    assert funcea and utils.is_func_start(funcea)
    if py_type is None and idc.get_tinfo(funcea) is None:
        # in this case apply_type() would return False
        # causing unnecessary warning message
        return
    if not idc.apply_type(funcea, py_type, ida_typeinf.TINFO_DEFINITE):
        log.warn(
            "Failed to %s type for func %08X %s",
            "apply new" if py_type else "delete",
            funcea,
            idc.get_name(funcea),
        )
        return
    log.debug(
        "%s type for func %08X %s",
        " Applied new" if py_type else "Deleted",
        funcea,
        idc.get_name(funcea),
    )


class CPPHooks(ida_idp.IDB_Hooks):
    def struc_member_renamed(self, sptr, mptr):
        assert sptr
        assert mptr
        if sptr.is_frame():
            # function argument was renamed, not interested
            # there will be separate ti_changed() event for the whole function type
            return 0
        funcea = get_linked_func(mptr.id)
        if not funcea:
            return 0
        new_name = ida_struct.get_member_name(mptr.id)
        assert new_name, mptr.id
        rename_func(funcea, new_name)
        return 0

    def renamed(self, ea, new_name, local_name):
        # This event happens when anything is renamed,
        # including struct members and function arguments.
        # Here we only interested if function was renamed.
        # And for struct members we have separate event handler.

        if utils.is_func_start(ea):
            self._func_renamed(ea, new_name)
        return 0

    def _func_renamed(self, funcea, new_name):
        assert utils.is_func_start(funcea)
        assert new_name, funcea

        if not has_linked_members(funcea):
            return

        self.unhook()
        old_batch = idc.batch(1)
        try:
            for mid in enum_linked_members(funcea):
                rename_member(mid, new_name)
        finally:
            idc.batch(old_batch)
            self.hook()

    def ti_changed(self, ea, type, fnames):
        if utils.is_func_start(ea):
            self._func_ti_changed(ea, type, fnames)
        elif ida_struct.is_member_id(ea):
            self._struc_member_ti_changed(ea, type, fnames)
        return 0

    def _func_ti_changed(self, funcea, type, fnames):
        assert utils.is_func_start(funcea)

        if not has_linked_members(funcea):
            return

        func_type = (type, fnames) if type else utils.get_func_type(funcea)
        member_type = utils.create_funcptr(func_type)

        self.unhook()
        old_batch = idc.batch(1)
        try:
            for mid in enum_linked_members(funcea):
                apply_member_type(mid, member_type)
        finally:
            idc.batch(old_batch)
            self.hook()

    def _struc_member_ti_changed(self, mid, type, fnames):
        assert ida_struct.is_member_id(mid)

        funcea = get_linked_func(mid)
        if not funcea:
            return

        member_type = (type, fnames) if type else None
        func_type = utils.remove_pointer(member_type) if member_type else None

        apply_func_type(funcea, func_type)
