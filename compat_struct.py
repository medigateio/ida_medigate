# -*- coding: utf-8 -*-
"""
Compatibility shim: re-implements the subset of the removed ``ida_struct`` module
(and the ``struc_t`` / ``member_t`` object model) that ida_medigate uses, on top of
the IDA 9 ``ida_typeinf`` / ``idc`` APIs.

IDA 9.0 removed ``ida_struct`` and ``ida_enum`` (struct/enum model moved to
``ida_typeinf``).  ida_medigate was written for IDA 7.x.  Rather than rewrite ~90
call sites, each module does ``from . import compat_struct as ida_struct`` and keeps
calling ``ida_struct.*`` unchanged.

Design notes:
* Member access stays BYTE-offset based (the legacy ``soff`` semantics) by delegating
  to the ``idc.*`` struct helpers, which still exist in IDA 9 and still take byte
  offsets.  This avoids the ``ida_typeinf`` bit-offset pitfall.
* ``get_struc`` returns a light ``_Struc`` wrapper exposing ``.id`` / ``.is_union()``.
* ``get_member`` returns a light ``_Member`` wrapper exposing ``.id`` / ``.soff`` /
  ``.get_soff()`` / ``.flag`` / ``.props`` (``props |= MF_BASECLASS`` is honoured).
"""
import idaapi
import idc
import ida_typeinf

try:
    import ida_idaapi
    BADADDR = ida_idaapi.BADADDR
except Exception:  # pragma: no cover
    BADADDR = idaapi.BADADDR

# ---- legacy constants -------------------------------------------------------
# idc still exposes the STRUC_ERROR_MEMBER_* codes returned by add_struc_member.
STRUC_ERROR_MEMBER_NAME = getattr(idc, "STRUC_ERROR_MEMBER_NAME", -3)
STRUC_ERROR_MEMBER_OFFSET = getattr(idc, "STRUC_ERROR_MEMBER_OFFSET", -2)
STRUC_ERROR_MEMBER_SIZE = getattr(idc, "STRUC_ERROR_MEMBER_SIZE", -4)
STRUC_ERROR_MEMBER_TINFO = getattr(idc, "STRUC_ERROR_MEMBER_TINFO", -5)
# legacy member property bit for "this member is a base class"
MF_BASECLASS = 0x00000002

_FF_STRUCT = getattr(idaapi, "FF_STRUCT", 0x60000000)

# member-tid -> (sid, byte_offset); populated whenever we hand out a _Member
_MID2LOC = {}


# ---- internal helpers -------------------------------------------------------
def _sid_of(s):
    return s.id if isinstance(s, _Struc) else s


def _struct_tif(sid):
    """Load the tinfo_t for a struct/union by its tid, or None."""
    t = ida_typeinf.tinfo_t()
    try:
        if t.get_type_by_tid(sid) and t.is_udt():
            return t
    except Exception:
        pass
    return None


def _udm_by_off(sid, byte_off):
    """Return (tif, idx, udm) for the member whose start == byte_off, else (tif,-1,None)."""
    t = _struct_tif(sid)
    if t is None:
        return None, -1, None
    try:
        idx, udm = t.get_udm_by_offset(byte_off * 8)
    except Exception:
        idx, udm = -1, None
    return t, (idx if idx is not None else -1), udm


def _copy_tinfo(dst, src):
    """Make dst hold a copy of src (tinfo_t)."""
    try:
        dst.swap(ida_typeinf.tinfo_t(src))
        return True
    except Exception:
        pass
    try:
        dst.assign(src)
        return True
    except Exception:
        return False


def _is_bad_id(x):
    # idc returns BADADDR (0xFFFF...) or -1 for "not found"; both are invalid.
    return x is None or x == BADADDR or x < 0


def _edit_udt(sid, mutate):
    """Load the UDT details, let mutate(udt) change them in place (returns True if
    it changed something), then rebuild and store the type under its name. Proven
    to preserve members and persist udm flag/type changes on IDA 9.4."""
    t = _struct_tif(sid)
    if t is None:
        return False
    udt = ida_typeinf.udt_type_data_t()
    if not t.get_udt_details(udt):
        return False
    if not mutate(udt):
        return False
    bt = ida_typeinf.BTF_UNION if t.is_union() else ida_typeinf.BTF_STRUCT
    nt = ida_typeinf.tinfo_t()
    if not nt.create_udt(udt, bt):
        return False
    return nt.set_named_type(
        None, idc.get_struc_name(sid), getattr(ida_typeinf, "NTF_REPLACE", 0x20)
    ) == 0


# ---- wrapper objects --------------------------------------------------------
class _Struc(object):
    __slots__ = ("id",)

    def __init__(self, sid):
        self.id = sid

    def is_union(self):
        t = _struct_tif(self.id)
        return bool(t and t.is_union())


class _Member(object):
    def __init__(self, sid, soff):
        self._sid = sid
        self.soff = soff
        mid = idc.get_member_id(sid, soff)
        self.id = mid
        if not _is_bad_id(mid):
            _MID2LOC[mid] = (sid, soff)
        self._props = 0

    def get_soff(self):
        return self.soff

    @property
    def flag(self):
        tif = ida_typeinf.tinfo_t()
        if get_member_tinfo(tif, self) and tif.is_udt():
            return _FF_STRUCT
        return 0

    @property
    def props(self):
        return self._props

    @props.setter
    def props(self, value):
        self._props = value
        if value & MF_BASECLASS:
            _set_member_baseclass(self._sid, self.soff, True)


# ---- struct-level API -------------------------------------------------------
def add_struc(_dummy, name, is_union=False):
    return idc.add_struc(-1, name, bool(is_union))


def get_struc_id(name):
    return idc.get_struc_id(name)


def get_struc(sid):
    sid = _sid_of(sid)
    if sid is None or sid == BADADDR:
        return None
    if idc.get_struc_name(sid) is None:
        return None
    return _Struc(sid)


def get_struc_name(sid):
    return idc.get_struc_name(_sid_of(sid))


def get_struc_size(s):
    return idc.get_struc_size(_sid_of(s))


def set_struc_name(sid, name):
    return idc.set_struc_name(_sid_of(sid), name)


def get_max_offset(sptr):
    # legacy: end offset of the struct (== size for non-unions)
    return idc.get_struc_size(_sid_of(sptr))


# ---- member-level API -------------------------------------------------------
def add_struc_member(sptr, name, offset, flag, mt, size):
    sid = _sid_of(sptr)
    typeid = -1
    if mt is not None:
        typeid = getattr(mt, "tid", -1)
        if typeid is None:
            typeid = -1
    if offset is None:
        offset = BADADDR
    return idc.add_struc_member(sid, name or "", offset, flag, typeid, size)


def get_member(sptr, offset):
    sid = _sid_of(sptr)
    t, idx, udm = _udm_by_off(sid, offset)
    if udm is not None:
        return _Member(sid, udm.offset // 8)
    mid = idc.get_member_id(sid, offset)
    if _is_bad_id(mid):
        return None
    return _Member(sid, offset)


def get_member_by_name(sptr, name):
    sid = _sid_of(sptr)
    off = idc.get_member_offset(sid, name)
    if off is None or off == BADADDR or off == -1:
        return None
    return _Member(sid, off)


def _loc_from_mid(mid):
    """Resolve a member tid to (sid, byte_off): registry first, then by fullname."""
    loc = _MID2LOC.get(mid)
    if loc:
        return loc
    getfn = getattr(idaapi, "get_member_fullname", None)
    if getfn:
        try:
            full = getfn(mid)
        except Exception:
            full = None
        if full and "." in full:
            sname, mname = full.split(".", 1)
            sid = idc.get_struc_id(sname)
            if sid != BADADDR:
                off = idc.get_member_offset(sid, mname)
                if off not in (None, BADADDR, -1):
                    _MID2LOC[mid] = (sid, off)
                    return (sid, off)
    return None


def get_member_by_id(mid):
    """Return (member, fullname, sptr) as the legacy API did, else (None, None, None)."""
    loc = _loc_from_mid(mid)
    if not loc:
        return None, None, None
    sid, soff = loc
    m = _Member(sid, soff)
    full = "%s.%s" % (idc.get_struc_name(sid) or "", idc.get_member_name(sid, soff) or "")
    return m, full, _Struc(sid)


def get_member_by_fullname(fullname):
    """Legacy ida_struct.get_member_by_fullname('Struct.member') -> member (or None)."""
    if not fullname or "." not in fullname:
        return None
    sname, mname = fullname.split(".", 1)
    sid = idc.get_struc_id(sname)
    if sid == BADADDR:
        return None
    off = idc.get_member_offset(sid, mname)
    if off in (None, BADADDR, -1):
        return None
    return _Member(sid, off)


def get_member_name(mid):
    loc = _loc_from_mid(mid)
    if loc:
        return idc.get_member_name(loc[0], loc[1])
    return None


def get_struc_by_idx(idx):
    """Best-effort legacy ida_struct.get_struc_by_idx(): tid of the idx-th UDT in the til."""
    til = ida_typeinf.get_idati()
    try:
        limit = ida_typeinf.get_ordinal_limit(til)
    except Exception:
        try:
            limit = ida_typeinf.get_ordinal_count(til)
        except Exception:
            limit = 0
    count = -1
    for ordn in range(1, limit):
        t = ida_typeinf.tinfo_t()
        try:
            if t.get_numbered_type(til, ordn) and t.is_udt():
                count += 1
                if count == idx:
                    return t.get_tid()
        except Exception:
            continue
    return BADADDR


def set_member_name(sptr, offset, name):
    return bool(idc.set_member_name(_sid_of(sptr), offset, name))


def del_struc_member(sptr, offset):
    return idc.del_struc_member(_sid_of(sptr), offset)


def del_struc_members(sptr, off1, off2):
    sid = _sid_of(sptr)
    t = _struct_tif(sid)
    if t is None:
        return
    try:
        udt = ida_typeinf.udt_type_data_t()
        t.get_udt_details(udt)
        starts = [m.offset // 8 for m in udt if off1 <= (m.offset // 8) <= off2]
    except Exception:
        starts = []
    for off in sorted(starts, reverse=True):
        idc.del_struc_member(sid, off)


def get_member_tinfo(out_tif, member):
    _t, _idx, udm = _udm_by_off(member._sid, member.soff)
    if udm is None:
        return False
    return _copy_tinfo(out_tif, udm.type)


def set_member_tinfo(sptr, member, delta, tinfo, flags):
    # Be tolerant of callers that accidentally hand us a get_member_by_id()
    # tuple or None instead of a member object.
    if isinstance(member, tuple):
        member = member[0] if member else None
    if member is None or not hasattr(member, "soff"):
        return False
    sid = _sid_of(sptr)
    soff = member.soff
    t = _struct_tif(sid)
    if t is None:
        return False
    # Fast path: set_udm_type edits the stored type in place.
    try:
        idx = t.find_udm(soff * 8)
        if idx is not None and idx >= 0 and t.set_udm_type(idx, tinfo, 0) == 0:
            return True
    except Exception:
        pass

    # Fallback: rebuild the UDT with the member's type replaced.
    def mutate(udt):
        for i in range(len(udt)):
            if udt[i].offset // 8 == soff:
                udt[i].type = tinfo
                return True
        return False

    return _edit_udt(sid, mutate)


def get_sptr(member):
    """Sub-struct embedded at a member (member type is a UDT), else None."""
    tif = ida_typeinf.tinfo_t()
    if not get_member_tinfo(tif, member):
        return None
    if tif.is_ptr():
        tif = tif.get_pointed_object()
    if tif is not None and tif.is_udt():
        sid = idc.get_struc_id(tif.get_type_name() or "")
        if sid != BADADDR:
            return _Struc(sid)
    return None


# ---- base-class flag --------------------------------------------------------
def _set_member_baseclass(sid, byte_off, on=True):
    def mutate(udt):
        for i in range(len(udt)):
            if udt[i].offset // 8 == byte_off:
                udt[i].set_baseclass(on)
                return True
        return False

    try:
        _edit_udt(sid, mutate)
    except Exception:
        pass
