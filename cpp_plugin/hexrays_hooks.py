import logging
import ida_hexrays
import ida_nalt
import ida_struct
import idaapi
from idc import BADADDR
from .. import cpp_utils, utils

log = logging.getLogger("ida_medigate")


_ANOTHER_DECOMPILER_EA = None


class Polymorphism_fixer_visitor_t(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.counter = 0
        self.selections = []

    def get_vtables_union_name(self, expr):
        if expr.op != ida_hexrays.cot_memref:
            return None
        typeinf = expr.type
        if typeinf is None:
            return None
        if not typeinf.is_union():
            return None
        union_name = typeinf.get_type_name()
        if not cpp_utils.is_vtables_union_name(union_name):
            return None
        return union_name

    def build_classes_chain(self, expr):
        chain = []
        n_expr = expr.x
        while n_expr.op == ida_hexrays.cot_memref:
            chain.insert(0, n_expr.type.get_type_name())
            n_expr = n_expr.x
        chain.insert(0, n_expr.type.get_type_name())
        if n_expr.op == ida_hexrays.cot_memptr:
            chain.insert(0, n_expr.x.type.get_pointed_object().get_type_name())
        elif n_expr.op == ida_hexrays.cot_idx:
            log.debug("encountered idx, skipping")
            return None
        return chain

    def find_best_member(self, chain, union_name):
        for cand in chain:
            result = ida_struct.get_member_by_fullname(union_name + "." + cand)
            if result:
                m, s = result
                log.debug("Found class: %s, offset=0x%X", cand, m.soff)
                return m
        return None

    def get_vtable_sptr(self, m):
        vtable_type = utils.get_member_tinfo(m)
        if not (vtable_type and vtable_type.is_ptr()):
            log.debug("vtable_type isn't ptr %s", vtable_type)
            return None

        vtable_struc_typeinf = vtable_type.get_pointed_object()
        if not (vtable_struc_typeinf and vtable_struc_typeinf.is_struct()):
            log.debug("vtable isn't struct (%s)", vtable_struc_typeinf.dstr())
            return None

        vtable_struct_name = vtable_struc_typeinf.get_type_name()
        vtable_sptr = utils.get_sptr_by_name(vtable_struct_name)
        if vtable_sptr is None:
            log.debug(
                "%08X: Oh no %s is not a valid struct",
                self.cfunc.entry_ea,
                vtable_struct_name,
            )
            return None

        return vtable_sptr

    def get_ancestors(self):
        vtable_expr = self.parents.back().cexpr
        if vtable_expr.op not in (
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_memref,
        ):
            return None

        if self.parents.size() < 2:
            log.debug("parents size less than 2 (%d)", self.parents.size())
            return None

        idx_cexpr = None
        funcptr_parent = None
        funcptr_item = self.parents.at(self.parents.size() - 2)
        if not funcptr_item.is_expr():
            log.debug(
                "funcptr_item is not expr!: %s %s %d",
                type(funcptr_item),
                funcptr_item.is_expr(),
                funcptr_item.op,
            )
            return None
        funcptr_expr = funcptr_item.cexpr
        if funcptr_expr.op == ida_hexrays.cot_idx:
            idx_cexpr = funcptr_expr
            if self.parents.size() < 4:
                log.debug(
                    "there is idx but parents size less than 3 (%d)",
                    self.parents.size(),
                )
                return None

            funcptr_expr = self.parents.at(self.parents.size() - 3)
            if not funcptr_expr.is_expr():
                log.debug("funcptr isn't expr")
                return None
            funcptr_expr = funcptr_expr.cexpr
            funcptr_parent = self.parents.at(self.parents.size() - 4)
            if not funcptr_parent.is_expr():
                log.debug("funcptr_parent isn't expr")
                return None
            funcptr_parent = funcptr_parent.cexpr
        if funcptr_expr.op not in (
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_memref,
        ):

            log.debug("funcptr_expr isn't -> (%s)", funcptr_expr.opname)
            return None

        return funcptr_parent, funcptr_expr, idx_cexpr, vtable_expr

    def fix_member_idx(self, idx_cexpr):
        num = 0
        if idx_cexpr:
            # wrong vtable*, so it might be too short struct, like:
            #   .vtable.PdmAcqServiceIf[1].___cxa_pure_virtual_2
            if idx_cexpr.y.op != ida_hexrays.cot_num:
                log.debug(
                    "%08X: idx doesn't contains a num but %s",
                    self.cfunc.entry_ea,
                    idx_cexpr.y.opname,
                )
                return -1
            num = idx_cexpr.y.get_const_value()
            if not (idx_cexpr.type and idx_cexpr.type.is_struct()):
                log.debug(
                    "%08X idx type isn't struct %s",
                    self.cfunc.entry_ea,
                    idx_cexpr.type,
                )
                return -1
            idx_struct = utils.get_struc_from_tinfo(idx_cexpr.type)
            if idx_struct is None:
                log.debug(
                    "%08X idx type isn't pointing to struct %s",
                    self.cfunc.entry_ea,
                    idx_cexpr.type,
                )
                return -1
            struct_size = ida_struct.get_struc_size(idx_struct)
            num *= struct_size
        return num

    def get_vtable_member_type(self, vtable_sptr, offset):
        vtable_struct_name = ida_struct.get_struc_name(vtable_sptr.id)
        try:
            funcptr_member = ida_struct.get_member(vtable_sptr, offset)
        except TypeError:
            log.exception("%08X: bad offset: 0x%X", self.cfunc.entry_ea, offset)
            return None

        if funcptr_member is None:
            log.debug(
                "%08X:  %s.0x%X is not a valid struct member",
                self.cfunc.entry_ea,
                vtable_struct_name,
                offset,
            )
            return None

        funcptr_member_type = utils.get_member_tinfo(funcptr_member)
        if not funcptr_member_type.is_funcptr():
            log.debug(
                "%08X: member type (%s) isn't funcptr!",
                self.cfunc.entry_ea,
                funcptr_member_type.dstr(),
            )
            return None

        return funcptr_member_type

    def find_funcptr(self, m):
        ancestors = self.get_ancestors()
        if ancestors is None:
            return None
        funcptr_parent, funcptr_expr, idx_cexpr, vtable_expr = ancestors

        vtable_sptr = self.get_vtable_sptr(m)
        if vtable_sptr is None:
            return None
        offset = self.fix_member_idx(idx_cexpr)
        if offset == -1:
            return None
        funcptr_member_type = self.get_vtable_member_type(vtable_sptr, funcptr_expr.m + offset)
        return funcptr_member_type

    def dump_expr(self, e):
        log.debug("dump: %s", e.opname)
        while e.op in [
            ida_hexrays.cot_memref,
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_cast,
            ida_hexrays.cot_call,
        ]:
            if e.op in [ida_hexrays.cot_memref, ida_hexrays.cot_memptr]:
                log.debug("(%s, %d, %s", e.opname, e.m, e.type.dstr())
            else:
                log.debug("(%s, %s", e.opname, e.type.dstr())
            e = e.x

    def find_ea(self):
        i = self.parents.size() - 1
        parent = self.parents.at(i)
        ea = BADADDR
        while i >= 0 and (parent.is_expr() or parent.op == ida_hexrays.cit_expr):
            if parent.cexpr.ea != BADADDR:
                ea = parent.cexpr.ea
                break
            i -= 1
            parent = self.parents.at(i)
        return ea

    def visit_expr(self, expr):
        union_name = self.get_vtables_union_name(expr)
        if union_name is None:
            return 0
        log.debug("Found union - %s", union_name)

        chain = self.build_classes_chain(expr)
        if chain is None:
            return 0

        m = self.find_best_member(chain, union_name)
        if m is None:
            return 0

        ea = self.find_ea()

        funcptr_member_type = self.find_funcptr(m)

        if ea == BADADDR:
            log.debug("BADADDR")
            return 0
        log.debug("Found VTABLES, ea: %08X", ea)
        self.selections.append((ea, m.soff, funcptr_member_type))
        return 0


def _on_maturity(cfunc, maturity):
    global _ANOTHER_DECOMPILER_EA
    if maturity not in [idaapi.CMAT_FINAL]:
        return
    if _ANOTHER_DECOMPILER_EA:
        _ANOTHER_DECOMPILER_EA = None
        return
    # if maturity in [idaapi.CMAT_CPA]:
    # if maturity in [idaapi.CPA]:
    pfv = Polymorphism_fixer_visitor_t(cfunc)
    pfv.apply_to_exprs(cfunc.body, None)
    log.debug("results: %s", pfv.selections)
    if pfv.selections == []:
        return
    for ea, offset, funcptr_member_type in pfv.selections:
        intvec = idaapi.intvec_t()
        # TODO: Think if needed to distinguished between user
        #   union members chooses and plugin chooses
        if not cfunc.get_user_union_selection(ea, intvec):
            intvec.push_back(offset)
            cfunc.set_user_union_selection(ea, intvec)
            if funcptr_member_type is not None:
                ida_nalt.set_op_tinfo(ea, 0, funcptr_member_type)
    cfunc.save_user_unions()
    _ANOTHER_DECOMPILER_EA = cfunc.entry_ea


def _on_refresh_pseudocode(vu):
    global _ANOTHER_DECOMPILER_EA
    if not _ANOTHER_DECOMPILER_EA:
        return
    log.debug("decompile again")
    ea = _ANOTHER_DECOMPILER_EA
    ida_hexrays.mark_cfunc_dirty(ea, False)
    cfunc = ida_hexrays.decompile(ea)
    _ANOTHER_DECOMPILER_EA = None
    vu.switch_to(cfunc, True)


def _callback(*args):
    if args[0] == idaapi.hxe_maturity:
        cfunc = args[1]
        maturity = args[2]
        _on_maturity(cfunc, maturity)
    elif args[0] == idaapi.hxe_refresh_pseudocode:
        vu = args[1]
        _on_refresh_pseudocode(vu)
    return 0


def install_hexrays_hook():
    return ida_hexrays.install_hexrays_callback(_callback)


def remove_hexrays_hook():
    return ida_hexrays.remove_hexrays_callback(_callback)
