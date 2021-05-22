# -*- coding: utf-8 -*-
"""
Referee creates struct xrefs for decompiled functions
"""

import sys
import logging
import traceback

import idaapi

log = logging.getLogger("referee")

IS_PYTHON3 = sys.version_info[0] == 3

NETNODE_NAME = "$ referee-xrefs"
NETNODE_TAG = "X"


def is_assn(t):
    return (
        t == idaapi.cot_asg
        or t == idaapi.cot_asgbor
        or t == idaapi.cot_asgxor
        or t == idaapi.cot_asgband
        or t == idaapi.cot_asgsub
        or t == idaapi.cot_asgmul
        or t == idaapi.cot_asgsshr
        or t == idaapi.cot_asgushr
        or t == idaapi.cot_asgsdiv
        or t == idaapi.cot_asgudiv
        or t == idaapi.cot_asgsmod
        or t == idaapi.cot_asgumod
    )


def is_incdec(t):
    return (
        t == idaapi.cot_postinc  # = 53,  ///< x++
        or t == idaapi.cot_postdec  # = 54,  ///< x--
        or t == idaapi.cot_preinc  # = 55,  ///< ++x
        or t == idaapi.cot_predec  # = 56,  ///< --x
    )


def add_struct_xrefs(cfunc):
    class xref_adder_t(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
            self.cfunc = cfunc
            self.node = idaapi.netnode()
            self.clear_struct_xrefs()
            self.xrefs = {}

        def load(self):
            try:
                data = self.node.getblob_ea(self.cfunc.entry_ea, NETNODE_TAG)
                if data:
                    if IS_PYTHON3:
                        # data is just a dict, where key is a tuple of long integers
                        # and value is an integer,
                        # some of the integer values inside the key tuple might be None
                        data = data.replace(b"L", b"")
                    xrefs = eval(data)  # pylint: disable=eval-used
                    log.debug("Loaded %d xrefs", len(xrefs))
                    return xrefs
            except:  # pylint: disable=bare-except
                log.error("Failed to load xrefs from netnode")
                traceback.print_exc()
            return {}

        def save(self):
            try:
                buf = repr(self.xrefs).encode() if IS_PYTHON3 else repr(self.xrefs)
                self.node.setblob_ea(buf, self.cfunc.entry_ea, NETNODE_TAG)
            except:  # pylint: disable=bare-except
                log.error("Failed to save xrefs to netnode")
                traceback.print_exc()

        def clear_struct_xrefs(self):
            if not self.node.create(NETNODE_NAME):
                xrefs = self.load()
                for (ea, struct_id, member_id) in xrefs.keys():
                    if member_id is None:
                        idaapi.del_dref(ea, struct_id)
                    else:
                        idaapi.del_dref(ea, member_id)
                self.xrefs = {}
                self.save()
                log.debug("Cleared %d xrefs", len(xrefs))

        def find_addr(self, e):
            if e.ea != idaapi.BADADDR:
                ea = e.ea
            else:
                while True:
                    e = self.cfunc.body.find_parent_of(e)
                    if e is None:
                        ea = self.cfunc.entry_ea
                        break
                    if e.ea != idaapi.BADADDR:
                        ea = e.ea
                        break
            return ea

        def add_dref(self, ea, struct_id, flags, member_id=None):
            if (ea, struct_id, member_id) not in self.xrefs or flags < self.xrefs[
                (ea, struct_id, member_id)
            ]:
                self.xrefs[(ea, struct_id, member_id)] = flags
                strname = idaapi.get_struc_name(struct_id)
                if member_id is None:
                    idaapi.add_dref(ea, struct_id, flags)
                    log.debug(" %X \tstruct %s \t%s", ea, strname, flags_to_str(flags))
                else:
                    idaapi.add_dref(ea, member_id, flags)
                    log.debug(
                        " %X \tmember %s.%s \t%s",
                        ea,
                        strname,
                        idaapi.get_member_name(member_id),
                        flags_to_str(flags),
                    )
            self.save()

        def visit_expr(self, *args):
            e = args[0]
            dr = idaapi.dr_R | idaapi.XREF_USER
            ea = self.find_addr(e)

            # We wish to know what context a struct usage occurs in
            # so we can determine what kind of xref to create. Unfortunately,
            # a post-order traversal makes this difficult.

            # For assignments, we visit the left, instead
            # Note that immediate lvalues will be visited twice,
            # and will be eronneously marked with a read dref.
            # However, it is safer to overapproximate than underapproximate
            if is_assn(e.op) or is_incdec(e.op):
                e = e.x
                dr = idaapi.dr_W | idaapi.XREF_USER

            # &x
            if e.op == idaapi.cot_ref:
                e = e.x
                dr = idaapi.dr_O | idaapi.XREF_USER

            # x.m, x->m
            if e.op == idaapi.cot_memref or e.op == idaapi.cot_memptr:
                moff = e.m

                # The only way I could figure out how
                # to get the structure/member associated with its use
                typ = e.x.type

                if e.op == idaapi.cot_memptr:
                    typ.remove_ptr_or_array()

                strname = typ.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct ") :]

                stid = idaapi.get_struc_id(strname)
                struc = idaapi.get_struc(stid)
                mem = idaapi.get_member(struc, moff)

                if struc is not None:
                    self.add_dref(ea, stid, dr)
                    if mem is not None:
                        self.add_dref(ea, stid, dr, mem.id)

                else:
                    log.error(
                        "failure from %X " "on struct %s (id: %d) %s",
                        ea,
                        strname,
                        stid,
                        flags_to_str(dr),
                    )

            elif idaapi.is_lvalue(e.op) and e.type.is_struct():
                strname = e.type.dstr()
                if strname.startswith("struct "):
                    strname = strname[len("struct ") :]

                stid = idaapi.get_struc_id(strname)
                struc = idaapi.get_struc(stid)

                if struc is not None:
                    self.add_dref(ea, stid, dr)

            return 0

    adder = xref_adder_t(cfunc)
    adder.apply_to_exprs(cfunc.body, None)


def callback(*args):
    if args[0] == idaapi.hxe_maturity:
        cfunc = args[1]
        mat = args[2]
        if mat == idaapi.CMAT_FINAL:
            log.debug("analyzing function at %X", cfunc.entry_ea)
            add_struct_xrefs(cfunc)
    return 0


class Referee(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Adds struct xref info from decompilation"
    help = ""

    wanted_name = "Referee"
    wanted_hotkey = ""

    def __init__(self):
        self.inited = False

    def init(self):
        if not idaapi.init_hexrays_plugin():
            log.error("Decompiler is not ready")
            return idaapi.PLUGIN_SKIP

        if not idaapi.install_hexrays_callback(callback):
            log.error("Failed to install hexrays callback")
            return idaapi.PLUGIN_SKIP

        log.info(
            "Hex-Rays version %s has been detected; %s is ready to use",
            idaapi.get_hexrays_version(),
            self.wanted_name,
        )

        self.inited = True
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # never called
        pass

    def term(self):
        if self.inited:
            if not idaapi.remove_hexrays_callback(callback):
                log.warn("Failed to remove hexrays callback")
            idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return Referee()


def flags_to_str(num):
    match = []
    if num & idaapi.dr_R == idaapi.dr_R:
        match.append("dr_R")
        num ^= idaapi.dr_R
    if num & idaapi.dr_O == idaapi.dr_O:
        match.append("dr_O")
        num ^= idaapi.dr_O
    if num & idaapi.dr_W == idaapi.dr_W:
        match.append("dr_W")
        num ^= idaapi.dr_W
    if num & idaapi.dr_I == idaapi.dr_I:
        match.append("dr_I")
        num ^= idaapi.dr_I
    if num & idaapi.dr_T == idaapi.dr_T:
        match.append("dr_T")
        num ^= idaapi.dr_T
    if num & idaapi.XREF_USER == idaapi.XREF_USER:
        match.append("XREF_USER")
        num ^= idaapi.XREF_USER
    if num & idaapi.XREF_DATA == idaapi.XREF_DATA:
        match.append("XREF_DATA")
        num ^= idaapi.XREF_DATA
    res = " | ".join(match)
    if num:
        res += " unknown flags: 0x%08X" % num
    return res


def clear_output_window():
    idaapi.process_ui_action("msglist:Clear")
