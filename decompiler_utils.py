import logging

import ida_hexrays
import idc
from . import utils
from idaapi import BADADDR


def get_insn(ea=None):
    if ea is None:
        ea = idc.here()
    xfunc = ida_hexrays.decompile(ea)
    return xfunc.get_eamap()[ea][0]


def get_str_from_expr(expr, make_str=True):
    if expr is None:
        return None
    str_addr = get_obj_ea_from_expr(expr)
    if str_addr == BADADDR:
        return None
    ret = idc.get_strlit_contents(str_addr)
    if ret is not None:
        ret = ret.decode()
    return ret


def extract_op_from_expr(expr, op):
    if expr is None:
        return BADADDR
    while expr.is_expr() and expr.op != op:
        expr = expr.x
        if expr is None:
            return BADADDR
    if expr.op == op:
        return expr


def get_obj_ea_from_expr(expr):
    expr = extract_op_from_expr(expr, ida_hexrays.cot_obj)
    if expr is None:
        return BADADDR
    return expr.obj_ea


def get_num_from_expr(expr):
    expr = extract_op_from_expr(expr, ida_hexrays.cot_num)
    if expr is None:
        return None
    return expr.get_const_value()


def get_call_from_insn(insn):
    expr = None
    if type(insn) == ida_hexrays.cinsn_t and insn.op == ida_hexrays.cit_expr:
        expr = insn.cexpr
    elif type(insn) == ida_hexrays.cexpr_t:
        expr = insn
    else:
        return None
    if expr.op != ida_hexrays.cot_call:
        return None
    return expr


def run_operation_on_func_xrefs(func_name, operation, exception_msg=None):
    if exception_msg is None:
        exception_msg = "exception in %s xrefs" % func_name
    ea = utils.get_func_ea_by_name(func_name)
    for xref in utils.get_code_xrefs(ea):
        try:
            insn = get_insn(xref)
            operation(insn, xref)
        except Exception as e:
            logging.exception("0x%x: %s", ea, exception_msg)
