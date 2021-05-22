import logging
import ida_frame
import ida_funcs
import ida_idp
import ida_struct
from idc import BADADDR
from .. import cpp_utils, utils

log = logging.getLogger("ida_medigate")


class CPPHooks(ida_idp.IDB_Hooks):
    def __init__(self, is_decompiler_on):
        super(CPPHooks, self).__init__()
        self.is_decompiler_on = is_decompiler_on

    def renamed(self, ea, new_name, local_name):
        if utils.is_func_start(ea):
            func, args_list = cpp_utils.post_func_name_change(new_name, ea)
            self.unhook()
            for args in args_list:
                func(*args)
            self.hook()
        return 0

    def func_updated(self, pfn):
        func, args_list = cpp_utils.post_func_type_change(pfn)
        self.unhook()
        for args in args_list:
            func(*args)
        self.hook()
        return 0

    def renaming_struc_member(self, sptr, mptr, newname):
        if sptr.is_frame():
            return 0
        cpp_utils.post_struct_member_name_change(mptr, newname)
        return 0

    def struc_member_changed(self, sptr, mptr):
        cpp_utils.post_struct_member_type_change(mptr)
        return 0

    def ti_changed(self, ea, typeinf, fnames):
        if self.is_decompiler_on:
            res = ida_struct.get_member_by_id(ea)
            if res is not None:
                m, name, sptr = res
                if sptr.is_frame():
                    func = ida_funcs.get_func(ida_frame.get_func_by_frame(sptr.id))
                    if func is not None:
                        return self.func_updated(func)
            elif utils.is_func_start(ea):
                return self.func_updated(ida_funcs.get_func(ea))
        return 0