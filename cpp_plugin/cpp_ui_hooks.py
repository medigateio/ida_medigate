import logging
import ida_kernwin
import ida_name
import ida_struct
import idc
from idc import BADADDR
from .. import cpp_utils, utils

log = logging.getLogger("ida_medigate")


class CPPUIHooks(ida_kernwin.View_Hooks):
    def view_dblclick(self, viewer, point):
        widget_type = ida_kernwin.get_widget_type(viewer)
        if not (widget_type == 48 or widget_type == 28):
            return
        # Decompiler or Structures window
        func_cand_name = None
        place, x, y = ida_kernwin.get_custom_viewer_place(viewer, False)
        if place.name() == "structplace_t":  # Structure window:
            structplace = ida_kernwin.place_t_as_structplace_t(place)
            if structplace is not None:
                s = ida_struct.get_struc(ida_struct.get_struc_by_idx(structplace.idx))
                if s:
                    member = ida_struct.get_member(s, structplace.offset)
                    if member:
                        func_cand_name = ida_struct.get_member_name(member.id)
        if func_cand_name is None:
            line = utils.get_curline_striped_from_viewer(viewer)
            func_cand_name = cpp_utils.find_valid_cppname_in_line(line, x)
        if func_cand_name is not None:
            func_cand_ea = ida_name.get_name_ea(BADADDR, func_cand_name)
            if func_cand_ea is not None and utils.is_func_start(func_cand_ea):
                idc.jumpto(func_cand_ea)
