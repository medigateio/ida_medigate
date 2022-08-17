from ida_medigate import cpp_utils
import ida_ida
import idaapi
import ida_kernwin
import collections

class medigate_cpp_gui_plugin_helps:
    # Menu
    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])

    class IdaMenuActionHandler(idaapi.action_handler_t):
        def __init__(self, handler, action):
            idaapi.action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action
    
        def activate(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                self.action_handler.handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


class make_virtual_table_form(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""Medigate plugin 
Make Virtual Table
<## ClassName\::{ClassName}>
<## VtableEA\::{VtableEa}>
<## VtableEAStop\::{VtableEaStop}>
<## OffsetInClass\::{Offset}>
""",
{
    'ClassName'     : F.StringInput(swidth=20,  tp=F.FT_ASCII),
    'VtableEa'      : F.NumericInput(swidth=20, tp=F.FT_HEX),
    'VtableEaStop'  : F.NumericInput(swidth=20, tp=F.FT_HEX),
    'Offset'        : F.NumericInput(swidth=20, tp=F.FT_HEX),
}
        )

##add_baseclass(class_name, baseclass_name, baseclass_offset=0, to_refresh=False):   
class add_base_class_form(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""Medigate plugin
Add Base Class
<## ClassName\::{ClassName}>
<## BaseClassname\::{BaseClassName}>
<## BaseClassOffset\::{BaseClassOffset}>
<## Refresh\::{Refresh}>
""",
{
    'ClassName' : F.StringInput(swidth=20,  tp=F.FT_ASCII),
    'BaseClassName' : F.StringInput(swidth=20, tp=F.FT_ASCII),
    'BaseClassOffset': F.NumericInput(swidth=20, tp=F.FT_UINT64),
    'Refresh' : F.NumericInput(swidth=20, tp=F.FT_UINT64)
}
        )


class medigate_cpp_gui_plugin_t(idaapi.plugin_t, idaapi.UI_Hooks):

    popup_menu_hook = None
    flags = idaapi.PLUGIN_KEEP
    comment = 'Medigate plugin for c++ reverse engineering and other utils'
    wanted_hotkey = 'Ctrl-Alt-M'
    plugin_name = 'Medigate Gui'
    wanted_name = 'Medigate Gui'

    def __init__(self, name = 'medigate gui' ):
        super(medigate_cpp_gui_plugin_t, self).__init__()

        self.plugin_name = name
        self.wanted_name = name
        self.run()
    
    def init(self, name = 'medigate gui'):
        self.hook_ui_actions()

        return idaapi.PLUGIN_KEEP

    def run(self, args=0):
        self.register_menu_actions()
        self.attach_main_menu_actions()

    def term(self):
        self.unhook_ui_actions()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        
    def unload_plugin(self):
        self.detach_main_menu_actions()
        self.unregister_menu_actions

    MENU_ITEMS = []
    def register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        new_action = idaapi.action_desc_t(
            act_name,       # The action name. This acts like an ID and must be unique
            act_text,       # The action text.
            act_handler,    # The action handler.
            shortcut,       # Optional: the action shortcut
            tooltip,        # Optional: the action tooltip (available in menus/toolbar)
            icon)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(new_action)
    
    def handle_menu_action(self, action):
        [x.handler() for x in self.MENU_ITEMS if x.action == action]
  
    def register_menu_actions(self):
        # TODO 

        self.MENU_ITEMS.append(medigate_cpp_gui_plugin_helps.MenuItem(self.plugin_name + ":make_table",             self.make_table,             "make_table",             "make a virtual table ",           None,                   True    ))
        self.MENU_ITEMS.append(medigate_cpp_gui_plugin_helps.MenuItem(self.plugin_name + ":add_base_class",            self.add_base_class,            "add_base_class",            "add base class",           None,                   True    ))
        self.MENU_ITEMS.append(medigate_cpp_gui_plugin_helps.MenuItem(self.plugin_name + ":rebuilding_all_class",            self.rebuilding_all_class,            "rebuilding_all_class",            "rebuilding all class",           None,                   True    ))

        self.add_custom_menu()
        for item in self.MENU_ITEMS:
            if item.action == '-':
                continue
            self.register_new_action(item.action, item.title, medigate_cpp_gui_plugin_helps.IdaMenuActionHandler(self, item.action), item.shortcut, item.tooltip, -1)        

    def unregister_menu_actions(self):
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            idaapi.unregister_action(item.action)

    def attach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            idaapi.attach_action_to_menu("Edit/" + self.plugin_name + "/" + item.title, item.action, idaapi.SETMENU_APP)

    def detach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            idaapi.detach_action_from_menu("Edit/" + self.plugin_name + "/" + item.title, item.action)

    def add_custom_menu(self): # used by extensions
        pass

    def hook_ui_actions(self):
        self.popup_menu_hook = self
        self.popup_menu_hook.hook()

    def unhook_ui_actions(self):
        if self.popup_menu_hook != None:
            self.popup_menu_hook.unhook()

    # IDA 7.x
    def finish_populating_widget_popup(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) == idaapi.BWN_DISASM:
            for item in self.MENU_ITEMS:
                if item.popup:
                    idaapi.attach_action_to_popup(widget, popup_handle, item.action, self.plugin_name + "/")
    
    def make_table(self, ClassName='B', VtableEa=0, VtableEaStop=0, Offset=0):
        f = make_virtual_table_form()
        f.Compile()
        """
        'ClassName'     : F.StringInput(swidth=20,  tp=F.FT_ASCII),
        'VtableEa'      : F.NumericInput(swidth=20, tp=F.FT_HEX),
        'VtableEaStop'  : F.NumericInput(swidth=20, tp=F.FT_HEX),
        'Offset'        : F.NumericInput(swidth=20, tp=F.FT_HEX),
        """
        f.ClassName.value = ClassName
        f.VtableEa.value = VtableEa
        f.VtableEaStop.value = VtableEaStop
        f.Offset.value = Offset

        ok = f.Execute()
        if ok == 1:
 # def make_vtable(class_name,vtable_ea=None,vtable_ea_stop=None,offset_in_class=0,parent_name=None,add_func_this=True,_get_vtable_line=get_vtable_line,):
            class_name = f.ClassName.value
            # vtable_ea = f.VtableEa.value
            # vtable_ea_stop =  f.VtableEaStop.value
            if f.VtableEa.value == 0 or f.VtableEaStop.value == 0:
                vtable_ea ,vtable_ea_stop = None, None
            else:
                vtable_ea, vtable_ea_stop = f.VtableEa.value , f.VtableEaStop.value

            offset_in_class = f.Offset.value
            cpp_utils.make_vtable(class_name=class_name, vtable_ea=vtable_ea, vtable_ea_stop=vtable_ea_stop, offset_in_class=offset_in_class)
    
#add_baseclass(class_name, baseclass_name, baseclass_offset=0, to_refresh=False):
    def add_base_class(self, ClassName='C', BaseClassName='B', BaseClassOffset=0, Refresh=0):
        f = add_base_class_form()
        f.Compile()

        f.ClassName.value = ClassName
        f.BaseClassName.value = BaseClassName
        f.BaseClassOffset.value = BaseClassOffset
        f.Refresh.value = Refresh

        ok = f.Execute()
        if ok == 1:
            class_name = f.ClassName.value
            baseclass_name = f.BaseClassName.value
            baseclass_offset = f.BaseClassOffset.value
            if f.Refresh.value == 0:
                to_refresh = False
            else:
                to_refresh = True
            
            cpp_utils.add_baseclass(class_name=class_name, baseclass_name=baseclass_name, baseclass_offset=baseclass_offset, to_refresh=to_refresh)

    def rebuilding_all_class(self, BuildALL=1):

        from ida_medigate.rtti_parser import GccRTTIParser
        GccRTTIParser.init_parser()
        GccRTTIParser.build_all()


def PLUGIN_ENTRY():
    return medigate_cpp_gui_plugin_t()
