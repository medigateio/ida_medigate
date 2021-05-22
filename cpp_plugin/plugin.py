import logging

import ida_idaapi
import ida_kernwin
import idaapi
from .hooks import CPPHooks, CPPUIHooks, HexRaysHooks

log = logging.getLogger("ida_medigate.plugin")


class CPPPlugin(ida_idaapi.plugin_t):
    """
    This is the main class of the plugin. It subclasses plugin_t as required
    by IDA. It holds the modules of plugin, which themselves provides the
    functionality of the plugin (hooking/events, interface, networking, etc.).
    """

    # Mandatory definitions
    PLUGIN_NAME = "ida_cpp"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "Medigate"
    TOGGLE_HOTKEY = "CTRL+ALT+C"

    # These flags specify that the plugin should persist between databases
    # loading and saving, and should not have a menu entry.
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = "CPP support plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        log.info("Im up")
        self.core_hook = None
        self.gui_hook = None
        self.hexrays_hooks = None
        self.hooking = False
        self.is_decompiler_on = False

    def init(self):
        """
        This method is called when IDA is loading the plugin. It will first
        load the configuration file, then initialize all the modules.
        """
        if idaapi.init_hexrays_plugin():
            self.hexrays_hooks = HexRaysHooks()
            self.is_decompiler_on = True
        self.core_hook = CPPHooks(self.is_decompiler_on)
        self.gui_hook = CPPUIHooks()
        if not self.hook():
            log.warn("Failed to set hooks")
            return idaapi.PLUGIN_SKIP
        if not self.install_hotkey():
            log.warn("Failed to add hotkey")
        return idaapi.PLUGIN_KEEP

    def toggle_hooks(self):
        if self.hooking:
            self.unhook()
        else:
            self.hook()
        log.info("C++ plugin is now: %s" % ("On" if self.hooking else "Off"))

    def hook(self):
        if self.hexrays_hooks:
            if not self.hexrays_hooks.hook():
                log.warn("Failed to set decompiler hooks")
        if not self.core_hook.hook():
            log.warn("Failed to set core hooks")
        if not self.gui_hook.hook():
            log.warn("Failed to set gui hooks")
        log.info("hooks installed")
        self.hooking = True

    def unhook(self):
        if self.hexrays_hooks:
            if not self.hexrays_hooks.unhook():
                log.warn("Failed to unhook decompiler hooks")
        if not self.core_hook.unhook():
            log.warn("Failed to unhook core hooks")
        if not self.gui_hook.unhook():
            log.warn("Failed to unhook gui hooks")
        log.info("hooks uninstalled")
        self.hooking = False

    def install_hotkey(self):
        return ida_kernwin.add_hotkey(self.TOGGLE_HOTKEY, self.toggle_hooks)

    @classmethod
    def description(cls):
        """Return the description displayed in the console."""
        return "%s v%s".format(cls.PLUGIN_NAME, cls.PLUGIN_VERSION)

    def run(self, _):
        """
        This method is called when IDA is running the plugin as a script.
        """
        ida_kernwin.warning("ida_medigate C++ plugin cannot be run as a script")
        return False

    def term(self):
        """
        This method is called when IDA is unloading the plugin. It will
        terminated all the modules, then save the configuration file.
        """
        log.debug("terminating")
        self.unhook()
        idaapi.term_hexrays_plugin()
