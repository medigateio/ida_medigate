import logging

import ida_idaapi
import ida_kernwin
import idaapi
from .cpp_hooks import CPPHooks
from .cpp_ui_hooks import CPPUIHooks
from .hexrays_hooks import (
    install_hexrays_hooks,
    remove_hexrays_hooks,
)

log = logging.getLogger("ida_medigate")


class CPPPlugin(ida_idaapi.plugin_t):
    """
    This is the main class of the plugin. It subclasses plugin_t as required
    by IDA. It holds the modules of plugin, which themselves provides the
    functionality of the plugin (hooking/events, interface, networking, etc.).
    """

    # Mandatory definitions
    PLUGIN_NAME = "ida_medigate"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "Medigate"
    TOGGLE_HOTKEY = "CTRL+ALT+SHIFT-M"

    # These flags specify that the plugin should not have a menu entry
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "CPP support plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        self.cpp_hooks = None
        self.gui_hooks = None
        self.hooking = False
        self.is_decompiler_on = False

    def init(self):
        """
        This method is called when IDA is loading the plugin. It will first
        load the configuration file, then initialize all the modules.
        """
        if idaapi.init_hexrays_plugin():
            self.is_decompiler_on = True
        else:
            log.warn("Hex-Rays decompiler is not available")

        self.cpp_hooks = CPPHooks()
        self.gui_hooks = CPPUIHooks()

        if not self.hook():
            log.warn("Failed to set hooks")
            return idaapi.PLUGIN_SKIP

        self.install_hotkey()

        log.info("Im up")

        return idaapi.PLUGIN_KEEP

    def toggle_hooks(self):
        if self.hooking:
            self.unhook()
        else:
            self.hook()
        log.info("C++ plugin is now: %s" % ("On" if self.hooking else "Off"))

    def hook(self):
        if self.is_decompiler_on:
            if not install_hexrays_hooks():
                log.warn("Failed to install decompiler hooks")
        if not self.cpp_hooks.hook():
            log.warn("Failed to install core hooks")
        if not self.gui_hooks.hook():
            log.warn("Failed to install gui hooks")
        self.hooking = True
        return True

    def unhook(self):
        if self.is_decompiler_on:
            if not remove_hexrays_hooks():
                log.warn("Failed to remove decompiler hooks")
        if not self.cpp_hooks.unhook():
            log.warn("Failed to remove core hooks")
        if not self.gui_hooks.unhook():
            log.warn("Failed to remove gui hooks")
        self.hooking = False
        return True

    def install_hotkey(self):
        if not ida_kernwin.add_hotkey(self.TOGGLE_HOTKEY, self.toggle_hooks):
            log.warn("Failed to add hotkey %s", self.TOGGLE_HOTKEY)
            return False
        return True

    @classmethod
    def description(cls):
        """Return the description displayed in the console."""
        return "%s v%s" % (cls.PLUGIN_NAME, cls.PLUGIN_VERSION)

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
        self.unhook()
        idaapi.term_hexrays_plugin()
