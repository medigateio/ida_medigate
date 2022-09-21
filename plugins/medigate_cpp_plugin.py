try:
    from ida_medigate.cpp_plugin.plugin import CPPPlugin

    def PLUGIN_ENTRY():
        return CPPPlugin()


except ImportError:
    print(
        "[WARN] Couldn't load ida_medigate_cpp plugin. ida_medigate Python package doesn't seem "
        "to be installed"
    )
