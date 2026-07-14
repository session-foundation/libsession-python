def Settings(**kwargs):
    import sysconfig

    includes = (f"-I{p}" for p in sysconfig.get_config_vars("INCLUDEPY"))

    return {
        "flags": ["-x", "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", *includes]
    }
