set_project("asteria")
set_version("1.0.0")
set_languages("cxx23")

add_rules("mode.debug", "mode.release")

add_rules("plugin.compile_commands.autoupdate", { outputdir = "." })

set_targetdir("bin/$(mode)")

target("injector")
set_kind("binary")
add_files("/**.cpp")
