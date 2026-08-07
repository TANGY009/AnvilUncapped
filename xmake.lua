set_project("AnvilUncapped")
set_version("1.0.0")

set_languages("cxx23")

add_rules("mode.release")

add_cxflags("-O2", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections", "-flto", "-w")
add_ldflags("-Wl,--gc-sections", "-Wl,--strip-all")

add_repositories(
    "xmake-repo https://github.com/xmake-io/xmake-repo.git"
)

target("AnvilUncapped")
    set_kind("shared")
    add_files("src/main.cpp")
    add_includedirs("src")
    
    add_links("log")