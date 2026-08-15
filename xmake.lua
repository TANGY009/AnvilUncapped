set_project("AnvilUncapped")
set_version("1.1.1")

add_rules("mode.release")
add_repositories("xmake-repo https://github.com/xmake-io/xmake-repo.git")

target("AnvilUncapped")
    set_kind("shared")
    add_files("src/*.cpp")
    add_includedirs("src")

    if is_plat("windows") then
        set_languages("c++20")
        set_symbols("debug")
        set_policy("build.optimization.lto", true)
        
        add_defines("WIN32_LEAN_AND_MEAN")
        add_syslinks("kernel32", "user32")
        
        add_cxflags("/Os", "/GF", "/Gy", "/Gw", "/w")
        add_ldflags("/OPT:REF", "/OPT:ICF")
        
        set_targetdir("build/windows/x86_64/release")

    elseif is_plat("android") then
        set_languages("cxx23")
        
        add_cxflags("-O2", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections", "-flto", "-w")
        add_ldflags("-Wl,--gc-sections", "-Wl,--strip-all")
        
        add_syslinks("log")
    end