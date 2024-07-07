add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

if xmake.version():satisfies(">=2.5.7 <=2.5.9") then
    on_load(function (target)
        raise("xmake(%s) has a bug preventing BPF source code compilation. Please run `xmake update -f 2.5.6` to revert to v2.5.6 version or upgrade to xmake v2.6.1 that fixed the issue.", xmake.version())
    end)
end

option("system-libbpf",      {showmenu = true, default = false, description = "Use system-installed libbpf"})
option("require-bpftool",    {showmenu = true, default = false, description = "Require bpftool package"})

add_requires("elfutils", "zlib")
if is_plat("android") then
    add_requires("ndk >=22.x <26", "argp-standalone")
    set_toolchains("@ndk", {sdkver = "23"})
else
    add_requires("llvm >=10.x")
    set_toolchains("@llvm")
    add_requires("linux-headers")
end

-- fix error: libbpf: map 'my_pid_map': unsupported map linkage static. for bpftool >= 7.2.0
-- we cannot add `"-fvisibility=hidden"` when compiling *.bpf.c
set_symbols("none")

if is_arch("arm64", "arm64-v8a") then
    add_includedirs("../vmlinux/arm64")
elseif is_arch("arm.*") then
    add_includedirs("../vmlinux/arm")
elseif is_arch("riscv32", "riscv64") then
    add_includedirs("../vmlinux/riscv")
elseif is_arch("loongarch") then
    add_includedirs("../vmlinux/loongarch")
elseif is_arch("ppc", "powerpc") then
    add_includedirs("../vmlinux/powerpc")
elseif is_arch("x86_64", "i386") then
    add_includedirs("../vmlinux/x86")
else
    add_includedirs("../vmlinux")
end

-- we can run `xmake f --require-bpftool=y` to pull bpftool from xmake-repo repository
if has_config("require-bpftool") then
    add_requires("linux-tools", {configs = {bpftool = true}})
    add_packages("linux-tools")
else
    before_build(function (target)
        os.addenv("PATH", path.join(os.scriptdir(), "..", "..", "tools"))
    end)
end

-- we use the vendored libbpf sources for libbpf-bootstrap.
-- for some projects you may want to use the system-installed libbpf, so you can run `xmake f --system-libbpf=y`
if has_config("system-libbpf") then
    add_requires("libbpf", {system = true})
else
    target("libbpf")
        set_kind("static")
        set_basename("bpf")
        add_files("../libbpf/src/*.c")
        add_includedirs("../libbpf/include")
        add_includedirs("../libbpf/include/uapi", {public = true})
        add_includedirs("$(buildir)", {interface = true})
        add_configfiles("../libbpf/src/(*.h)", {prefixdir = "bpf"})
        add_packages("elfutils", "zlib")
        if is_plat("android") then
            add_defines("__user=", "__force=", "__poll_t=uint32_t")
        end
end

target("bpfdos")
    set_kind("binary")
    add_files("bpfdos.c", "bpfdos.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("exechijack")
    set_kind("binary")
    add_files("exechijack.c", "exechijack.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end
    
target("pidhide")
    set_kind("binary")
    add_files("pidhide.c", "pidhide.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("sudoadd")
    set_kind("binary")
    add_files("sudoadd.c", "sudoadd.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("textreplace")
    set_kind("binary")
    add_files("textreplace.c", "textreplace.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("textreplace2")
    set_kind("binary")
    add_files("textreplace2.c", "textreplace2.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("writeblocker")
    set_kind("binary")
    add_files("writeblocker.c", "writeblocker.bpf.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end

target("hijackee")
    set_kind("binary")
    add_files("hijackee.c")
    end
