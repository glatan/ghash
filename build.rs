use std::env;
use std::process::Command;
use std::str;
use std::str::FromStr;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc_version = get_rustc_version();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();

    // Version: 1.43(MSRV) ~ 1.47
    // Target : aarch64-unknown-linux-musl
    if rustc_version.0 == 1
        && rustc_version.1 < 48
        && is_aarch64_unknown_linux_musl(
            &target_arch,
            &target_vendor,
            &target_os,
            &target_env,
            &target_endian,
        )
    {
        // let gcc_libdir = get_gcc_library_path("mips64-linux-gnuabi64-gcc");
        // println!("cargo:rustc-link-search=native={}", gcc_libdir);
        // println!("cargo:rustc-link-lib=static=gcc");
        println!("cargo:rustc-flags=-lgcc");
    }
    // Version: 1.43(MSRV) ~ 1.46
    // Target : mips-unknown-linux-musl
    if rustc_version.0 == 1
        && rustc_version.1 < 47
        && is_mips_unknown_linux_musl(
            &target_arch,
            &target_vendor,
            &target_os,
            &target_env,
            &target_endian,
        )
    {
        // let gcc_libdir = get_gcc_library_path("mips64-linux-gnuabi64-gcc");
        // println!("cargo:rustc-link-search=native={}", gcc_libdir);
        // println!("cargo:rustc-link-lib=static=gcc");
        println!("cargo:rustc-flags=-lgcc");
    }
    // Version: 1.43(MSRV) ~ 1.47
    // Target : mips64-unknown-linux-muslabi64
    if rustc_version.0 == 1
        && rustc_version.1 < 48
        && is_mips64_unknown_linux_muslabi64(
            &target_arch,
            &target_vendor,
            &target_os,
            &target_env,
            &target_endian,
        )
    {
        // let gcc_libdir = get_gcc_library_path("mips64-linux-gnuabi64-gcc");
        // println!("cargo:rustc-link-search=native={}", gcc_libdir);
        // println!("cargo:rustc-link-lib=static=gcc");
        println!("cargo:rustc-flags=-lgcc");
    }
    // Version: 1.43(MSRV) ~ 1.47
    // Target : mips64el-unknown-linux-muslabi64
    if rustc_version.0 == 1
        && rustc_version.1 < 48
        && is_mips64el_unknown_linux_muslabi64(
            &target_arch,
            &target_vendor,
            &target_os,
            &target_env,
            &target_endian,
        )
    {
        // let gcc_libdir = get_gcc_library_path("mips64el-linux-gnuabi64-gcc");
        // println!("cargo:rustc-link-search=native={}", gcc_libdir);
        // println!("cargo:rustc-link-lib=static=gcc");
        println!("cargo:rustc-flags=-lgcc");
    }
}

fn get_rustc_version() -> (u32, u32, u32) {
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .unwrap();
    let version_str = str::from_utf8(&output.stdout)
        .unwrap()
        .split(" ")
        .collect::<Vec<&str>>()[1];
    let splitted_version = version_str.split(".").collect::<Vec<&str>>();
    let major_version = u32::from_str(splitted_version[0]).ok().unwrap();
    let minor_version = u32::from_str(splitted_version[1]).ok().unwrap();
    let patch_version = u32::from_str(splitted_version[2]).ok().unwrap();
    (major_version, minor_version, patch_version)
}

// fn get_gcc_library_path(cmd: &str) -> String {
//     let output = Command::new(cmd)
//         .arg("-print-search-dirs")
//         .output()
//         .ok()
//         .unwrap();

//     // install: PATH <- get this
//     // programs: PATH
//     // libraries: PATH
//     let install_path = str::from_utf8(&output.stdout)
//         .unwrap()
//         .split("\n")
//         .collect::<Vec<&str>>()[0];
//     let path = install_path.trim_start_matches("install: ");
//     path.to_owned()
// }

fn is_aarch64_unknown_linux_musl(
    target_arch: &str,
    target_vendor: &str,
    target_os: &str,
    target_env: &str,
    target_endian: &str,
) -> bool {
    if target_arch == "aarch64"
        && target_vendor == "unknown"
        && target_os == "linux"
        && target_env == "musl"
        && target_endian == "little"
    {
        return true;
    }
    false
}

fn is_mips_unknown_linux_musl(
    target_arch: &str,
    target_vendor: &str,
    target_os: &str,
    target_env: &str,
    target_endian: &str,
) -> bool {
    if target_arch == "mips"
        && target_vendor == "unknown"
        && target_os == "linux"
        && target_env == "musl"
        && target_endian == "big"
    {
        return true;
    }
    false
}

fn is_mips64_unknown_linux_muslabi64(
    target_arch: &str,
    target_vendor: &str,
    target_os: &str,
    target_env: &str,
    target_endian: &str,
) -> bool {
    if target_arch == "mips64"
        && target_vendor == "unknown"
        && target_os == "linux"
        && target_env == "musl"
        && target_endian == "big"
    {
        return true;
    }
    false
}

fn is_mips64el_unknown_linux_muslabi64(
    target_arch: &str,
    target_vendor: &str,
    target_os: &str,
    target_env: &str,
    target_endian: &str,
) -> bool {
    if target_arch == "mips64"
        && target_vendor == "unknown"
        && target_os == "linux"
        && target_env == "musl"
        && target_endian == "little"
    {
        return true;
    }
    false
}
