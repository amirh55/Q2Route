//! Links the vendored WinDivert import library and copies `WinDivert.dll`
//! and `WinDivert64.sys` next to the built executables (and into `deps/`
//! so integration-test binaries can load the DLL).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const RUNTIME_FILES: &[&str] = &["WinDivert.dll", "WinDivert64.sys"];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest_dir.join("../../vendor/windivert");
    let vendor = vendor.canonicalize().unwrap_or(vendor);

    for f in ["WinDivert.lib", "WinDivert.dll", "WinDivert64.sys"] {
        println!("cargo:rerun-if-changed={}", vendor.join(f).display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rustc-link-search=native={}", vendor.display());
    println!("cargo:rustc-link-lib=dylib=WinDivert");

    // OUT_DIR = target/<profile>/build/<pkg>-<hash>/out
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("unexpected OUT_DIR layout")
        .to_path_buf();

    for dest in [profile_dir.clone(), profile_dir.join("deps")] {
        fs::create_dir_all(&dest).unwrap();
        for f in RUNTIME_FILES {
            copy_if_changed(&vendor.join(f), &dest.join(f));
        }
    }
}

fn copy_if_changed(src: &Path, dst: &Path) {
    let same = match (fs::metadata(src), fs::metadata(dst)) {
        (Ok(s), Ok(d)) => s.len() == d.len() && s.modified().ok() <= d.modified().ok(),
        _ => false,
    };
    if !same {
        // A running exe may hold the DLL open; that copy is then already current.
        if let Err(e) = fs::copy(src, dst) {
            if !dst.exists() {
                panic!("copy {} -> {}: {e}", src.display(), dst.display());
            }
        }
    }
}
