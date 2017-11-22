extern crate gcc;
use std::process::Command;
use std::path::Path;


fn main() {
    // check if `easy-ecc` has been downloaded.
    if !Path::new("dep/easy-ecc/.git").exists() {
        // if not, tell git to initialize submodules.
        let cmd = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status()
            .unwrap();
        // if we got a nonzero exit code, don't continue.
        if !cmd.success() {
            panic!("failed to initialize git submodule: `easy-ecc`")
        }
    }

    // compile `easy-ecc` into a static lib.
    gcc::compile_library("libp256.a",&["dep/easy-ecc/ecc.c"]);
}
