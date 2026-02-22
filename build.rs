use std::env;
use std::path::PathBuf;

fn main() {
    // Use pkg-config to locate libssh and emit the correct linker flags.
    let library = pkg_config::probe_library("libssh")
        .expect("libssh not found via pkg-config; install libssh-dev");

    // Collect -I flags so clang can find all transitive headers.
    let clang_args: Vec<String> = library
        .include_paths
        .iter()
        .map(|p| format!("-I{}", p.display()))
        .collect();

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("/usr/include/libssh/libssh.h")
        .clang_args(&clang_args)
        // functions we actually call
        .allowlist_function("ssh_new")
        .allowlist_function("ssh_free")
        .allowlist_function("ssh_disconnect")
        .allowlist_function("ssh_options_set")
        .allowlist_function("ssh_connect")
        .allowlist_function("ssh_get_error")
        // host-key verification
        .allowlist_function("ssh_session_is_known_server")
        .allowlist_function("ssh_session_update_known_hosts")
        .allowlist_function("ssh_get_server_publickey")
        .allowlist_function("ssh_get_publickey_hash")
        .allowlist_function("ssh_clean_pubkey_hash")
        .allowlist_function("ssh_key_free")
        // authentication
        .allowlist_function("ssh_userauth_publickey_auto")
        .allowlist_function("ssh_userauth_password")
        // channel / exec
        .allowlist_function("ssh_channel_new")
        .allowlist_function("ssh_channel_open_session")
        .allowlist_function("ssh_channel_request_exec")
        .allowlist_function("ssh_channel_read")
        .allowlist_function("ssh_channel_read_timeout")
        .allowlist_function("ssh_channel_send_eof")
        .allowlist_function("ssh_channel_close")
        .allowlist_function("ssh_channel_free")
        .allowlist_function("ssh_channel_is_eof")
        .allowlist_function("ssh_channel_is_open")
        .allowlist_function("ssh_channel_get_exit_status")
        // enums we reference by name
        .allowlist_type("ssh_auth_e")
        // (ssh_options_e, ssh_known_hosts_e, ssh_publickey_hash_type are
        //  pulled in transitively as parameter/return types of the functions)
        // codegen options
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate libssh bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings.rs");
}
