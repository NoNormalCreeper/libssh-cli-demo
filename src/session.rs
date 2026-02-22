use std::ffi::{CStr, CString};
use std::io::{self, BufRead, Write};
use std::os::raw::{c_uchar, c_void};

use anyhow::{anyhow, bail, Context};

use crate::ffi;

// Rename bindgen-generated "TypeName_VARIANT" constants to short names
#[rustfmt::skip]
use crate::ffi::{
    ssh_options_e_SSH_OPTIONS_HOST          as SSH_OPTIONS_HOST,
    ssh_options_e_SSH_OPTIONS_USER          as SSH_OPTIONS_USER,
    ssh_options_e_SSH_OPTIONS_PORT          as SSH_OPTIONS_PORT,
    ssh_options_e_SSH_OPTIONS_IDENTITY      as SSH_OPTIONS_IDENTITY,
    ssh_known_hosts_e_SSH_KNOWN_HOSTS_OK        as SSH_KNOWN_HOSTS_OK,
    ssh_known_hosts_e_SSH_KNOWN_HOSTS_UNKNOWN   as SSH_KNOWN_HOSTS_UNKNOWN,
    ssh_known_hosts_e_SSH_KNOWN_HOSTS_NOT_FOUND as SSH_KNOWN_HOSTS_NOT_FOUND,
    ssh_known_hosts_e_SSH_KNOWN_HOSTS_CHANGED   as SSH_KNOWN_HOSTS_CHANGED,
    ssh_known_hosts_e_SSH_KNOWN_HOSTS_OTHER     as SSH_KNOWN_HOSTS_OTHER,
    ssh_publickey_hash_type_SSH_PUBLICKEY_HASH_SHA256 as SSH_PUBLICKEY_HASH_SHA256,
    ssh_auth_e_SSH_AUTH_SUCCESS as SSH_AUTH_SUCCESS,
    ssh_auth_e_SSH_AUTH_ERROR   as SSH_AUTH_ERROR,
};

// libssh integer return codes (plain #defines, not in an enum).
const SSH_OK: i32 = 0;

// Helpers

/// Return the last error string attached to a session.
fn last_error(session: ffi::ssh_session) -> String {
    let ptr = unsafe { ffi::ssh_get_error(session as *mut c_void) };
    if ptr.is_null() {
        "unknown SSH error".into()
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}

// RAII session

/// Owns a libssh `ssh_session`; disconnects and frees it on drop.
pub struct SshSession {
    inner: ffi::ssh_session,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        unsafe {
            ffi::ssh_disconnect(self.inner);
            ffi::ssh_free(self.inner);
        }
    }
}

impl SshSession {
    /// Allocate a session, apply options, and open the TCP connection.
    pub fn connect(
        host: &str,
        port: u16,
        user: &str,
        identity: Option<&str>,
    ) -> anyhow::Result<Self> {
        let session = unsafe { ffi::ssh_new() };
        if session.is_null() {
            bail!("ssh_new() returned NULL – out of memory?");
        }

        let sess = Self { inner: session };

        // Closure for setting string-valued options.
        let set_str = |opt: ffi::ssh_options_e, val: &str| -> anyhow::Result<()> {
            let c = CString::new(val).context("option string contains a NUL byte")?;
            let rc = unsafe {
                ffi::ssh_options_set(sess.inner, opt, c.as_ptr() as *const c_void)
            };
            if rc != SSH_OK {
                bail!("ssh_options_set failed (option id {opt})");
            }
            Ok(())
        };

        set_str(SSH_OPTIONS_HOST, host)?;
        set_str(SSH_OPTIONS_USER, user)?;

        // PORT expects a *const unsigned int.
        let port_u32: u32 = port.into();
        let rc = unsafe {
            ffi::ssh_options_set(
                sess.inner,
                SSH_OPTIONS_PORT,
                &raw const port_u32 as *const c_void,
            )
        };
        if rc != SSH_OK {
            bail!("ssh_options_set(SSH_OPTIONS_PORT) failed");
        }

        if let Some(id) = identity {
            set_str(SSH_OPTIONS_IDENTITY, id)?;
        }

        // Open the TCP connection.
        let rc = unsafe { ffi::ssh_connect(sess.inner) };
        if rc != SSH_OK {
            let msg = last_error(sess.inner);
            bail!("Connection to {host}:{port} failed: {msg}");
        }

        Ok(sess)
    }

    // Host-key verification

    /// Verify the server's host key against `~/.ssh/known_hosts`.
    ///
    /// * **Known OK** – silent pass.  
    /// * **Unknown / first time** – print SHA-256 fingerprint, ask yes/no,
    ///   update known_hosts on confirmation.  
    /// * **Changed** – hard abort (possible MITM).
    pub fn verify_host(&self) -> anyhow::Result<()> {
        let state = unsafe { ffi::ssh_session_is_known_server(self.inner) };

        match state {
            SSH_KNOWN_HOSTS_OK => Ok(()),

            SSH_KNOWN_HOSTS_UNKNOWN | SSH_KNOWN_HOSTS_NOT_FOUND => {
                let fp = self.server_fingerprint()?;
                eprintln!(
                    "The authenticity of the host cannot be established.\n\
                     SHA256 fingerprint: {fp}"
                );
                eprint!("Are you sure you want to continue connecting (yes/no)? ");
                io::stderr().flush().ok();

                let mut answer = String::new();
                io::stdin().lock().read_line(&mut answer)?;

                if answer.trim().to_lowercase() != "yes" {
                    bail!("Host key verification aborted by user.");
                }

                let rc = unsafe { ffi::ssh_session_update_known_hosts(self.inner) };
                if rc != SSH_OK {
                    let msg = last_error(self.inner);
                    bail!("Could not update known_hosts: {msg}");
                }
                eprintln!("Warning: Permanently added host to the list of known hosts.");
                Ok(())
            }

            SSH_KNOWN_HOSTS_CHANGED => {
                let fp = self.server_fingerprint().unwrap_or_else(|_| "<unknown>".into());
                bail!(
                    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     @  WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!  @\n\
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     Server fingerprint: {fp}\n\n\
                     Someone could be doing a man-in-the-middle attack!\n\
                     Remove the offending key from ~/.ssh/known_hosts and try again."
                )
            }

            SSH_KNOWN_HOSTS_OTHER => bail!(
                "The host key type has changed unexpectedly – possible MITM attack."
            ),

            _ /* SSH_KNOWN_HOSTS_ERROR + anything else */ => {
                bail!("Host key check error: {}", last_error(self.inner));
            }
        }
    }

    /// Compute the server's public-key SHA-256 fingerprint as a colon-delimited
    /// hex string (matches the format displayed by OpenSSH).
    fn server_fingerprint(&self) -> anyhow::Result<String> {
        let mut server_key: ffi::ssh_key = std::ptr::null_mut();
        let rc = unsafe { ffi::ssh_get_server_publickey(self.inner, &mut server_key) };
        if rc != SSH_OK {
            bail!("ssh_get_server_publickey failed");
        }

        let mut hash_ptr: *mut c_uchar = std::ptr::null_mut();
        let mut hash_len: usize = 0;
        let rc = unsafe {
            ffi::ssh_get_publickey_hash(
                server_key,
                SSH_PUBLICKEY_HASH_SHA256,
                &mut hash_ptr,
                &mut hash_len,
            )
        };
        unsafe { ffi::ssh_key_free(server_key) }; // always free the key

        if rc != SSH_OK || hash_ptr.is_null() {
            bail!("ssh_get_publickey_hash failed");
        }

        let hex = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) }
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        unsafe { ffi::ssh_clean_pubkey_hash(&mut hash_ptr) };
        Ok(hex)
    }

    // Authentication

    /// Authenticate: try public-key / SSH-agent auto first;
    /// fall back to interactive password prompt.
    pub fn authenticate(&self, _identity: Option<&str>) -> anyhow::Result<()> {
        // 1. Public-key auto: SSH agent + ~/.ssh/id_* key files in order.
        let rc = unsafe {
            ffi::ssh_userauth_publickey_auto(
                self.inner,
                std::ptr::null(), // username: NULL → use configured user
                std::ptr::null(), // passphrase: NULL → try agent / no passphrase
            )
        };

        match rc {
            x if x == SSH_AUTH_SUCCESS => return Ok(()),
            x if x == SSH_AUTH_ERROR => {
                bail!("Public-key auth error: {}", last_error(self.inner));
            }
            _ => { /* SSH_AUTH_DENIED / PARTIAL – fall through to password */ }
        }

        // 2. Password fallback.
        let password =
            rpassword::prompt_password("Password: ").context("Could not read password")?;
        let c_pw = CString::new(password).context("Password contains a NUL byte")?;

        let rc = unsafe {
            ffi::ssh_userauth_password(
                self.inner,
                std::ptr::null(), // username: NULL → use configured user
                c_pw.as_ptr(),
            )
        };

        if rc == SSH_AUTH_SUCCESS {
            Ok(())
        } else {
            bail!("Authentication failed: {}", last_error(self.inner));
        }
    }

    // Accessors

    /// Return the raw `ssh_session` pointer (needed by `SshChannel`).
    pub(crate) fn raw(&self) -> ffi::ssh_session {
        self.inner
    }
}

/// Build an `anyhow::Error` from the last libssh error on `session`.
pub(crate) fn session_error(session: ffi::ssh_session) -> anyhow::Error {
    anyhow!("{}", last_error(session))
}
