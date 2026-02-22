use std::ffi::CString;
use std::io::{self, Write};
use std::os::raw::c_void;

use anyhow::{bail, Context};

use crate::ffi;
use crate::session::{session_error, SshSession};

const SSH_OK: i32 = 0;
const BUF: usize = 4096;

/// Owns a `ssh_channel*`; closes and frees it on drop.
pub struct SshChannel {
    inner: ffi::ssh_channel,
    session: ffi::ssh_session, // borrowed reference for error messages only
}

impl Drop for SshChannel {
    fn drop(&mut self) {
        unsafe {
            if ffi::ssh_channel_is_open(self.inner) != 0 {
                let _ = ffi::ssh_channel_send_eof(self.inner);
                ffi::ssh_channel_close(self.inner);
            }
            ffi::ssh_channel_free(self.inner);
        }
    }
}

impl SshChannel {
    /// Allocate a new channel and open a session on it.
    pub fn open(sess: &SshSession) -> anyhow::Result<Self> {
        let channel = unsafe { ffi::ssh_channel_new(sess.raw()) };
        if channel.is_null() {
            bail!("ssh_channel_new returned NULL");
        }

        let chan = Self { inner: channel, session: sess.raw() };

        let rc = unsafe { ffi::ssh_channel_open_session(chan.inner) };
        if rc != SSH_OK {
            bail!("ssh_channel_open_session failed: {}", session_error(sess.raw()));
        }

        Ok(chan)
    }

    /// Execute `cmd` on the remote host, streaming stdout/stderr to the
    /// process's stdout/stderr. Returns the remote process exit status.
    pub fn exec(&self, cmd: &str) -> anyhow::Result<i32> {
        let c_cmd = CString::new(cmd).context("command contains NUL byte")?;

        let rc = unsafe { ffi::ssh_channel_request_exec(self.inner, c_cmd.as_ptr()) };
        if rc != SSH_OK {
            bail!(
                "ssh_channel_request_exec failed: {}",
                session_error(self.session)
            );
        }

        let mut buf = [0u8; BUF];

        // Stream stdout
        loop {
            let n = unsafe {
                ffi::ssh_channel_read(
                    self.inner,
                    buf.as_mut_ptr() as *mut c_void,
                    BUF as u32,
                    0, // is_stderr = false
                )
            };

            if n > 0 {
                io::stdout().write_all(&buf[..n as usize])?;
            } else if n == 0 {
                break; // remote closed stdout (EOF)
            } else {
                bail!("ssh_channel_read(stdout) error: {}", session_error(self.session));
            }
        }

        // Drain stderr (non-blocking, 0 ms timeout)
        loop {
            let n = unsafe {
                ffi::ssh_channel_read_timeout(
                    self.inner,
                    buf.as_mut_ptr() as *mut c_void,
                    BUF as u32,
                    1,  // is_stderr = true
                    0,  // timeout_ms = 0 → non-blocking
                )
            };

            if n > 0 {
                io::stderr().write_all(&buf[..n as usize])?;
            } else {
                break;
            }
        }

        io::stdout().flush().ok();
        io::stderr().flush().ok();

        // Collect exit status
        // Make sure we've seen remote EOF before reading exit status.
        unsafe { ffi::ssh_channel_send_eof(self.inner) };

        let status = unsafe { ffi::ssh_channel_get_exit_status(self.inner) };
        Ok(status)
    }
}
