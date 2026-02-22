use clap::Parser;

/// A minimal SSH client powered by libssh FFI.
///
/// Usage:
///   myssh [user@]host [-p PORT] [-i KEY] [-- COMMAND...]
#[derive(Parser, Debug)]
#[command(
    name    = "myssh",
    about   = "Minimal SSH client built on top of libssh via FFI",
    version
)]
pub struct Cli {
    /// Target in the form `[user@]host`
    pub destination: String,

    /// Remote port (default: 22)
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,

    /// Path to a private key file (default: SSH agent / ~/.ssh/id_*)
    #[arg(short, long, value_name = "FILE")]
    pub identity: Option<String>,

    /// Command to execute on the remote host.
    /// Separate with `--`, e.g.: myssh user@host -- ls -la
    #[arg(last = true)]
    pub command: Vec<String>,
}

/// Parsed components of a `[user@]host` string.
pub struct Destination {
    pub user: String,
    pub host: String,
}

impl Destination {
    pub fn parse(dest: &str) -> anyhow::Result<Self> {
        if let Some((user, host)) = dest.split_once('@') {
            anyhow::ensure!(!user.is_empty() && !host.is_empty(), "invalid destination: {dest}");
            Ok(Self { user: user.to_owned(), host: host.to_owned() })
        } else {
            // No `user@` prefix – fall back to the current Unix user.
            let user = std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".to_owned());
            Ok(Self { user, host: dest.to_owned() })
        }
    }
}
