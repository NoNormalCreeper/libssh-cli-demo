use lexopt::prelude::*;

pub struct Cli {
    pub destination: String,
    pub port: u16,
    pub identity: Option<String>,
    pub command: Vec<String>,
}

impl Cli {
    pub fn parse() -> anyhow::Result<Self> {
        let mut parser = lexopt::Parser::from_env();

        let mut destination: Option<String> = None;
        let mut port: u16 = 22;
        let mut identity: Option<String> = None;
        let mut command: Vec<String> = Vec::new();

        while let Some(arg) = parser.next()? {
            match arg {
                Short('p') => {
                    port = parser.value()?.parse()?;
                }
                Short('i') => {
                    identity = Some(parser.value()?.string()?);
                }
                Short('h') | Long("help") => {
                    print_help();
                    std::process::exit(0);
                }
                Short('V') | Long("version") => {
                    print_version();
                    std::process::exit(0);
                }
                Value(val) if destination.is_none() => {
                    destination = Some(val.string()?);
                }
                Value(val) => {
                    command.push(val.string()?);
                }
                _ => return Err(arg.unexpected().into()),
            }
        }

        let destination = destination.ok_or_else(|| {
            anyhow::anyhow!(
                "missing required argument: destination\n\n\
                 Usage: {} [user@]host [-p port] [-i keyfile] [-- command ...]",
                env!("CARGO_PKG_NAME"),
            )
        })?;

        Ok(Self { destination, port, identity, command })
    }
}

fn print_help() {
    let bin = env!("CARGO_PKG_NAME");
    println!(
        "\
{bin} - minimal SSH client built on libssh via FFI

Usage: {bin} [user@]host [-p port] [-i keyfile] [-- command ...]

Options:
  -p PORT    Remote port (default: 22)
  -i FILE    Path to private key file
  -h         Print this help message
  -V         Print version"
    );
}

fn print_version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
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
