mod ffi;
mod cli;
mod session;
mod channel;

use std::process;

use cli::{Cli, Destination};
use session::SshSession;
use channel::SshChannel;

fn run() -> anyhow::Result<i32> {
    let args = Cli::parse()?;

    // Parse `[user@]host`
    let dest = Destination::parse(&args.destination)?;

    // Build remote command
    // Default to a simple `hostname` if none given.
    let command = if args.command.is_empty() {
        "hostname".to_owned()
    } else {
        args.command.join(" ")
    };

    eprintln!(
        "Connecting to {}@{}:{} …",
        dest.user, dest.host, args.port
    );

    // Establish TCP connection + set options
    let sess = SshSession::connect(
        &dest.host,
        args.port,
        &dest.user,
        args.identity.as_deref(),
    )?;

    // Verify server host key
    sess.verify_host()?;

    // Authenticate
    sess.authenticate(args.identity.as_deref())?;

    eprintln!("Authenticated. Running: {command}");

    // Open a channel and execute the command
    let chan = SshChannel::open(&sess)?;
    let exit_status = chan.exec(&command)?;

    Ok(exit_status)
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            process::exit(1);
        }
    }
}
