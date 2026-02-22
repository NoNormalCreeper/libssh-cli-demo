# libssh CLI demo

## Installation

### Install system dependencies

```bash
sudo apt install libssh-dev libclang-dev
```

`libssh-dev` provides `libssh.h` and the shared library; `libclang-dev` is required by `bindgen` to parse C headers.

### Build and run

```bash
# known host, pubkey auth
cargo run -- alice@myserver.example -- ls -la /tmp

# custom port + force password (defeat pubkey by pointing identity to /dev/null)
cargo run -- alice@myserver.example -p 2222 -i /dev/null -- whoami

# defaults user to $USER, defaults command to `hostname`
cargo run -- myserver.example
```

## Usage

```bash
$ cargo run -- --help

Usage: myssh [user@]host [-p PORT] [-i KEY] [-- COMMAND...]

Usage: libssh-cli-demo [OPTIONS] <DESTINATION> [-- <COMMAND>...]

Arguments:
  <DESTINATION>
          Target in the form `[user@]host`

  [COMMAND]...
          Command to execute on the remote host. Separate with `--`, e.g.: myssh user@host -- ls -la

Options:
  -p, --port <PORT>
          Remote port (default: 22)
          
          [default: 22]

  -i, --identity <FILE>
          Path to a private key file (default: SSH agent / ~/.ssh/id_*)

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
