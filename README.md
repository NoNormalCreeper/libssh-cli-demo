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

```
$ cargo run -- -h

libssh-cli-demo - minimal SSH client built on libssh via FFI

Usage: libssh-cli-demo [user@]host [-p port] [-i keyfile] [-- command ...]

Options:
  -p PORT    Remote port (default: 22)
  -i FILE    Path to private key file
  -h         Print this help message
  -V         Print version
```
