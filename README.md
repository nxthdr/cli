# CLI

Command line interface for nxthdr platform.

## Installation

```bash
cargo install nxthdr
```

## Usage

```bash
# Interact with peering platform
nxthdr peering

# Interact with probing platform
nxthdr probing

# Verbose logging
nxthdr peering -vvv
```

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with verbose logging
cargo run -- peering local bird-status -vvv
```
