# CLI

Command line interface for the nxthdr platform.

## Installation

```bash
cargo install nxthdr
```

## Usage

```bash
nxthdr help
```

### Authentication

```bash
# Log in to the platform
nxthdr login

# Log out of the platform
nxthdr logout
```

### PeerLab Integration

```bash
# Generate .env file for PeerLab
nxthdr peering peerlab env > .env
```

This command automatically generates a PeerLab `.env` file using your assigned ASN and active prefix leases from nxthdr.
