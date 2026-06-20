# CLI

Command-line interface for the [nxthdr](https://nxthdr.dev) platform — the peering (PeerLab) and probing (Saimiris) services.

## Installation

```bash
cargo install nxthdr
```

## Shell completions

Generate a completion script with `nxthdr completions <shell>` and install it where your shell looks for completions:

```bash
# fish
nxthdr completions fish > ~/.config/fish/completions/nxthdr.fish

# zsh — ensure the target dir is on $fpath, then restart the shell
nxthdr completions zsh > ~/.zfunc/_nxthdr

# bash
nxthdr completions bash > ~/.local/share/bash-completion/completions/nxthdr
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

## Command structure

Commands follow a consistent `nxthdr <group> <resource> <verb>` shape:

```
nxthdr
├─ auth      login · logout · status
├─ peering
│  ├─ asn      get
│  ├─ prefix   list · request <hours> · revoke <prefix> · rpki {enable,disable} <prefix>
│  ├─ route    list · lookup <prefix>
│  └─ peerlab  env
├─ probing
│  ├─ agent        list
│  ├─ credits      get
│  ├─ measurement  send <file> · list · get <id> · cancel <id>
│  └─ reply        list --src-ip <ip>
└─ completions  <shell>   # bash · zsh · fish · elvish · powershell
```

Run `nxthdr help` or `nxthdr <group> <resource> --help` for any command's options.

## Authentication

```bash
nxthdr auth login     # device-flow login (prints a URL + code to approve)
nxthdr auth status    # show token state
nxthdr auth logout
```

## Output formats

Every command takes a global `-o` / `--output` flag — `text` (default), `json`, or `csv` — for piping and scripting:

```bash
nxthdr probing measurement list --status cancelled -o csv
nxthdr peering prefix list -o json
```

## Examples

```bash
# Peering: request a 12h /48 lease, then generate a PeerLab .env
nxthdr peering prefix request 12
nxthdr peering peerlab env > .env

# Probing: send probes, check progress, fetch replies
echo '2001:4860:4860::8888,24000,33434,16,udp' | nxthdr probing measurement send --agent vltcdg01
nxthdr probing measurement get <id>
nxthdr probing reply list --src-ip <ip>
```

## Documentation

Full CLI reference: <https://docs.nxthdr.dev/docs/tools/cli/>
