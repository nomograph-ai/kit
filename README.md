![hero](hero.svg)

# kit

[![crates.io](https://img.shields.io/crates/v/nomograph-kit)](https://crates.io/crates/nomograph-kit)
[![pipeline](https://gitlab.com/nomograph/kit/badges/main/pipeline.svg)](https://gitlab.com/nomograph/kit/-/pipelines)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![built with GitLab](https://img.shields.io/badge/built_with-GitLab-FC6D26?logo=gitlab)](https://gitlab.com/nomograph/kit)

Verified tool registry manager -- manages developer toolchains from
git-based registries.

kit resolves tool versions across multiple registries, generates
[mise](https://mise.jdx.dev) configuration, verifies checksums and
cosign signatures, and automates upstream update tracking.

## Install

```bash
cargo install nomograph-kit
```

The binary is called `kit`.

## Quick start

```bash
kit setup --registry https://gitlab.com/your/registry.git
kit sync
kit status
```

## Commands

| Command | Description |
|---------|-------------|
| `kit setup` | One-time config, optionally add a registry |
| `kit sync` | Pull registries, resolve, generate mise config, install |
| `kit status` | Installed vs registry, drift detection, verification strength |
| `kit diff` | Show changes between lockfile and registry |
| `kit upgrade` | Interactive tool update workflow |
| `kit verify` | Re-verify all installed binaries (cosign + checksums) |
| `kit audit` | Check tools for known security advisories |
| `kit add <name> <source>` | Query upstream, generate tool definition |
| `kit push <name>` | Commit and push a tool definition |
| `kit remove <name>` | Remove a tool from a writable registry |
| `kit pin <name> <version>` | Pin a tool's version locally |
| `kit unpin <name>` | Remove a local pin |
| `kit sense` | Detect upstream changes, classify updates (CI mode) |
| `kit check` | Scan upstream for newer versions (CI mode) |
| `kit evaluate` | LLM review for edge cases (CI mode) |
| `kit apply` | Apply updates, create MR (CI mode) |
| `kit verify-registry` | Validate all tool definitions before merge (CI mode) |
| `kit init [--ci]` | Scaffold a new registry |
| `kit completions <shell>` | Shell completions (bash/zsh/fish) |
| `kit man-page` | Generate man page |

## Registries

A registry is a git repo with per-tool TOML definitions:

```
tools/
  _meta.toml        # registry metadata + policy
  gh.toml           # one file per tool
  muxr.toml
  ...
```

Each tool definition is self-contained:

```toml
[tool]
name = "gh"
source = "github"
repo = "cli/cli"
version = "2.89.0"
tag_prefix = "v"
bin = "gh"
tier = "high"
aqua = "cli/cli"

[tool.assets]
macos-arm64 = "gh_{version}_macOS_arm64.zip"
linux-x64 = "gh_{version}_linux_amd64.tar.gz"

[tool.checksum]
file = "gh_{version}_checksums.txt"
format = "sha256"

[tool.signature]
method = "github-attestation"
```

Sources: `github`, `gitlab`, `npm`, `crates`, `direct`, `rustup`

Smart `kit add` queries upstream and auto-populates:

```bash
kit add jq jqlang/jq              # GitHub
kit add muxr nomograph/muxr --gitlab  # GitLab (resolves project_id)
kit add claude-code --npm @anthropic-ai/claude-code
kit add cargo-nextest --crates
```

## Multi-registry

Configure multiple registries in `~/.config/kit/config.toml`. First
registry wins when tools overlap. Local pins override.

```toml
[[registry]]
name = "nomograph"
url = "https://gitlab.com/nomograph/kits.git"

[[registry]]
name = "corp"
url = "https://gitlab.com/corp/tools.git"
readonly = true
```

## Security

kit is a supply chain tool. Security is enforced at every layer:

- **Input validation**: all fields validated against strict regex patterns
- **TOML injection prevention**: mise config built via toml_edit API
- **Supply chain attack detection**: same version + changed checksum = hard stop
- **Dependency confusion prevention**: registry migration requires confirmation
- **Cosign verification**: anchored certificate identity match
- **Registry URL restriction**: https:// and git@ only
- **Symlink rejection**: malicious registries cannot escape tools/ directory
- **HTTPS-only**: all HTTP clients enforce TLS

46 security findings identified and addressed across 5 adversarial
review passes.

## License

MIT -- [Nomograph](https://gitlab.com/nomograph)
