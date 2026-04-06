# kit

Verified tool registry manager -- manages developer toolchains from
git-based registries.

kit resolves tool versions across multiple registries, generates
[mise](https://mise.jdx.dev) configuration, verifies checksums and
signatures, and automates upstream update tracking.

## Install

### From source

```bash
cargo install --git https://gitlab.com/dunn.dev/kit/cli.git
```

### From release (mise)

```toml
[tools."http:kit"]
version = "0.1.0"

[tools."http:kit".platforms]
macos-arm64 = { url = "https://gitlab.com/api/v4/projects/81066225/packages/generic/kit/v0.1.0/kit-darwin-arm64", bin = "kit" }
linux-x64 = { url = "https://gitlab.com/api/v4/projects/81066225/packages/generic/kit/v0.1.0/kit-linux-amd64", bin = "kit" }
```

### Manual

```bash
curl -L "https://gitlab.com/api/v4/projects/81066225/packages/generic/kit/v0.1.0/kit-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -o kit
chmod +x kit
```

## Quick start

```bash
kit setup          # creates ~/.config/kit/config.toml with default registry
kit sync           # pull tools, generate mise config, install, verify
kit status         # show all tools with versions and drift
```

## Commands

| Command | What it does |
|---------|-------------|
| `kit setup` | One-time config creation |
| `kit sync` | Pull registries, resolve, generate mise config, install |
| `kit status` | Show installed vs registry, drift detection |
| `kit verify` | Re-verify all installed binaries (checksums + signatures) |
| `kit add <name> <source>` | Add a tool definition to a writable registry |
| `kit push <name>` | Commit and push a tool definition |
| `kit pin <name> <version>` | Pin a tool's version locally |
| `kit unpin <name>` | Remove a local pin |
| `kit init [--ci]` | Scaffold a new registry |
| `kit check` | Check upstream for newer versions (CI mode) |
| `kit evaluate` | LLM evaluation of edge cases (CI mode) |
| `kit apply` | Apply updates, create MR (CI mode) |

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

## Multi-registry

Configure multiple registries in `~/.config/kit/config.toml`. First
registry wins when tools overlap. Local pins override registry versions.

```toml
[[registry]]
name = "dunn"
url = "https://gitlab.com/dunn.dev/kit/registry.git"

[[registry]]
name = "corp"
url = "https://gitlab.com/corp/tools.git"
readonly = true
```

## Security

kit is a supply chain tool. Security is enforced at every layer:

- **Input validation**: tool names, versions, repos, asset names, URLs,
  checksums all validated against strict patterns
- **TOML injection prevention**: mise config built via toml_edit API,
  never string interpolation
- **Registry URL restriction**: only https:// and git@ allowed
- **Supply chain attack detection**: same version + changed checksum
  triggers hard stop (S-2)
- **Dependency confusion prevention**: registry migration requires
  explicit confirmation (S-9)
- **Cosign verification**: exact certificate identity match, not regexp
- **Symlink rejection**: malicious registries cannot use symlinks to
  escape the tools/ directory

38 security findings identified and addressed across 3 adversarial
review passes.

## License

MIT
