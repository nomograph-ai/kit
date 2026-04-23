# kit — developer toolchain supply chain

Manage the versions and verification posture of developer binaries (CLI
tools, runtimes) from git-based registries. Resolves cross-registry tool
defs, generates mise configuration, enforces cosign / attestation /
checksum verification per tier, and automates upstream bump tracking via
a three-pipeline CI architecture.

## Concepts

- **Registry**: git repo containing per-tool TOML definitions under
  `tools/`. Split across two typical classes: first-party (`nomograph/…`,
  tools you ship, always `own` tier with cosign) and third-party
  (`<namespace>/kits`, mixed, verified by attestation or checksum).
- **Manifest**: none at project level — kit is global. It resolves the
  union of every configured registry and writes
  `~/.config/mise/conf.d/kit.toml` from the resolved set.
- **Lock**: the generated mise config is the lock. First line reads
  `# Managed by kit. Do not edit.` for a reason.
- **Tier**: `own` / `high` / `low`. Drives verification strictness.
  - **own** → cosign keyless required (sigstore, OIDC-rooted identity)
  - **high** → GitHub attestation or checksum required
  - **low** → sha256 checksum
- **Pin**: a local override that holds a tool at a specific version or
  registry source, bypassing the registry's chosen version.

## Lifecycle

```
upstream release      (e.g. gh 2.74.0 appears)
  ↓
kit sense             (CI Pipeline 1: detect)
  ↓
kit evaluate + apply  (CI Pipeline 2: LLM-gated update, opens MR)
  ↓
kit verify-registry   (CI Pipeline 3: hard gate before merge)
  ↓
merge to registry main
  ↓
user runs `kit sync`  → mise picks up the new resolved version
```

## Critical rules

1. **`~/.config/mise/conf.d/kit.toml` is generated. Never hand-edit it.**
   Every `kit sync` regenerates the file from the resolved registry set.
   Manual edits are silently overwritten. Use `kit pin` / `kit unpin` /
   `kit add` to change state.

2. **Registry push is the authoritative publish.** Every edit to a
   registry's tool TOML (e.g. `tools/gh.toml`) must be followed by
   `kit push` in the same session. A plain `git commit` in the registry
   checkout stages the edit locally but doesn't ship it to the registry
   remote; other machines' `kit sync` won't see it.

3. **Do not downgrade a tool's tier for convenience.** Tier reflects
   actual trust posture. If cosign is failing for an `own` tool, fix the
   signing chain; don't move the definition to `high` to make the error
   go away. Tier changes require an explicit rationale and review.

4. **`kit verify` after any bulk operation.** Signature mismatches can
   pass through a routine `kit sync` if verification is partial.
   `kit verify` re-hashes and re-verifies every installed binary from
   scratch — the explicit safety net after adding multiple tools,
   bumping versions, or restoring a machine.

5. **Sense / evaluate / apply belong to CI, not to interactive use.**
   These subcommands run in the three-pipeline automation. Running
   `kit apply` manually on a registry's main branch bypasses the LLM
   evaluation gate that catches regressions. If the gate rejected a
   bump, the gate is the signal — investigate, don't override.

6. **`verify_signatures = true` stays on.** Turning it off "temporarily
   to debug a breakage" hides the signal you need to debug the
   breakage. If a signature is failing, find out why, don't silence it.

## When to use which

- **`kit setup [--registry <url>]`** — one-time per machine. Creates
  `~/.config/kit/config.toml`, adds a first registry, initializes the
  cache dir. Run this before anything else on a fresh machine.
- **`kit status`** — at session start or when debugging "what version am
  I actually on." Shows installed vs registry-resolved for every tool,
  and which registry won the resolution when multiple match.
- **`kit sync`** — after changing a pin, after `git pull` on a kit
  registry, or when setting up a new machine. Resolves all registries,
  writes mise config, verifies per tier.
- **`kit pin <tool> <version>`** — hold a tool at a specific version
  overriding the registry. Useful when a bump broke something in your
  project; unpin after the upstream fix lands.
- **`kit unpin <tool>`** — release a pin, re-resolve via registry.
- **`kit add <tool> <source>`** — add a new tool to a writable
  registry. Writes the tool TOML + scaffolds the signature/checksum
  config based on source type.
- **`kit push`** — publish a registry edit upstream. (See rule #2.)
- **`kit remove <tool>`** — drop a tool from a writable registry.
- **`kit verify`** — re-verify every installed binary against its
  registry spec. (See rule #4.)
- **`kit audit`** — scan installed tools for known security advisories.
- **`kit diff`** — compare local lockfile (mise config) against the
  current registry state. Useful for "what would `kit sync` change?"
- **`kit upgrade`** — interactive: check upstream for updates, apply
  selected ones, re-verify.
- **`kit init --ci`** — bootstrap a new registry with the three-pipeline
  CI automation. One-time per registry.

## CI subcommands (don't run interactively)

- **`kit sense`** — Pipeline 1. Scans registry tools for upstream
  updates, produces a classified report. Always succeeds unless infra
  is broken.
- **`kit evaluate`** — Pipeline 2. LLM assessment of edge-case updates.
- **`kit apply`** — Pipeline 2. Writes updated tool definitions from
  evaluation output. Does not create MRs itself; pipeline orchestrates.
- **`kit verify-registry`** — Pipeline 3. Validates every TOML in
  `tools/`, re-verifies checksums upstream. Deterministic merge gate.

## Gotchas

- **Tier change requires regenerating signatures/checksums.** Moving a
  tool from `low` to `high` doesn't automatically acquire an
  attestation; the registry maintainer has to source it.
- **The `own` tier is reserved for nomograph-owned projects.** Using it
  for third-party tools produces cosign verification failures you can't
  fix.
- **Multiple registries with the same tool name** resolve via registry
  declaration order in config. First registry wins; later registries'
  definitions are ignored for that name. `kit status` shows the
  winning registry per tool.
- **Tool names must match `[a-zA-Z0-9_-]+`.** Same validation as rune.
