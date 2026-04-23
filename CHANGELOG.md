# Changelog

## v0.11.0 (2026-04-23)

Discipline pass bringing kit to parity with rune's hygiene posture
(v0.10 equivalent). No user-facing behavior changes; all work is
internal quality — stricter compiler gates, file-size enforcement,
better agent context.

### Added

- **`kit skill`** subcommand. Prints a self-documenting reference —
  concepts (registry / tier / pin), lifecycle (sense → evaluate → apply
  → verify-registry → sync), six critical rules (don't hand-edit
  generated mise config, registry push is authoritative, don't
  downgrade tier for convenience, verify after bulk ops, CI subcommands
  aren't for interactive use, `verify_signatures` stays on), a
  when-to-use breakdown for every command, and gotchas. Content lives
  in `resources/skill.md` and is baked in via `include_str!`. Designed
  to feed an agent's skill listing so the LLM sees tier discipline and
  signature-verification-is-non-negotiable before touching kit.

- **File-size CI gate.** Any `.rs` file over 500 lines fails the
  `file-size-gate` job. Ten current offenders (`main.rs`, `mise.rs`,
  `verify.rs`, `ci/check.rs`, `source/mod.rs`, `tool.rs`, `ci/apply.rs`,
  `lockfile.rs`, `registry.rs`, `ci/evaluate.rs`) are waived in
  `.file-size-waiver` pending follow-up splits. New files that regress
  get blocked at CI. Rationale: smaller files = smaller LLM context
  per edit, cheaper restarts, more reviewable diffs.

### Changed

- **`#![deny(warnings, clippy::all)]`** at the crate level. The lint
  posture that rune has had since v0.10. Two pre-existing lints
  (`assert_eq!` with a literal bool in `verify_registry.rs` tests)
  fixed as part of this. Any new warning fails the build — no quiet
  drift.

### Scope of this release

This MR closes kit's biggest hygiene gaps against rune in a single
pass. Remaining follow-ups (CHANGELOG backfill for v0.10.x and prior,
tests/ directory with integration tests, splitting the waived files,
error-prescription audit) are scheduled per usage-driven need, not
bundled into this release. See rune's v0.10-v0.13 playbook for the
pattern.

Shared design principle with rune: "registry push is the authoritative
publish, plain git commit is not." Same phrasing in both tools' skill
outputs; applies to muxr and any future registry-fronting tool.
