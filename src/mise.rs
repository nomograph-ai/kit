//! Generate mise config.toml from resolved tool definitions.
//!
//! SECURITY (S-3): All TOML is constructed programmatically via the toml_edit
//! crate. No string interpolation or formatting is used to build TOML values.
//! Every value passes through toml_edit's API, which handles escaping.

use anyhow::Result;
use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table};

use crate::config::Config;
use crate::platform::Platform;
use crate::registry::ResolvedTool;
use crate::tool::Source;

/// All supported platforms, in the order they appear in generated config.
const PLATFORMS: &[Platform] = &[Platform::MacosArm64, Platform::LinuxX64];

/// Generate a complete mise config.toml from resolved tool definitions.
///
/// The output contains:
/// 1. Header comments (managed-by, timestamp)
/// 2. `[tools]` section with flat entries (aqua-backed, npm, cargo, rustup)
/// 3. `[tools."http:name"]` subtables for http-backend tools
/// 4. `[settings]` section with trusted_config_paths from config (S-12)
pub fn generate(tools: &[ResolvedTool], config: &Config) -> Result<String> {
    let mut doc = DocumentMut::new();

    // -- Header comments --
    doc.decor_mut()
        .set_prefix("# Managed by kit. Do not edit directly.\n# Source: kit sync\n\n");

    // -- [tools] section --
    let mut tools_table = Table::new();
    tools_table.set_implicit(false);

    // Partition tools: flat entries first, then http-backend tools.
    let mut flat_entries: Vec<(&ResolvedTool, String, String)> = Vec::new();
    let mut http_entries: Vec<&ResolvedTool> = Vec::new();

    for rt in tools {
        match classify(rt) {
            ToolEntry::Flat { key, version } => {
                flat_entries.push((rt, key, version));
            }
            ToolEntry::Http => {
                http_entries.push(rt);
            }
        }
    }

    // Add flat entries to [tools]
    for (_rt, key, version) in &flat_entries {
        tools_table[key.as_str()] = value(version.as_str());
    }

    // Add http-backend subtables to [tools]
    for rt in &http_entries {
        let subtable = build_http_subtable(rt)?;
        let key = format!("http:{}", rt.def.name);
        tools_table[key.as_str()] = Item::Table(subtable);
    }

    doc["tools"] = Item::Table(tools_table);

    // -- [settings] section (S-12: only from config, never from registry data) --
    if !config.settings.trusted_config_paths.is_empty() {
        let mut settings_table = Table::new();
        let mut paths_array = Array::new();
        for path in &config.settings.trusted_config_paths {
            paths_array.push(path.as_str());
        }
        settings_table["trusted_config_paths"] = value(paths_array);
        doc["settings"] = Item::Table(settings_table);
    }

    Ok(doc.to_string())
}

/// Classification of how a tool maps to mise config.
enum ToolEntry {
    /// A single `key = "version"` line in [tools].
    Flat { key: String, version: String },
    /// A `[tools."http:name"]` subtable with platform URLs.
    Http,
}

/// Determine the mise backend representation for a resolved tool.
fn classify(rt: &ResolvedTool) -> ToolEntry {
    let def = &rt.def;
    match def.source {
        Source::Rustup => ToolEntry::Flat {
            key: "rust".to_string(),
            version: def.version.clone(),
        },
        Source::Npm => {
            let pkg = def
                .package
                .as_deref()
                .unwrap_or(&def.name);
            ToolEntry::Flat {
                key: format!("npm:{pkg}"),
                version: def.version.clone(),
            }
        }
        Source::Crates => {
            let crate_name = def
                .crate_name
                .as_deref()
                .unwrap_or(&def.name);
            ToolEntry::Flat {
                key: format!("cargo:{crate_name}"),
                version: def.version.clone(),
            }
        }
        Source::Github => {
            if def.aqua.is_some() {
                // Aqua-backed: mise resolves via its aqua registry
                ToolEntry::Flat {
                    key: def.name.clone(),
                    version: def.version.clone(),
                }
            } else {
                // No aqua: use github: backend
                let repo = def.repo.as_deref().unwrap_or("MISSING/REPO");
                ToolEntry::Flat {
                    key: format!("github:{repo}"),
                    version: def.version.clone(),
                }
            }
        }
        Source::Gitlab => {
            if def.project_id.is_some() {
                // Own GitLab tool: http backend with generic package URLs
                ToolEntry::Http
            } else if def.aqua.is_some() {
                // Third-party GitLab with aqua support
                let repo = def.repo.as_deref().unwrap_or("MISSING/REPO");
                ToolEntry::Flat {
                    key: format!("gitlab:{repo}"),
                    version: def.version.clone(),
                }
            } else {
                // Third-party GitLab without aqua: http backend
                ToolEntry::Http
            }
        }
        Source::Direct => ToolEntry::Http,
    }
}

/// Build a `[tools."http:name"]` subtable with version and platform URLs.
fn build_http_subtable(rt: &ResolvedTool) -> Result<Table> {
    let def = &rt.def;
    let mut subtable = Table::new();

    subtable["version"] = value(def.version.as_str());

    let mut platforms_table = Table::new();
    for &platform in PLATFORMS {
        if let Some(url) = def.url_for(platform) {
            let mut entry = InlineTable::new();
            entry.insert("url", url.as_str().into());
            entry.insert("bin", def.bin_name().into());
            platforms_table[platform.key()] = value(entry);
        }
    }

    if !platforms_table.is_empty() {
        subtable["platforms"] = Item::Table(platforms_table);
    }

    Ok(subtable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Settings};
    use crate::registry::ResolvedTool;
    use crate::tool::{Source, ToolDef, Tier};
    use std::collections::HashMap;

    /// Minimal config for tests.
    fn test_config() -> Config {
        Config {
            settings: Settings::default(),
            registry: vec![],
            pins: HashMap::new(),
        }
    }

    /// Helper: build a ToolDef with common defaults, overriding specific fields.
    fn make_tool(
        name: &str,
        source: Source,
        version: &str,
    ) -> ToolDef {
        ToolDef {
            name: name.to_string(),
            description: None,
            source,
            version: version.to_string(),
            tag_prefix: "v".to_string(),
            bin: None,
            tier: Tier::Low,
            repo: None,
            project_id: None,
            package: None,
            crate_name: None,
            aqua: None,
            assets: HashMap::new(),
            checksum: None,
            checksums: HashMap::new(),
            signature: None,
        }
    }

    fn resolved(def: ToolDef) -> ResolvedTool {
        ResolvedTool {
            def,
            registry: "test".to_string(),
        }
    }

    #[test]
    fn github_with_aqua_produces_flat_entry() {
        let mut def = make_tool("gh", Source::Github, "2.89.0");
        def.repo = Some("cli/cli".to_string());
        def.aqua = Some("cli/cli".to_string());

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        // Should produce: gh = "2.89.0"
        assert!(output.contains("gh = \"2.89.0\""), "expected flat aqua entry, got:\n{output}");
        // Should NOT contain http: or github:
        assert!(!output.contains("http:gh"), "should not use http backend for aqua tool");
        assert!(!output.contains("github:"), "should not use github: prefix for aqua tool");
    }

    #[test]
    fn github_without_aqua_produces_github_prefix() {
        let mut def = make_tool("dolt", Source::Github, "1.50.5");
        def.repo = Some("dolthub/dolt".to_string());

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        // Should produce: "github:dolthub/dolt" = "1.50.5"
        assert!(
            output.contains("\"github:dolthub/dolt\" = \"1.50.5\""),
            "expected github: prefix entry, got:\n{output}"
        );
    }

    #[test]
    fn gitlab_own_tool_produces_http_with_platforms() {
        let mut def = make_tool("muxr", Source::Gitlab, "0.6.2");
        def.project_id = Some(80663080);
        def.bin = Some("muxr".to_string());
        def.assets = HashMap::from([
            ("macos-arm64".to_string(), "muxr-darwin-arm64".to_string()),
            ("linux-x64".to_string(), "muxr-linux-amd64".to_string()),
        ]);

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        // Should have [tools."http:muxr"] section
        assert!(
            output.contains("[tools.\"http:muxr\"]"),
            "expected http:muxr subtable, got:\n{output}"
        );
        // Should contain version
        assert!(
            output.contains("version = \"0.6.2\""),
            "expected version in subtable, got:\n{output}"
        );
        // Should contain platform URLs from generic package registry
        assert!(
            output.contains("projects/80663080/packages/generic/muxr/v0.6.2/muxr-darwin-arm64"),
            "expected macos-arm64 URL, got:\n{output}"
        );
        assert!(
            output.contains("projects/80663080/packages/generic/muxr/v0.6.2/muxr-linux-amd64"),
            "expected linux-x64 URL, got:\n{output}"
        );
        // Should contain bin name
        assert!(
            output.contains("bin = \"muxr\""),
            "expected bin in platform entry, got:\n{output}"
        );
    }

    #[test]
    fn npm_tool_produces_npm_prefix() {
        let mut def = make_tool("claude-code", Source::Npm, "2.1.92");
        def.package = Some("@anthropic-ai/claude-code".to_string());

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("\"npm:@anthropic-ai/claude-code\" = \"2.1.92\""),
            "expected npm: prefix entry, got:\n{output}"
        );
    }

    #[test]
    fn crates_tool_produces_cargo_prefix() {
        let mut def = make_tool("some-crate", Source::Crates, "1.0.0");
        def.crate_name = Some("some-crate".to_string());

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("\"cargo:some-crate\" = \"1.0.0\""),
            "expected cargo: prefix entry, got:\n{output}"
        );
    }

    #[test]
    fn rustup_tool_produces_rust_key() {
        let def = make_tool("rust", Source::Rustup, "1.93.0");

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("rust = \"1.93.0\""),
            "expected rust = version, got:\n{output}"
        );
    }

    #[test]
    fn gitlab_third_party_with_aqua_produces_gitlab_prefix() {
        let mut def = make_tool("glab", Source::Gitlab, "1.91.0");
        def.repo = Some("gitlab-org/cli".to_string());
        def.aqua = Some("gitlab-org/cli".to_string());

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("\"gitlab:gitlab-org/cli\" = \"1.91.0\""),
            "expected gitlab: prefix entry, got:\n{output}"
        );
    }

    #[test]
    fn gitlab_third_party_without_aqua_produces_http() {
        let mut def = make_tool("some-gl-tool", Source::Gitlab, "2.0.0");
        def.repo = Some("some-org/some-tool".to_string());
        def.bin = Some("some-gl-tool".to_string());
        def.assets = HashMap::from([
            ("macos-arm64".to_string(), "some-gl-tool-darwin-arm64".to_string()),
            ("linux-x64".to_string(), "some-gl-tool-linux-amd64".to_string()),
        ]);

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("[tools.\"http:some-gl-tool\"]"),
            "expected http: subtable for third-party gitlab without aqua, got:\n{output}"
        );
    }

    #[test]
    fn settings_trusted_config_paths_from_config() {
        let mut config = test_config();
        config.settings.trusted_config_paths = vec![
            "~/projects".to_string(),
            "~/work".to_string(),
        ];

        let output = generate(&[], &config).unwrap();

        assert!(
            output.contains("[settings]"),
            "expected settings section, got:\n{output}"
        );
        assert!(
            output.contains("trusted_config_paths"),
            "expected trusted_config_paths in settings, got:\n{output}"
        );
        assert!(
            output.contains("~/projects"),
            "expected first path, got:\n{output}"
        );
        assert!(
            output.contains("~/work"),
            "expected second path, got:\n{output}"
        );
    }

    #[test]
    fn no_settings_section_when_no_trusted_paths() {
        let config = test_config();
        let output = generate(&[], &config).unwrap();

        assert!(
            !output.contains("[settings]"),
            "should not emit [settings] when no trusted paths, got:\n{output}"
        );
    }

    #[test]
    fn header_comment_present() {
        let output = generate(&[], &test_config()).unwrap();
        assert!(
            output.contains("# Managed by kit. Do not edit directly."),
            "expected header comment, got:\n{output}"
        );
    }

    /// S-3 enforcement: verify that no values are built via string interpolation.
    /// All values must go through toml_edit's API. We verify this structurally
    /// by parsing the output back and checking values are well-formed.
    #[test]
    fn output_is_valid_toml() {
        let mut gh = make_tool("gh", Source::Github, "2.89.0");
        gh.repo = Some("cli/cli".to_string());
        gh.aqua = Some("cli/cli".to_string());

        let mut muxr = make_tool("muxr", Source::Gitlab, "0.6.2");
        muxr.project_id = Some(80663080);
        muxr.bin = Some("muxr".to_string());
        muxr.assets = HashMap::from([
            ("macos-arm64".to_string(), "muxr-darwin-arm64".to_string()),
            ("linux-x64".to_string(), "muxr-linux-amd64".to_string()),
        ]);

        let mut cc = make_tool("claude-code", Source::Npm, "2.1.92");
        cc.package = Some("@anthropic-ai/claude-code".to_string());

        let tools = vec![resolved(gh), resolved(muxr), resolved(cc)];
        let mut config = test_config();
        config.settings.trusted_config_paths = vec!["~/projects".to_string()];

        let output = generate(&tools, &config).unwrap();

        // Parse it back -- if this succeeds, toml_edit produced valid TOML
        let parsed: DocumentMut = output.parse().expect("generated output must be valid TOML");

        // Verify specific values via the parsed document
        let tools_table = parsed["tools"].as_table().expect("tools should be a table");
        assert_eq!(
            tools_table["gh"].as_str(),
            Some("2.89.0"),
            "gh should be flat entry"
        );
        assert!(
            tools_table.contains_key("http:muxr"),
            "should have http:muxr subtable"
        );

        let muxr_table = tools_table["http:muxr"]
            .as_table()
            .expect("http:muxr should be a table");
        assert_eq!(muxr_table["version"].as_str(), Some("0.6.2"));
    }

    #[test]
    fn flat_entries_before_subtables() {
        let mut gh = make_tool("gh", Source::Github, "2.89.0");
        gh.repo = Some("cli/cli".to_string());
        gh.aqua = Some("cli/cli".to_string());

        let mut muxr = make_tool("muxr", Source::Gitlab, "0.6.2");
        muxr.project_id = Some(80663080);
        muxr.bin = Some("muxr".to_string());
        muxr.assets = HashMap::from([
            ("macos-arm64".to_string(), "muxr-darwin-arm64".to_string()),
            ("linux-x64".to_string(), "muxr-linux-amd64".to_string()),
        ]);

        let tools = vec![resolved(gh), resolved(muxr)];
        let output = generate(&tools, &test_config()).unwrap();

        // Flat entries should appear before subtable headers
        let flat_pos = output.find("gh = \"2.89.0\"").expect("should contain gh flat entry");
        let subtable_pos = output
            .find("[tools.\"http:muxr\"]")
            .expect("should contain http:muxr subtable");
        assert!(
            flat_pos < subtable_pos,
            "flat entries must come before subtables in output"
        );
    }

    #[test]
    fn direct_source_produces_http_backend() {
        let mut def = make_tool("custom-tool", Source::Direct, "3.0.0");
        def.bin = Some("custom-tool".to_string());
        def.assets = HashMap::from([
            (
                "macos-arm64".to_string(),
                "https://example.com/custom-tool-3.0.0-darwin-arm64".to_string(),
            ),
            (
                "linux-x64".to_string(),
                "https://example.com/custom-tool-3.0.0-linux-amd64".to_string(),
            ),
        ]);

        let tools = vec![resolved(def)];
        let output = generate(&tools, &test_config()).unwrap();

        assert!(
            output.contains("[tools.\"http:custom-tool\"]"),
            "expected http: subtable for direct source, got:\n{output}"
        );
        assert!(
            output.contains("https://example.com/custom-tool-3.0.0-darwin-arm64"),
            "expected direct URL in output, got:\n{output}"
        );
    }
}
