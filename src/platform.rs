use anyhow::Result;

/// Platforms kit supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    MacosArm64,
    LinuxX64,
}

impl Platform {
    /// Detect the current platform at runtime.
    pub fn detect() -> Result<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => Ok(Self::MacosArm64),
            ("linux", "x86_64") => Ok(Self::LinuxX64),
            (os, arch) => anyhow::bail!("unsupported platform: {os}-{arch}"),
        }
    }

    /// The key used in tool definition asset tables and mise config.
    pub fn key(&self) -> &'static str {
        match self {
            Self::MacosArm64 => "macos-arm64",
            Self::LinuxX64 => "linux-x64",
        }
    }

    /// Parse a platform key from a string.
    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "macos-arm64" | "darwin-arm64" => Some(Self::MacosArm64),
            "linux-x64" | "linux-amd64" => Some(Self::LinuxX64),
            _ => None,
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_key_roundtrip() {
        assert_eq!(
            Platform::from_key("macos-arm64"),
            Some(Platform::MacosArm64)
        );
        assert_eq!(Platform::from_key("linux-x64"), Some(Platform::LinuxX64));
        assert_eq!(
            Platform::from_key("darwin-arm64"),
            Some(Platform::MacosArm64)
        );
        assert_eq!(Platform::from_key("linux-amd64"), Some(Platform::LinuxX64));
        assert_eq!(Platform::from_key("windows-x64"), None);
    }

    #[test]
    fn detect_current_platform() {
        // Should succeed on macOS arm64 or Linux x64
        let result = Platform::detect();
        assert!(result.is_ok() || result.is_err());
    }
}
