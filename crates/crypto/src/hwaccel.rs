//! Hardware acceleration detection and feature flags.
//!
//! Detects CPU features at runtime to enable optimized cryptographic implementations.
//! Supports x86_64 (SHA-NI, AVX2, SSE4.1) and AArch64 (SHA2) extensions.

use std::sync::OnceLock;

/// Detected hardware capabilities for SHA-256 acceleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Capabilities {
    /// x86: SHA-NI (Intel SHA Extensions) is available
    pub sha_ni: bool,
    /// x86: AVX2 is available (for 8-way parallel hashing)
    pub avx2: bool,
    /// x86: SSE4.1 is available (for 4-way parallel hashing)
    pub sse41: bool,
    /// AArch64: SHA2 instructions are available
    pub arm_sha2: bool,
}

impl Sha256Capabilities {
    /// Detects CPU capabilities at runtime.
    #[cfg(target_arch = "x86_64")]
    pub fn detect() -> Self {
        Self {
            sha_ni: std::arch::is_x86_feature_detected!("sha"),
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            sse41: std::arch::is_x86_feature_detected!("sse4.1"),
            arm_sha2: false,
        }
    }

    /// Detects CPU capabilities at runtime.
    #[cfg(target_arch = "aarch64")]
    pub fn detect() -> Self {
        Self {
            sha_ni: false,
            avx2: false,
            sse41: false,
            arm_sha2: std::arch::is_aarch64_feature_detected!("sha2"),
        }
    }

    /// Fallback for other architectures.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn detect() -> Self {
        Self {
            sha_ni: false,
            avx2: false,
            sse41: false,
            arm_sha2: false,
        }
    }

    /// Returns true if any hardware acceleration is available.
    pub fn has_acceleration(&self) -> bool {
        self.sha_ni || self.avx2 || self.sse41 || self.arm_sha2
    }

    /// Returns a human-readable description of available capabilities.
    pub fn description(&self) -> String {
        let mut features = Vec::new();

        if self.sha_ni {
            features.push("sha-ni");
        }
        if self.avx2 {
            features.push("avx2");
        }
        if self.sse41 {
            features.push("sse4.1");
        }
        if self.arm_sha2 {
            features.push("arm-sha2");
        }

        if features.is_empty() {
            "portable".to_string()
        } else {
            features.join(";")
        }
    }
}

/// Global cached capabilities, detected once on first access.
static CAPABILITIES: OnceLock<Sha256Capabilities> = OnceLock::new();

/// Returns the detected SHA-256 capabilities for this CPU.
/// The detection is performed once and cached.
pub fn sha256_capabilities() -> &'static Sha256Capabilities {
    CAPABILITIES.get_or_init(Sha256Capabilities::detect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_detection() {
        let caps = sha256_capabilities();
        // Should not panic and should return consistent results
        let caps2 = sha256_capabilities();
        assert_eq!(caps, caps2);
    }

    #[test]
    fn test_description() {
        let caps = Sha256Capabilities {
            sha_ni: false,
            avx2: false,
            sse41: false,
            arm_sha2: false,
        };
        assert_eq!(caps.description(), "portable");

        let caps = Sha256Capabilities {
            sha_ni: true,
            avx2: true,
            sse41: true,
            arm_sha2: false,
        };
        assert_eq!(caps.description(), "sha-ni;avx2;sse4.1");
    }
}
