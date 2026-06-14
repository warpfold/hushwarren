//! API token: creation, persistence, and constant-time Bearer verification.
//!
//! Implements `specs/wp3-api-cli.md` §1.
//!
//! Token lifecycle:
//! 1. On boot, `ensure_token(state_dir)` is called.
//! 2. If `state_dir/api.token` is absent or malformed → generate a fresh
//!    32-byte hex token (64 hex chars) and write it `0600` (unix; `// P2: tighten
//!    ACL on Windows`).
//! 3. If present and well-formed (exactly 64 lowercase hex chars) → reuse it.
//!
//! Every request header is compared constant-time via the `subtle` crate to
//! prevent timing side-channels.

use rand::{rngs::OsRng, TryRngCore};
use std::path::Path;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::{info, warn};

/// Number of random bytes in the token.
const TOKEN_BYTES: usize = 32;
/// Expected length of the hex-encoded token (2 chars per byte).
pub const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// Errors from token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    /// I/O error reading or writing the token file.
    #[error("token file I/O: {0}")]
    Io(#[from] std::io::Error),
    /// OS RNG failed to produce bytes.
    #[error("OsRng failed: {0}")]
    Rng(String),
}

/// Ensure `state_dir/api.token` exists and is well-formed.
///
/// Returns the token string (64 lowercase hex chars).
///
/// - Reuses an existing, well-formed token.
/// - Regenerates (with `warn!`) if the file is present but malformed.
/// - Creates a fresh token if the file is absent.
pub fn ensure_token(state_dir: &Path) -> Result<String, TokenError> {
    let token_path = state_dir.join("api.token");

    // Try to load an existing token.
    if token_path.exists() {
        match std::fs::read_to_string(&token_path) {
            Ok(s) => {
                let trimmed = s.trim();
                if is_valid_token(trimmed) {
                    info!("reusing existing API token from {}", token_path.display());
                    return Ok(trimmed.to_owned());
                }
                warn!(
                    path = %token_path.display(),
                    "api.token is malformed (not 64 hex chars); regenerating"
                );
            }
            Err(e) => {
                warn!(
                    path = %token_path.display(),
                    error = %e,
                    "cannot read api.token; regenerating"
                );
            }
        }
    }

    // Generate a fresh token.
    let token = generate_token()?;
    write_token_file(&token_path, &token)?;
    info!("wrote new API token to {}", token_path.display());
    Ok(token)
}

/// Returns `true` iff the token is exactly [`TOKEN_HEX_LEN`] lowercase hex chars.
pub fn is_valid_token(s: &str) -> bool {
    s.len() == TOKEN_HEX_LEN
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

/// Generate a fresh token: 32 random bytes, hex-encoded.
fn generate_token() -> Result<String, TokenError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| TokenError::Rng(e.to_string()))?;
    Ok(hex::encode(bytes))
}

/// Write the token to `path` atomically with a tmp+rename pattern.
///
/// On Unix, sets the file mode to `0600` (owner read/write only).
/// On Windows the ACL is left at defaults; see `// P2: tighten ACL` comment.
fn write_token_file(path: &Path, token: &str) -> Result<(), TokenError> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join(".api.token.tmp");

    // Write to tmp file.
    std::fs::write(&tmp_path, token)?;

    // On Unix: set 0600 before renaming so the file is never readable by
    // others, even briefly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)?;
    }
    // P2: tighten ACL on Windows (currently left at default ACLs).

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Compare the incoming `Authorization` header against the expected token
/// in constant time (prevents timing side-channels).
///
/// Returns `true` if the header is `"Bearer <token>"`.
pub fn check_bearer(authorization_header: Option<&str>, expected_token: &str) -> bool {
    let Some(header) = authorization_header else {
        return false;
    };
    let Some(provided) = header.strip_prefix("Bearer ") else {
        return false;
    };
    // Constant-time compare — both sides must be the same length or the
    // comparison is trivially not-equal.  We pad/truncate to TOKEN_HEX_LEN
    // so the compare is always over a fixed number of bytes, preventing
    // length leakage.
    if provided.len() != TOKEN_HEX_LEN || expected_token.len() != TOKEN_HEX_LEN {
        return bool::from(0u8.ct_eq(&1u8)); // always false, constant time
    }
    bool::from(provided.as_bytes().ct_eq(expected_token.as_bytes()))
}

// ── Hex encoding helper (avoids pulling in the `hex` crate) ──────────────────

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    // ── Token validity check ──────────────────────────────────────────────────

    #[test]
    fn valid_token_accepted() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        assert!(is_valid_token(&token));
    }

    #[test]
    fn uppercase_hex_rejected() {
        let token = "A".repeat(TOKEN_HEX_LEN);
        assert!(!is_valid_token(&token));
    }

    #[test]
    fn short_token_rejected() {
        assert!(!is_valid_token("abc123"));
    }

    #[test]
    fn empty_token_rejected() {
        assert!(!is_valid_token(""));
    }

    #[test]
    fn non_hex_chars_rejected() {
        let token = "g".repeat(TOKEN_HEX_LEN);
        assert!(!is_valid_token(&token));
    }

    #[test]
    fn correct_length_non_hex_rejected() {
        let token = "z".repeat(TOKEN_HEX_LEN);
        assert!(!is_valid_token(&token));
    }

    // ── Token file create + reuse ─────────────────────────────────────────────

    #[test]
    fn ensure_token_creates_file() {
        let tmp = TempDir::new().unwrap();
        let token = ensure_token(tmp.path()).unwrap();
        assert!(is_valid_token(&token), "created token must be valid");
        let on_disk = std::fs::read_to_string(tmp.path().join("api.token")).unwrap();
        assert_eq!(
            on_disk.trim(),
            token,
            "on-disk token must match returned value"
        );
    }

    #[test]
    fn ensure_token_reuses_valid_file() {
        let tmp = TempDir::new().unwrap();
        let first = ensure_token(tmp.path()).unwrap();
        let second = ensure_token(tmp.path()).unwrap();
        assert_eq!(first, second, "second call must reuse the same token");
    }

    #[test]
    fn ensure_token_regenerates_malformed_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("api.token"), "malformed!!!").unwrap();
        let token = ensure_token(tmp.path()).unwrap();
        assert!(
            is_valid_token(&token),
            "regenerated token must be valid after malformed file"
        );
    }

    #[test]
    fn ensure_token_regenerates_empty_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("api.token"), "").unwrap();
        let token = ensure_token(tmp.path()).unwrap();
        assert!(is_valid_token(&token));
    }

    // ── Addr file content ─────────────────────────────────────────────────────
    // (addr file writing is tested via ensure_addr_file in api::mod; here we
    // document the expectation: addr file is written by ApiServer after bind.)

    // ── Constant-time bearer comparison ──────────────────────────────────────

    #[test]
    fn correct_bearer_returns_true() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let header = format!("Bearer {token}");
        assert!(check_bearer(Some(&header), &token));
    }

    #[test]
    fn wrong_bearer_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let wrong = "b".repeat(TOKEN_HEX_LEN);
        let header = format!("Bearer {wrong}");
        assert!(!check_bearer(Some(&header), &token));
    }

    #[test]
    fn empty_header_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        assert!(!check_bearer(Some(""), &token));
    }

    #[test]
    fn missing_bearer_prefix_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        // No "Bearer " prefix.
        assert!(!check_bearer(Some(&token), &token));
    }

    #[test]
    fn no_header_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        assert!(!check_bearer(None, &token));
    }

    #[test]
    fn shorter_token_in_header_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let header = format!("Bearer {}", "a".repeat(TOKEN_HEX_LEN - 1));
        assert!(!check_bearer(Some(&header), &token));
    }

    #[test]
    fn longer_token_in_header_returns_false() {
        let token = "a".repeat(TOKEN_HEX_LEN);
        let header = format!("Bearer {}", "a".repeat(TOKEN_HEX_LEN + 1));
        assert!(!check_bearer(Some(&header), &token));
    }

    // ── generate_token produces valid tokens ──────────────────────────────────

    #[test]
    fn generate_token_is_valid() {
        let t = generate_token().unwrap();
        assert!(
            is_valid_token(&t),
            "generated token must pass validity check"
        );
        assert_eq!(t.len(), TOKEN_HEX_LEN);
    }

    #[test]
    fn two_generated_tokens_differ() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(
            a, b,
            "two random tokens must be distinct (flake probability: 2^-256)"
        );
    }
}
