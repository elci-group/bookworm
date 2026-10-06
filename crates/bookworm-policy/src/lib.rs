//! Filesystem scope enforcement and the read-only acquisition posture
//! (directive §4: "Bookworm itself SHOULD be read-only by default"; §19).

use bookworm_core::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Bookworm v1 performs no writes anywhere except its own cache directory.
/// This constant is reported by `bookworm doctor` as the acquisition posture.
pub const READ_ONLY: bool = true;

/// Filesystem scope policy. When roots are configured, every read must
/// canonicalize inside one of them; symlink chains are resolved *before* the
/// scope check so traversal cannot escape an authorised root via a symlink
/// (§19: "prevent path traversal outside authorised roots").
///
/// With no roots configured the policy is self-scoped: any explicit target is
/// authorised, which matches the CLI default where the user names the target
/// directly. Server deployments (§24) must always configure roots.
#[derive(Debug, Clone, Default)]
pub struct ScopePolicy {
    allowed_roots: Vec<PathBuf>,
}

impl ScopePolicy {
    /// Self-scoped policy: the user's explicit target defines the scope.
    pub fn unrestricted() -> Self {
        ScopePolicy {
            allowed_roots: Vec::new(),
        }
    }

    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        ScopePolicy {
            allowed_roots: roots,
        }
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.allowed_roots
    }

    /// Authorize a read of `path`, returning its canonical path. Fails closed
    /// with `TargetMissing` / `PermissionDenied` / `OutsideScope`.
    pub fn authorize_read(&self, path: &Path) -> Result<PathBuf> {
        let canonical = fs::canonicalize(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::TargetMissing {
                path: path.to_path_buf(),
            },
            std::io::ErrorKind::PermissionDenied => Error::PermissionDenied {
                path: path.to_path_buf(),
            },
            _ => Error::io(path, e),
        })?;

        if self.allowed_roots.is_empty() {
            return Ok(canonical);
        }

        for root in &self.allowed_roots {
            let canonical_root = fs::canonicalize(root).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::TargetMissing { path: root.clone() },
                _ => Error::io(root, e),
            })?;
            if canonical.starts_with(&canonical_root) {
                return Ok(canonical);
            }
        }
        Err(Error::OutsideScope {
            path: canonical,
            root: self.allowed_roots[0].clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizes_inside_root() {
        let dir = tempfile_dir();
        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        let policy = ScopePolicy::with_roots(vec![dir.path().to_path_buf()]);
        let ok = policy.authorize_read(&file).unwrap();
        assert!(ok.ends_with("a.txt"));
    }

    #[test]
    fn rejects_outside_root() {
        let dir = tempfile_dir();
        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        let other = tempfile_dir();
        let policy = ScopePolicy::with_roots(vec![other.path().to_path_buf()]);
        assert!(matches!(
            policy.authorize_read(&file),
            Err(Error::OutsideScope { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_resolved_before_check() {
        let inner = tempfile_dir();
        let secret = inner.path().join("secret.txt");
        fs::write(&secret, b"s").unwrap();

        let scope = tempfile_dir();
        let policy = ScopePolicy::with_roots(vec![scope.path().to_path_buf()]);
        let link = scope.path().join("escape");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(matches!(
            policy.authorize_read(&link),
            Err(Error::OutsideScope { .. })
        ));
    }

    #[test]
    fn missing_target_fails_closed() {
        let policy = ScopePolicy::unrestricted();
        assert!(matches!(
            policy.authorize_read(Path::new("/nonexistent/definitely-missing-xyz")),
            Err(Error::TargetMissing { .. })
        ));
    }

    fn tempfile_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
}
