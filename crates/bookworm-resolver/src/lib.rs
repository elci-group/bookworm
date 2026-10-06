//! Target resolution (directive §5): establish exactly what exists, without
//! inference. Filesystem facts, symlink chains, permissions, encoding sniff,
//! Git repository identity, and structural inventories for directories.

use bookworm_classify::{language_for_path, path_flags, Language};
use bookworm_core::{sniff_encoding, Encoding, Error, Result, SNIFF_WINDOW};
use bookworm_policy::ScopePolicy;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Directory,
    Other,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetKind::File => "file",
            TargetKind::Directory => "directory",
            TargetKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoContext {
    pub root: PathBuf,
    /// `None` for a repository with an unborn HEAD.
    pub revision: Option<String>,
    pub branch: Option<String>,
    /// True when `git status --porcelain` reports any entry (including
    /// untracked files). Conservative: evidence from a dirty tree is marked.
    pub dirty: bool,
    pub dirty_samples: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTarget {
    pub requested: PathBuf,
    pub canonical: PathBuf,
    /// Symlink destinations, outermost first, as far as readable.
    pub symlink_chain: Vec<String>,
    pub kind: TargetKind,
    pub permissions: Permissions,
    pub size_bytes: u64,
    pub encoding: Option<Encoding>,
    pub extension: Option<String>,
    pub language: Option<Language>,
    pub generated: bool,
    pub vendored: bool,
    pub repository: Option<RepoContext>,
}

/// Resolve a filesystem target through the scope policy. For files, the
/// encoding is sniffed over the first [`SNIFF_WINDOW`] bytes; directories
/// carry no encoding.
pub fn resolve(path: &Path, scope: &ScopePolicy) -> Result<ResolvedTarget> {
    let canonical = scope.authorize_read(path)?;
    let meta = fs::metadata(&canonical).map_err(|e| Error::io(&canonical, e))?;
    let kind = if meta.is_dir() {
        TargetKind::Directory
    } else if meta.is_file() {
        TargetKind::File
    } else {
        TargetKind::Other
    };

    let symlink_chain = follow_symlinks(path);

    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        Permissions {
            readable: mode & 0o444 != 0,
            writable: mode & 0o222 != 0,
            executable: mode & 0o111 != 0,
        }
    };
    #[cfg(not(unix))]
    let permissions = Permissions {
        readable: true,
        writable: false,
        executable: false,
    };

    let size_bytes = if kind == TargetKind::Directory {
        0
    } else {
        meta.len()
    };

    let (encoding, extension) = if kind == TargetKind::File {
        (
            Some(sniff_head(&canonical)?),
            path.extension().map(|e| e.to_string_lossy().to_string()),
        )
    } else {
        (None, None)
    };

    let language = language_for_path(&canonical);
    let (generated, vendored) = path_flags(&canonical);
    let repository = repo_context(&canonical);

    Ok(ResolvedTarget {
        requested: path.to_path_buf(),
        canonical,
        symlink_chain,
        kind,
        permissions,
        size_bytes,
        encoding,
        extension,
        language,
        generated,
        vendored,
        repository,
    })
}

fn sniff_head(path: &Path) -> Result<Encoding> {
    let mut file = fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied {
            path: path.to_path_buf(),
        },
        _ => Error::io(path, e),
    })?;
    let mut head = vec![0u8; SNIFF_WINDOW];
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(Error::io(path, e)),
        }
    }
    head.truncate(filled);
    Ok(sniff_encoding(&head))
}

fn follow_symlinks(path: &Path) -> Vec<String> {
    let mut chain = Vec::new();
    let mut cur = path.to_path_buf();
    // A hard cap guards against symlink loops; canonicalize already proved
    // the final target exists.
    for _ in 0..32 {
        match fs::read_link(&cur) {
            Ok(dest) => {
                chain.push(dest.to_string_lossy().into_owned());
                let next = if dest.is_absolute() {
                    dest
                } else {
                    cur.parent().unwrap_or(Path::new(".")).join(dest)
                };
                cur = next;
            }
            Err(_) => break,
        }
    }
    chain
}

/// True when the `git` binary is usable at all (used by `doctor`).
pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Repository identity for a path inside a Git work tree, or `None` when the
/// path is not inside a repository (or `git` is unavailable — reported by
/// `doctor` rather than failing every read).
pub fn repo_context(path: &Path) -> Option<RepoContext> {
    // `git -C` requires a directory; resolve a file target to its parent.
    let dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().map(Path::to_path_buf)?
    };
    let root = git(&dir, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root);
    let revision = git(&root, &["rev-parse", "HEAD"]);
    let branch = git(&root, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let status = git(&root, &["status", "--porcelain"]);
    let dirty = status.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    let dirty_samples = status
        .map(|s| s.lines().take(5).map(str::to_string).collect())
        .unwrap_or_default();
    Some(RepoContext {
        root,
        revision,
        branch,
        dirty,
        dirty_samples,
    })
}

// ---------------------------------------------------------------------------
// Structural inventory (§5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryKind {
    Manifest,
    Lockfile,
    SourceRoot,
    TestRoot,
    FixtureRoot,
    Documentation,
    Ci,
    Configuration,
    BuildScript,
    VendoredDir,
    GeneratedDir,
    Vcs,
    EntryPoint,
    Other,
}

impl InventoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            InventoryKind::Manifest => "manifest",
            InventoryKind::Lockfile => "lockfile",
            InventoryKind::SourceRoot => "source_root",
            InventoryKind::TestRoot => "test_root",
            InventoryKind::FixtureRoot => "fixture_root",
            InventoryKind::Documentation => "documentation",
            InventoryKind::Ci => "ci",
            InventoryKind::Configuration => "configuration",
            InventoryKind::BuildScript => "build_script",
            InventoryKind::VendoredDir => "vendored_dir",
            InventoryKind::GeneratedDir => "generated_dir",
            InventoryKind::Vcs => "vcs",
            InventoryKind::EntryPoint => "entry_point",
            InventoryKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Path relative to the inventory root. Directories end with `/`.
    pub path: String,
    pub kind: InventoryKind,
    pub size_bytes: u64,
    pub generated: bool,
    pub vendored: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Inventory {
    pub root: PathBuf,
    pub entries: Vec<InventoryEntry>,
    pub files_total: u64,
    pub bytes_total: u64,
    pub max_depth: usize,
    /// Honest scope notes: what the inventory did not cover (§17).
    pub omissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InventoryOptions {
    pub max_depth: usize,
    pub include_generated: bool,
    pub include_vendored: bool,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        InventoryOptions {
            max_depth: 3,
            include_generated: false,
            include_vendored: false,
        }
    }
}

const VENDORED_DIR_NAMES: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "vendored",
];
const GENERATED_DIR_NAMES: &[&str] = &["target", "dist", "build", "out", "__pycache__", ".next"];

fn is_vendored_component(name: &str) -> bool {
    VENDORED_DIR_NAMES.contains(&name)
}

fn is_generated_component(name: &str) -> bool {
    GENERATED_DIR_NAMES.contains(&name)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn classify_dir_entry(path: &Path, depth: usize) -> InventoryKind {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    if name == ".git" {
        return InventoryKind::Vcs;
    }
    if is_vendored_component(&name) {
        return InventoryKind::VendoredDir;
    }
    if is_generated_component(&name) {
        return InventoryKind::GeneratedDir;
    }
    if depth == 1 {
        return match name.as_str() {
            "src" | "lib" | "source" => InventoryKind::SourceRoot,
            "tests" | "test" | "spec" | "e2e" => InventoryKind::TestRoot,
            "fixtures" | "testdata" | "__fixtures__" => InventoryKind::FixtureRoot,
            "docs" | "doc" | "documentation" => InventoryKind::Documentation,
            ".github" | ".gitlab" | ".circleci" => InventoryKind::Ci,
            "scripts" | "script" | "tools" | "build-tools" => InventoryKind::BuildScript,
            "config" | "etc" | "conf" => InventoryKind::Configuration,
            _ => InventoryKind::Other,
        };
    }
    InventoryKind::Other
}

fn classify_file_entry(path: &Path) -> InventoryKind {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    match name.as_str() {
        "cargo.toml" | "package.json" | "go.mod" | "pyproject.toml" | "gemfile" => {
            return InventoryKind::Manifest
        }
        "dockerfile" | "makefile" | "justfile" | ".gitignore" | ".env" => {
            return InventoryKind::Configuration
        }
        _ => {}
    }
    if name.ends_with(".lock")
        || matches!(
            name.as_str(),
            "cargo.lock"
                | "package-lock.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "poetry.lock"
                | "go.sum"
        )
    {
        return InventoryKind::Lockfile;
    }
    if name.ends_with(".yml") || name.ends_with(".yaml") {
        let in_ci_dir = path
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some(".github") | Some(".gitlab")));
        if in_ci_dir {
            return InventoryKind::Ci;
        }
    }
    // Entry points: conventional roots directly under a source directory.
    let parent_is_src = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case("src"))
        .unwrap_or(false);
    if parent_is_src
        && matches!(
            name.as_str(),
            "main.rs" | "lib.rs" | "mod.rs" | "index.ts" | "index.js" | "__init__.py" | "main.py"
        )
    {
        return InventoryKind::EntryPoint;
    }
    InventoryKind::Other
}

/// Construct a structural inventory of a directory. Remains inference-free
/// (§5): name and path conventions only. `.git` internals are never entered;
/// generated and vendored subtrees are collapsed to a single marker entry
/// unless explicitly included, and every such decision is recorded as an
/// omission so coverage stays honest (§17).
pub fn inventory(root: &Path, opts: &InventoryOptions) -> Result<Inventory> {
    let canonical = fs::canonicalize(root).map_err(|_| Error::TargetMissing {
        path: root.to_path_buf(),
    })?;

    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    let mut files_total = 0u64;
    let mut bytes_total = 0u64;
    let mut reached_depth_limit = false;

    let filter_root = canonical.clone();
    let walker = WalkDir::new(&canonical)
        .min_depth(1)
        .max_depth(opts.max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(move |e| {
            if e.depth() == 0 {
                return true;
            }
            match e.path().strip_prefix(&filter_root) {
                Ok(rel) => rel.components().all(|c| c.as_os_str() != ".git"),
                Err(_) => true,
            }
        });

    for entry in walker {
        let entry = entry.map_err(|e| Error::io(&canonical, std::io::Error::other(e)))?;
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        let rel = relative(&canonical, path);
        let depth = entry.depth();
        let is_dir = entry.file_type().is_dir();

        // Collapse generated/vendored subtrees: children under a collapsed
        // marker directory are skipped; the marker itself is still recorded.
        // Membership is judged by the entry's parent path so the marker
        // directory survives.
        let parent_rel = path
            .parent()
            .map(|p| relative(&canonical, p))
            .unwrap_or_default();
        let under_collapsed = parent_rel.split('/').any(|c| {
            let c = c.to_ascii_lowercase();
            (is_vendored_component(&c) && !opts.include_vendored)
                || (is_generated_component(&c) && !opts.include_generated)
        });

        if under_collapsed {
            continue;
        }

        if is_dir && depth == opts.max_depth {
            reached_depth_limit = true;
        }

        if is_dir {
            let kind = classify_dir_entry(path, depth);
            if kind == InventoryKind::VendoredDir && !opts.include_vendored {
                omissions.push(format!("vendored subtree collapsed: {rel}/"));
            }
            if kind == InventoryKind::GeneratedDir && !opts.include_generated {
                omissions.push(format!("generated subtree collapsed: {rel}/"));
            }
            entries.push(InventoryEntry {
                path: format!("{rel}/"),
                generated: kind == InventoryKind::GeneratedDir,
                vendored: kind == InventoryKind::VendoredDir,
                kind,
                size_bytes: 0,
            });
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        files_total += 1;
        bytes_total += size;
        let (g, v) = path_flags(path);
        entries.push(InventoryEntry {
            path: rel,
            kind: classify_file_entry(path),
            size_bytes: size,
            generated: g,
            vendored: v,
        });
    }

    if canonical.join(".git").exists() {
        omissions.push(".git internals not traversed".to_string());
    }
    if reached_depth_limit {
        omissions.push(format!(
            "depth-limited at {} levels (structurally exhaustive within depth)",
            opts.max_depth
        ));
    }

    Ok(Inventory {
        root: canonical,
        entries,
        files_total,
        bytes_total,
        max_depth: opts.max_depth,
        omissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn resolves_file_facts() {
        let dir = scratch();
        let file = dir.path().join("x.rs");
        fs::write(&file, b"fn f() {}").unwrap();
        let resolved = resolve(&file, &ScopePolicy::unrestricted()).unwrap();
        assert_eq!(resolved.kind, TargetKind::File);
        assert_eq!(resolved.encoding, Some(Encoding::Utf8));
        assert_eq!(resolved.language, Some(Language::Rust));
        assert_eq!(resolved.size_bytes, 9);
    }

    #[test]
    fn resolves_directory() {
        let dir = scratch();
        let resolved = resolve(dir.path(), &ScopePolicy::unrestricted()).unwrap();
        assert_eq!(resolved.kind, TargetKind::Directory);
        assert_eq!(resolved.encoding, None);
    }

    #[test]
    fn missing_target_fails_closed() {
        let err = resolve(
            Path::new("/nonexistent/bw-missing"),
            &ScopePolicy::unrestricted(),
        );
        assert!(matches!(err, Err(Error::TargetMissing { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn records_symlink_chain() {
        let dir = scratch();
        let real = dir.path().join("real.txt");
        fs::write(&real, b"content").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let resolved = resolve(&link, &ScopePolicy::unrestricted()).unwrap();
        assert_eq!(resolved.symlink_chain.len(), 1);
        assert!(resolved.symlink_chain[0].contains("real.txt"));
        assert_eq!(resolved.canonical, real);
    }

    #[test]
    fn inventory_classifies_structure() {
        let dir = scratch();
        let root = dir.path().join("repo");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::create_dir_all(root.join("vendor/dep")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("Cargo.toml"), b"[package]\nname = 'x'\n").unwrap();
        fs::write(root.join("Cargo.lock"), b"[]").unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join("tests/it.rs"), b"#[test] fn t() {}").unwrap();
        fs::write(root.join("docs/guide.md"), b"# guide").unwrap();
        fs::write(root.join("vendor/dep/a.c"), b"int a;").unwrap();
        fs::write(root.join("target/debug/x.rs"), b"fn x() {}").unwrap();

        let inv = inventory(&root, &InventoryOptions::default()).unwrap();
        let kind_of = |p: &str| {
            inv.entries
                .iter()
                .find(|e| e.path == p)
                .map(|e| e.kind.clone())
                .unwrap_or(InventoryKind::Other)
        };
        assert_eq!(kind_of("Cargo.toml"), InventoryKind::Manifest);
        assert_eq!(kind_of("Cargo.lock"), InventoryKind::Lockfile);
        assert_eq!(kind_of("src/"), InventoryKind::SourceRoot);
        assert_eq!(kind_of("src/main.rs"), InventoryKind::EntryPoint);
        assert_eq!(kind_of("tests/"), InventoryKind::TestRoot);
        assert_eq!(kind_of("docs/"), InventoryKind::Documentation);
        assert_eq!(kind_of("vendor/"), InventoryKind::VendoredDir);
        assert_eq!(kind_of("target/"), InventoryKind::GeneratedDir);

        // .git internals never appear; collapsed subtrees are acknowledged.
        assert!(!inv.entries.iter().any(|e| e.path.starts_with(".git")));
        assert!(inv
            .omissions
            .iter()
            .any(|o| o.contains("vendored subtree collapsed")));
        assert!(inv
            .omissions
            .iter()
            .any(|o| o.contains("generated subtree collapsed")));
        assert!(inv.omissions.iter().any(|o| o.contains(".git internals")));
        // Marker directories exist, but their contents were not listed.
        assert!(!inv.entries.iter().any(|e| e.path == "vendor/dep/"));
    }

    #[test]
    fn inventory_can_include_collapsed_subtrees() {
        let dir = scratch();
        let root = dir.path().join("repo");
        fs::create_dir_all(root.join("vendor/dep")).unwrap();
        fs::write(root.join("vendor/dep/a.c"), b"int a;").unwrap();
        let opts = InventoryOptions {
            include_vendored: true,
            ..Default::default()
        };
        let inv = inventory(&root, &opts).unwrap();
        assert!(inv.entries.iter().any(|e| e.path == "vendor/dep/a.c"));
        assert!(!inv
            .omissions
            .iter()
            .any(|o| o.contains("vendored subtree collapsed")));
    }

    #[test]
    fn inventory_respects_depth_limit_and_reports_it() {
        let dir = scratch();
        let root = dir.path().join("deep");
        fs::create_dir_all(root.join("a/b/c/d")).unwrap();
        fs::write(root.join("a/b/c/d/leaf.txt"), b"leaf").unwrap();
        let inv = inventory(
            &root,
            &InventoryOptions {
                max_depth: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!inv.entries.iter().any(|e| e.path.contains("d/")));
        assert!(inv.omissions.iter().any(|o| o.starts_with("depth-limited")));
    }

    #[test]
    fn repo_context_none_outside_repo() {
        if !git_available() {
            return;
        }
        let dir = scratch();
        assert!(repo_context(dir.path()).is_none());
    }

    #[test]
    fn repo_context_reads_identity_when_git_present() {
        if !git_available() {
            return; // environment without git: skip, not fail
        }
        let dir = scratch();
        let root = dir.path().join("r");
        fs::create_dir_all(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.email", "t@t"]);
        run_git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("f.txt"), b"x").unwrap();
        run_git(&root, &["add", "."]);
        run_git(&root, &["commit", "-q", "-m", "init"]);

        let ctx = repo_context(&root).expect("repo context");
        assert!(ctx.revision.is_some());
        assert!(!ctx.dirty);

        // Regression: detection must also work when handed a *file* path.
        let via_file = repo_context(&root.join("f.txt")).expect("repo context via file");
        assert_eq!(via_file.root, ctx.root);
        assert_eq!(via_file.revision, ctx.revision);

        fs::write(root.join("f.txt"), b"changed").unwrap();
        let ctx = repo_context(&root).expect("repo context");
        assert!(ctx.dirty);
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
}
