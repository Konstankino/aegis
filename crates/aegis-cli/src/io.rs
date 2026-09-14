//! Local-file I/O for the policy dir — the enforced boundary of everything the tool can touch.
//!
//! Every read/write goes through [`PolicyDir`], which joins a **constant** artifact basename to the
//! chosen dir and refuses to resolve anything outside it. There is no code path that writes an
//! arbitrary path, a `*.tf`, `Cargo.toml`, source, or a remote target — by construction.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::artifacts::Artifact;

/// The policy directory the tool operates on. The single root under which all reads/writes happen.
#[derive(Debug, Clone)]
pub struct PolicyDir {
    root: PathBuf,
}

/// What a write did (or would do, under `--dry-run`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The file was written (or created).
    Wrote,
    /// `--dry-run`: nothing was written; carries the unified diff for display.
    DryRun(String),
    /// The new contents were identical to what's on disk; nothing written.
    Unchanged,
}

impl PolicyDir {
    /// Construct a policy dir rooted at `root`. The path is used verbatim as the boundary; only the
    /// known [`Artifact`] basenames are ever joined to it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// A **tenant-scoped** policy dir: artifacts live under `<root>/tenants/<tenant>/` (Roadmap T1),
    /// so each tenant has its own `tools.json`/`broker.cedar`/`grants.toml`/… The tenant is validated
    /// as a slug and rejected if it is `.`/`..`, so it is a safe single path segment (no traversal).
    pub fn for_tenant(root: impl Into<PathBuf>, tenant: &str) -> Result<Self> {
        aegis_core::TenantId::new(tenant).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if tenant == "." || tenant == ".." {
            bail!("invalid tenant path segment '{tenant}'");
        }
        Ok(Self {
            root: root.into().join("tenants").join(tenant),
        })
    }

    /// The directory root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The absolute path of an artifact inside this dir. Guaranteed to stay within `root`: the
    /// basename is a compile-time constant with no separators or `..` (see `Artifact`).
    pub fn resolve(&self, artifact: Artifact) -> PathBuf {
        self.root.join(artifact.filename())
    }

    /// The path of an artifact's `.example.*` twin.
    pub fn resolve_example(&self, artifact: Artifact) -> PathBuf {
        self.root.join(artifact.example_filename())
    }

    /// Read an artifact's contents, or `None` if the file does not exist.
    pub fn read(&self, artifact: Artifact) -> Result<Option<String>> {
        read_opt(&self.resolve(artifact))
    }

    /// Read an artifact's `.example.*` twin, or `None` if absent.
    pub fn read_example(&self, artifact: Artifact) -> Result<Option<String>> {
        read_opt(&self.resolve_example(artifact))
    }

    /// Whether the live artifact file exists.
    pub fn exists(&self, artifact: Artifact) -> bool {
        self.resolve(artifact).is_file()
    }

    /// Atomically write `contents` to an artifact. Honors `dry_run` (returns the diff, writes
    /// nothing) and skips no-op writes. The caller is responsible for having *validated* `contents`
    /// first — this only handles durability, not correctness.
    pub fn write(&self, artifact: Artifact, contents: &str, dry_run: bool) -> Result<WriteOutcome> {
        let path = self.resolve(artifact);
        let current = read_opt(&path)?;
        if current.as_deref() == Some(contents) {
            return Ok(WriteOutcome::Unchanged);
        }
        if dry_run {
            let diff = unified_diff(
                current.as_deref().unwrap_or(""),
                contents,
                artifact.filename(),
            );
            return Ok(WriteOutcome::DryRun(diff));
        }
        write_atomic(&path, contents)?;
        Ok(WriteOutcome::Wrote)
    }
}

/// Read a file to a string, mapping "not found" to `None`.
fn read_opt(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write `contents` to `path` atomically: write a sibling temp file, fsync it, then rename over the
/// target — so a crash never leaves a half-written policy file.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("artifact path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("bad artifact path: {}", path.display()))?;
    let tmp = dir.join(format!(".{file_name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating temp {}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing temp {}", tmp.display()))?;
        f.sync_all().ok(); // best-effort durability; ignore fsync unsupported on odd fs
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Copy a `.example.*` twin over its live artifact (used by `init --examples`). Fails if the example
/// is missing.
pub fn activate_example(
    dir: &PolicyDir,
    artifact: Artifact,
    dry_run: bool,
) -> Result<WriteOutcome> {
    let Some(example) = dir.read_example(artifact)? else {
        bail!(
            "no example file {} to activate",
            artifact.example_filename()
        );
    };
    dir.write(artifact, &example, dry_run)
}

/// A compact unified line diff (old → new). Dependency-free LCS; fine for small policy files.
pub fn unified_diff(old: &str, new: &str, label: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    // LCS length table.
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = format!("--- {label} (current)\n+++ {label} (new)\n");
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push_str(&format!("  {}\n", a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    while i < n {
        out.push_str(&format!("- {}\n", a[i]));
        i += 1;
    }
    while j < m {
        out.push_str(&format!("+ {}\n", b[j]));
        j += 1;
    }
    out
}

/// Open `$EDITOR` (falling back to `vi`) on `initial` content in a temp file, returning the edited
/// text. Used by `broker policy edit` and the TUI's `e` key; the caller validates before persisting.
pub fn edit_text_in_editor(initial: &str) -> Result<String> {
    let editor = std::env::var("EDITOR")
        .ok()
        .filter(|e| !e.trim().is_empty())
        .unwrap_or_else(|| "vi".to_string());
    edit_text_with(&editor, initial)
}

/// The editor-invocation core (the `$EDITOR` value passed in explicitly, so it is testable without
/// mutating the process environment). Seeds a temp file with `initial`, opens `editor` on it, and
/// returns the edited text.
pub(crate) fn edit_text_with(editor: &str, initial: &str) -> Result<String> {
    // `$EDITOR` may carry arguments (e.g. `code --wait`, `subl -w`, `emacsclient -nw`): split it into
    // the program and its args so the editor actually launches on the temp file (and thus opens the
    // CURRENT content, never an empty buffer).
    let mut parts = editor.split_whitespace();
    let program = parts.next().unwrap_or("vi");
    let args: Vec<&str> = parts.collect();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("aegis-edit-{}-{nanos}.tmp", std::process::id()));
    // Seed the temp file with the current content BEFORE opening the editor.
    std::fs::write(&tmp, initial).with_context(|| format!("writing {}", tmp.display()))?;
    let status = std::process::Command::new(program)
        .args(&args)
        .arg(&tmp)
        .status()
        .with_context(|| format!("launching editor '{editor}'"))?;
    if !status.success() {
        std::fs::remove_file(&tmp).ok();
        bail!("editor '{editor}' exited without saving");
    }
    let edited = std::fs::read_to_string(&tmp)?;
    std::fs::remove_file(&tmp).ok();
    Ok(edited)
}

#[cfg(test)]
pub(crate) fn unique_temp_dir(tag: &str) -> PolicyDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aegis-cli-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    PolicyDir::new(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_stays_inside_root_for_every_artifact() {
        let dir = PolicyDir::new("/policies");
        for a in Artifact::ALL {
            let p = dir.resolve(a);
            assert!(p.starts_with("/policies"));
            assert_eq!(p.parent().unwrap(), Path::new("/policies"));
            assert_eq!(p.file_name().unwrap().to_str().unwrap(), a.filename());
        }
    }

    #[test]
    fn for_tenant_nests_under_tenants_and_rejects_bad_slugs() {
        let d = PolicyDir::for_tenant("/policies", "acme").unwrap();
        assert!(d.root().ends_with("tenants/acme"));
        // Every artifact still resolves inside the tenant dir (no traversal).
        for a in Artifact::ALL {
            assert!(d.resolve(a).starts_with(d.root()));
        }
        // Dot segments and non-slug ids are refused.
        assert!(PolicyDir::for_tenant("/policies", "..").is_err());
        assert!(PolicyDir::for_tenant("/policies", ".").is_err());
        assert!(PolicyDir::for_tenant("/policies", "Bad Slug").is_err());
        assert!(PolicyDir::for_tenant("/policies", "").is_err());
    }

    #[test]
    fn write_is_atomic_skips_noop_and_honors_dry_run() {
        let dir = unique_temp_dir("io");
        // First write creates the file.
        assert_eq!(
            dir.write(Artifact::Meter, "max_steps = 5\n", false)
                .unwrap(),
            WriteOutcome::Wrote
        );
        assert_eq!(
            dir.read(Artifact::Meter).unwrap().as_deref(),
            Some("max_steps = 5\n")
        );
        // Identical content is a no-op.
        assert_eq!(
            dir.write(Artifact::Meter, "max_steps = 5\n", false)
                .unwrap(),
            WriteOutcome::Unchanged
        );
        // Dry-run returns a diff and writes nothing.
        let out = dir.write(Artifact::Meter, "max_steps = 9\n", true).unwrap();
        match out {
            WriteOutcome::DryRun(d) => {
                assert!(d.contains("- max_steps = 5"));
                assert!(d.contains("+ max_steps = 9"));
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
        assert_eq!(
            dir.read(Artifact::Meter).unwrap().as_deref(),
            Some("max_steps = 5\n")
        );
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn read_absent_is_none() {
        let dir = unique_temp_dir("absent");
        assert!(dir.read(Artifact::Pins).unwrap().is_none());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    /// A fake editor script that records the content of the file it is handed (proving the CURRENT
    /// content reached it, not an empty buffer), then appends `" EDITED"`. Returns the editor
    /// command string, optionally carrying an extra `--flag` argument.
    fn fake_editor(dir: &Path, record: &Path, with_flag: bool) -> String {
        let script = dir.join("fake_editor.sh");
        // POSIX sh: drop a leading `--flag` if present, then the temp file is `$1`.
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n[ \"$1\" = \"--flag\" ] && shift\ncat \"$1\" > '{}'\nprintf ' EDITED' >> \"$1\"\n",
                record.display()
            ),
        )
        .unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&script)
            .status()
            .unwrap();
        if with_flag {
            format!("{} --flag", script.display())
        } else {
            script.display().to_string()
        }
    }

    // Regression: editing must open the editor on the CURRENT content (not an empty buffer).
    #[test]
    fn edit_loads_current_values_not_an_empty_buffer() {
        let dir = unique_temp_dir("edit");
        let record = dir.root().join("seen.txt");
        let editor = fake_editor(dir.root(), &record, false); // plain single-word editor (like `vim`)
        let current = "permit ( principal, action, resource );";
        let edited = edit_text_with(&editor, current).unwrap();
        assert_eq!(
            std::fs::read_to_string(&record).unwrap(),
            current,
            "editor got the current content"
        );
        assert!(!std::fs::read_to_string(&record).unwrap().is_empty());
        assert_eq!(edited, format!("{current} EDITED"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    // Regression: a `$EDITOR` that carries arguments (e.g. "code --wait") must still launch and
    // receive the current content — the old code passed the whole string as the program name.
    #[test]
    fn edit_honors_editor_with_arguments() {
        let dir = unique_temp_dir("edit-args");
        let record = dir.root().join("seen.txt");
        let editor = fake_editor(dir.root(), &record, true); // "<script> --flag"
        let current = "hosts = [\"api.example\"]\n";
        let edited = edit_text_with(&editor, current).unwrap();
        assert_eq!(std::fs::read_to_string(&record).unwrap(), current);
        assert_eq!(edited, format!("{current} EDITED"));
        std::fs::remove_dir_all(dir.root()).ok();
    }

    // A failing editor must not silently succeed.
    #[test]
    fn edit_reports_editor_failure() {
        assert!(edit_text_with("false", "x").is_err());
    }
}
