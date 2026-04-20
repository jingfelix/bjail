use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::ArgAction;
use clap::Parser;
use clap::builder::BoolishValueParser;
use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompFilter;
use seccompiler::TargetArch;
use seccompiler::apply_filter;

const DEFAULT_READABLE_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr",
    "/etc",
    "/lib",
    "/lib64",
    "/nix/store",
    "/run/current-system/sw",
];
const SANDBOX_EXECUTABLE_PATH: &str = "/.bjail/bin/bjail";
#[cfg(target_arch = "x86_64")]
const ADDITIONAL_DENIED_PROCESS_SYSCALLS: &[i64] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(not(target_arch = "x86_64"))]
const ADDITIONAL_DENIED_PROCESS_SYSCALLS: &[i64] = &[];

#[derive(Debug, Parser)]
#[command(
    name = "bjail",
    about = "Run a command inside a minimal bubblewrap-based sandbox",
    trailing_var_arg = true
)]
struct OuterCli {
    /// Writable workspace root mounted back into the sandbox.
    #[arg(long, default_value_os_t = default_sandbox_path())]
    sandbox_path: PathBuf,

    /// Whether the sandbox keeps host network access.
    #[arg(long, action = ArgAction::Set, default_value_t = false, value_parser = BoolishValueParser::new())]
    network: bool,

    /// Whether the sandboxed payload may create child processes.
    #[arg(long, action = ArgAction::Set, default_value_t = true, value_parser = BoolishValueParser::new())]
    subprocess: bool,

    /// Extra readable paths. When any are provided, bjail switches to whitelist mode.
    #[arg(long = "readable-path", action = ArgAction::Append)]
    readable_paths: Vec<PathBuf>,

    /// Also allow the directories listed in this bjail process's PATH environment variable.
    #[arg(long, action = ArgAction::SetTrue)]
    allow_env_path: bool,

    /// Bind mount the host /tmp directory as writable inside the sandbox.
    #[arg(long = "writable-host-tmp", action = ArgAction::SetTrue)]
    writable_host_tmp: bool,

    /// Paths that should become unreadable after mounts are applied.
    #[arg(long = "blocked-path", action = ArgAction::Append)]
    blocked_paths: Vec<PathBuf>,

    #[arg(required = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
#[command(name = "bjail", hide = true)]
struct InnerCli {
    #[arg(long, hide = true, default_value_t = false)]
    apply_seccomp_then_exec: bool,

    #[arg(long, action = ArgAction::Set, default_value_t = false, value_parser = BoolishValueParser::new())]
    network: bool,

    #[arg(long, action = ArgAction::Set, default_value_t = true, value_parser = BoolishValueParser::new())]
    subprocess: bool,

    #[arg(long)]
    shell_command: String,
}

#[derive(Debug, Clone)]
struct FilesystemPolicy {
    sandbox_path: PathBuf,
    readable_paths: Vec<PathBuf>,
    writable_host_tmp: bool,
    blocked_paths: Vec<PathBuf>,
}

#[derive(Debug)]
struct BwrapArgs {
    args: Vec<String>,
    preserved_files: Vec<File>,
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("bjail: {err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    let exit_code = if matches!(
        args.get(1).and_then(|arg| arg.to_str()),
        Some("--apply-seccomp-then-exec")
    ) {
        let cli = InnerCli::parse_from(args);
        run_inner(&cli)?
    } else {
        let cli = OuterCli::parse_from(args);
        run_outer(&cli)?
    };

    std::process::exit(exit_code);
}

fn run_outer(cli: &OuterCli) -> Result<i32> {
    let current_exe = env::current_exe().context("failed to resolve current executable")?;
    let current_exe = canonicalize_existing_path(&current_exe)?;
    let fs_policy = resolve_filesystem_policy(cli)?;
    let inner_exec_path = if fs_policy.readable_paths.is_empty() {
        current_exe.clone()
    } else {
        PathBuf::from(SANDBOX_EXECUTABLE_PATH)
    };
    let shell_command = build_shell_command(&cli.command, cli.subprocess)?;

    ensure_bwrap_available()?;

    let inner_argv = build_inner_argv(&inner_exec_path, cli, &shell_command);
    let bwrap = build_bwrap_argv(
        &fs_policy,
        &current_exe,
        &inner_exec_path,
        cli.network,
        &inner_argv,
    )?;

    let _preserved_files = bwrap.preserved_files;
    let status = Command::new("bwrap")
        .args(&bwrap.args)
        .status()
        .context("failed to launch bubblewrap")?;

    Ok(exit_code_from_status(status))
}

fn run_inner(cli: &InnerCli) -> Result<i32> {
    if !cli.subprocess {
        set_no_new_privs()?;
        install_no_subprocess_seccomp()?;
    }

    let err = Command::new("bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-lc")
        .arg(&cli.shell_command)
        .exec();
    Err(err).context("failed to exec bash inside sandbox")
}

fn ensure_bwrap_available() -> Result<()> {
    let output = Command::new("bwrap")
        .arg("--version")
        .output()
        .context("`bwrap` is required but was not found in PATH")?;

    if !output.status.success() {
        bail!("`bwrap --version` failed; bubblewrap is not usable in this environment");
    }

    Ok(())
}

fn resolve_filesystem_policy(cli: &OuterCli) -> Result<FilesystemPolicy> {
    let sandbox_path = canonicalize_sandbox_path(&cli.sandbox_path)?;
    let mut readable_paths = resolve_optional_existing_paths(&cli.readable_paths, "readable path")?;
    if cli.allow_env_path {
        readable_paths.extend(readable_path_dirs_from_env()?);
    }
    let mut blocked_paths = resolve_optional_existing_paths(&cli.blocked_paths, "blocked path")?;

    readable_paths.sort();
    readable_paths.dedup();
    blocked_paths.sort();
    blocked_paths.dedup();

    Ok(FilesystemPolicy {
        sandbox_path,
        readable_paths,
        writable_host_tmp: cli.writable_host_tmp,
        blocked_paths,
    })
}

fn resolve_optional_existing_paths(paths: &[PathBuf], kind: &str) -> Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();

    for path in paths {
        let absolute = match absolutize_path(path) {
            Ok(path) => path,
            Err(err) => {
                eprintln!(
                    "bjail: warning: skipping {kind} `{}` because it could not be resolved: {err:#}",
                    path.display()
                );
                continue;
            }
        };

        let metadata = match fs::metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "bjail: warning: skipping {kind} `{}` because it does not exist",
                    absolute.display()
                );
                continue;
            }
            Err(err) => {
                eprintln!(
                    "bjail: warning: skipping {kind} `{}` because metadata lookup failed: {err}",
                    absolute.display()
                );
                continue;
            }
        };

        let canonical = match absolute.canonicalize() {
            Ok(path) => path,
            Err(err) => {
                eprintln!(
                    "bjail: warning: skipping {kind} `{}` because canonicalization failed: {err}",
                    absolute.display()
                );
                continue;
            }
        };

        if !metadata.is_dir() && !metadata.is_file() {
            eprintln!(
                "bjail: warning: skipping {kind} `{}` because only regular files and directories are supported",
                absolute.display()
            );
            continue;
        }

        resolved_paths.push(canonical);
    }

    Ok(resolved_paths)
}

fn readable_path_dirs_from_env() -> Result<Vec<PathBuf>> {
    let current_dir = env::current_dir().context("failed to resolve current directory")?;
    Ok(readable_path_dirs_from_value(
        env::var_os("PATH"),
        &current_dir,
    ))
}

fn readable_path_dirs_from_value(
    path_value: Option<std::ffi::OsString>,
    current_dir: &Path,
) -> Vec<PathBuf> {
    let Some(path_value) = path_value else {
        return Vec::new();
    };

    let mut dirs = Vec::new();
    for entry in env::split_paths(&path_value) {
        let absolute = if entry.is_absolute() {
            entry
        } else {
            current_dir.join(entry)
        };

        let Ok(metadata) = fs::metadata(&absolute) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }

        let Ok(canonical) = canonicalize_existing_path(&absolute) else {
            continue;
        };
        dirs.push(canonical);
    }

    dirs
}

fn absolutize_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .context("failed to resolve current directory")?
            .join(path))
    }
}

fn canonicalize_existing_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("failed to canonicalize `{}`", path.display()))
}

fn canonicalize_sandbox_path(path: &Path) -> Result<PathBuf> {
    let absolute = absolutize_path(path)?;
    let metadata = fs::metadata(&absolute)
        .with_context(|| format!("sandbox path `{}` does not exist", absolute.display()))?;
    if !metadata.is_dir() {
        bail!("sandbox path `{}` must be a directory", absolute.display());
    }

    let canonical = canonicalize_existing_path(&absolute)?;
    if canonical == Path::new("/") {
        bail!("sandbox path must not be `/`");
    }

    Ok(canonical)
}

fn build_inner_argv(exec_path: &Path, cli: &OuterCli, shell_command: &str) -> Vec<String> {
    vec![
        exec_path.to_string_lossy().into_owned(),
        "--apply-seccomp-then-exec".to_string(),
        format!("--network={}", cli.network),
        format!("--subprocess={}", cli.subprocess),
        "--shell-command".to_string(),
        shell_command.to_string(),
    ]
}

fn build_bwrap_argv(
    fs_policy: &FilesystemPolicy,
    current_exe: &Path,
    inner_exec_path: &Path,
    network: bool,
    inner_argv: &[String],
) -> Result<BwrapArgs> {
    let BwrapArgs {
        args: filesystem_args,
        preserved_files,
    } = create_filesystem_args(
        fs_policy,
        if fs_policy.readable_paths.is_empty() {
            None
        } else {
            Some((current_exe, inner_exec_path))
        },
    )?;
    let sandbox = fs_policy.sandbox_path.to_string_lossy().into_owned();

    let mut args = vec!["--new-session".to_string(), "--die-with-parent".to_string()];
    args.extend(filesystem_args);
    args.extend([
        "--unshare-user".to_string(),
        "--unshare-pid".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "--chdir".to_string(),
        sandbox,
    ]);

    if !network {
        args.push("--unshare-net".to_string());
    }

    args.push("--".to_string());
    args.extend(inner_argv.iter().cloned());

    Ok(BwrapArgs {
        args,
        preserved_files,
    })
}

fn create_filesystem_args(
    fs_policy: &FilesystemPolicy,
    executable_mapping: Option<(&Path, &Path)>,
) -> Result<BwrapArgs> {
    let mut args = Vec::new();
    let mut preserved_files = Vec::new();
    let whitelist_mode = !fs_policy.readable_paths.is_empty();

    if whitelist_mode {
        args.extend(["--tmpfs".to_string(), "/".to_string()]);
        args.extend(["--dev".to_string(), "/dev".to_string()]);

        let mut readable_roots: BTreeSet<PathBuf> = DEFAULT_READABLE_ROOTS
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect();
        readable_roots.extend(fs_policy.readable_paths.iter().cloned());

        for readable_root in readable_roots {
            append_bind_mount_args(
                &mut args,
                &mut preserved_files,
                &readable_root,
                true,
                Path::new("/"),
            )?;
        }
    } else {
        args.extend([
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
        ]);
    }

    if fs_policy.writable_host_tmp {
        append_bind_mount_args(
            &mut args,
            &mut preserved_files,
            Path::new("/tmp"),
            false,
            Path::new("/"),
        )?;
    }

    if let Some((source, dest)) = executable_mapping {
        append_bind_mount_mapping_args(
            &mut args,
            &mut preserved_files,
            source,
            dest,
            true,
            Path::new("/"),
        )?;
    }

    append_bind_mount_args(
        &mut args,
        &mut preserved_files,
        &fs_policy.sandbox_path,
        false,
        Path::new("/"),
    )?;

    let mut blocked_paths = fs_policy.blocked_paths.clone();
    blocked_paths.sort_by_key(|path| path.components().count());
    for blocked_path in blocked_paths {
        append_blocked_path_args(&mut args, &mut preserved_files, &blocked_path)?;
    }

    Ok(BwrapArgs {
        args,
        preserved_files,
    })
}

fn append_bind_mount_args(
    args: &mut Vec<String>,
    preserved_files: &mut Vec<File>,
    path: &Path,
    read_only: bool,
    anchor: &Path,
) -> Result<()> {
    ensure_mount_target_exists(args, preserved_files, path, path, anchor)?;
    args.push(if read_only {
        "--ro-bind".to_string()
    } else {
        "--bind".to_string()
    });
    args.push(path_to_string(path));
    args.push(path_to_string(path));
    Ok(())
}

fn append_bind_mount_mapping_args(
    args: &mut Vec<String>,
    preserved_files: &mut Vec<File>,
    source: &Path,
    dest: &Path,
    read_only: bool,
    anchor: &Path,
) -> Result<()> {
    ensure_mount_target_exists(args, preserved_files, source, dest, anchor)?;
    args.push(if read_only {
        "--ro-bind".to_string()
    } else {
        "--bind".to_string()
    });
    args.push(path_to_string(source));
    args.push(path_to_string(dest));
    Ok(())
}

fn ensure_mount_target_exists(
    args: &mut Vec<String>,
    preserved_files: &mut Vec<File>,
    source: &Path,
    dest: &Path,
    anchor: &Path,
) -> Result<()> {
    append_mount_target_parent_dir_args(args, dest, anchor);

    let metadata = fs::metadata(source)
        .with_context(|| format!("failed to read metadata for `{}`", source.display()))?;
    if metadata.is_dir() {
        args.push("--dir".to_string());
        args.push(path_to_string(dest));
    } else {
        let fd = preserved_fd_for_dev_null(preserved_files)?;
        args.push("--file".to_string());
        args.push(fd.to_string());
        args.push(path_to_string(dest));
    }

    Ok(())
}

fn append_blocked_path_args(
    args: &mut Vec<String>,
    preserved_files: &mut Vec<File>,
    path: &Path,
) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| {
        format!(
            "failed to read metadata for blocked path `{}`",
            path.display()
        )
    })?;

    if metadata.is_dir() {
        args.push("--perms".to_string());
        args.push("000".to_string());
        args.push("--tmpfs".to_string());
        args.push(path_to_string(path));
        args.push("--remount-ro".to_string());
        args.push(path_to_string(path));
    } else {
        let fd = preserved_fd_for_dev_null(preserved_files)?;
        args.push("--perms".to_string());
        args.push("000".to_string());
        args.push("--ro-bind-data".to_string());
        args.push(fd.to_string());
        args.push(path_to_string(path));
    }

    Ok(())
}

fn append_mount_target_parent_dir_args(args: &mut Vec<String>, mount_target: &Path, anchor: &Path) {
    let mount_target_dir = if mount_target.is_dir() {
        mount_target
    } else if let Some(parent) = mount_target.parent() {
        parent
    } else {
        return;
    };

    let mut dirs: Vec<PathBuf> = mount_target_dir
        .ancestors()
        .take_while(|path| *path != anchor)
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect();
    dirs.reverse();

    for dir in dirs {
        args.push("--dir".to_string());
        args.push(path_to_string(&dir));
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn preserved_fd_for_dev_null(preserved_files: &mut Vec<File>) -> Result<i32> {
    if preserved_files.is_empty() {
        let file = File::open("/dev/null").context("failed to open /dev/null")?;
        clear_cloexec(file.as_raw_fd())?;
        preserved_files.push(file);
    }

    Ok(preserved_files[0].as_raw_fd())
}

fn clear_cloexec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read fd flags");
    }

    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to clear FD_CLOEXEC");
    }

    Ok(())
}

fn build_shell_command(command: &[String], subprocess: bool) -> Result<String> {
    if command.is_empty() {
        bail!("missing command to run inside the sandbox");
    }

    let joined = command
        .iter()
        .map(|arg| quote_shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ");

    if subprocess {
        Ok(joined)
    } else {
        Ok(format!("exec {joined}"))
    }
}

fn quote_shell_word(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }

    let safe = word.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'/' | b'.' | b'-' | b':'
        )
    });
    if safe {
        return word.to_string();
    }

    format!("'{}'", word.replace('\'', r#"'\''"#))
}

fn set_no_new_privs() -> Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to enable no_new_privs");
    }
    Ok(())
}

fn install_no_subprocess_seccomp() -> Result<()> {
    fn deny_syscall(rules: &mut BTreeMap<i64, Vec<seccompiler::SeccompRule>>, nr: i64) {
        rules.insert(nr, vec![]);
    }

    let mut rules = BTreeMap::new();
    deny_syscall(&mut rules, libc::SYS_clone);
    deny_syscall(&mut rules, libc::SYS_clone3);
    for syscall in ADDITIONAL_DENIED_PROCESS_SYSCALLS {
        deny_syscall(&mut rules, *syscall);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        current_arch(),
    )
    .context("failed to build seccomp filter")?;

    let program: BpfProgram = filter
        .try_into()
        .context("failed to compile seccomp filter")?;
    apply_filter(&program).context("failed to apply seccomp filter")?;
    Ok(())
}

fn current_arch() -> TargetArch {
    if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        panic!("unsupported architecture for seccomp");
    }
}

fn exit_code_from_status(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

fn default_sandbox_path() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn shell_command_uses_exec_when_subprocesses_are_disabled() {
        let command = vec!["cat".to_string(), "file.txt".to_string()];
        let shell = build_shell_command(&command, false).expect("shell command");
        assert_eq!(shell, "exec cat file.txt");
    }

    #[test]
    fn shell_command_quotes_unsafe_words() {
        let command = vec!["cat".to_string(), "weird file's name.txt".to_string()];
        let shell = build_shell_command(&command, true).expect("shell command");
        assert_eq!(shell, "cat 'weird file'\\''s name.txt'");
    }

    #[test]
    fn bwrap_argv_unshares_network_when_disabled() {
        let temp = tempdir().expect("tempdir");
        let sandbox = temp.path().join("workspace");
        fs::create_dir_all(&sandbox).expect("create sandbox");
        let inner = vec![
            "/tmp/bjail".to_string(),
            "--apply-seccomp-then-exec".to_string(),
        ];
        let policy = FilesystemPolicy {
            sandbox_path: sandbox.clone(),
            readable_paths: Vec::new(),
            writable_host_tmp: false,
            blocked_paths: Vec::new(),
        };
        let argv = build_bwrap_argv(
            &policy,
            Path::new("/tmp/bjail"),
            Path::new("/tmp/bjail"),
            false,
            &inner,
        )
        .expect("bwrap argv");
        let sandbox = path_to_string(&sandbox);

        assert!(argv.args.contains(&"--unshare-net".to_string()));
        assert!(
            argv.args
                .windows(2)
                .any(|window| window == ["--chdir", sandbox.as_str()])
        );
    }

    #[test]
    fn bwrap_argv_keeps_network_when_enabled() {
        let temp = tempdir().expect("tempdir");
        let sandbox = temp.path().join("workspace");
        fs::create_dir_all(&sandbox).expect("create sandbox");
        let inner = vec![
            "/tmp/bjail".to_string(),
            "--apply-seccomp-then-exec".to_string(),
        ];
        let policy = FilesystemPolicy {
            sandbox_path: sandbox,
            readable_paths: Vec::new(),
            writable_host_tmp: false,
            blocked_paths: Vec::new(),
        };
        let argv = build_bwrap_argv(
            &policy,
            Path::new("/tmp/bjail"),
            Path::new("/tmp/bjail"),
            true,
            &inner,
        )
        .expect("bwrap argv");
        assert!(!argv.args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn whitelist_mode_uses_tmpfs_root_and_mounts_readable_path() {
        let temp = tempdir().expect("tempdir");
        let readable = temp.path().join("docs");
        let sandbox = temp.path().join("workspace");
        fs::create_dir_all(&readable).expect("create readable");
        fs::create_dir_all(&sandbox).expect("create sandbox");

        let policy = FilesystemPolicy {
            sandbox_path: sandbox.clone(),
            readable_paths: vec![readable.clone()],
            writable_host_tmp: false,
            blocked_paths: Vec::new(),
        };

        let args = create_filesystem_args(&policy, None).expect("filesystem args");
        let readable = path_to_string(&readable);
        let sandbox = path_to_string(&sandbox);

        assert_eq!(args.args[0..4], ["--tmpfs", "/", "--dev", "/dev"]);
        assert!(
            args.args
                .windows(3)
                .any(|window| window == ["--ro-bind", readable.as_str(), readable.as_str()])
        );
        assert!(
            args.args
                .windows(3)
                .any(|window| window == ["--bind", sandbox.as_str(), sandbox.as_str()])
        );
    }

    #[test]
    fn writable_host_tmp_mounts_host_tmp_read_write() {
        let temp = tempdir().expect("tempdir");
        let readable = temp.path().join("docs");
        let sandbox = temp.path().join("workspace");
        fs::create_dir_all(&readable).expect("create readable");
        fs::create_dir_all(&sandbox).expect("create sandbox");

        let policy = FilesystemPolicy {
            sandbox_path: sandbox,
            readable_paths: vec![readable],
            writable_host_tmp: true,
            blocked_paths: Vec::new(),
        };

        let args = create_filesystem_args(&policy, None).expect("filesystem args");
        assert!(
            args.args
                .windows(3)
                .any(|window| window == ["--bind", "/tmp", "/tmp"])
        );
        assert!(
            !args
                .args
                .windows(3)
                .any(|window| window == ["--ro-bind", "/tmp", "/tmp"])
        );
    }

    #[test]
    fn readable_path_dirs_from_env_uses_existing_directories_only() {
        let temp = tempdir().expect("tempdir");
        let bin = temp.path().join("bin");
        let relative = PathBuf::from("relative-bin");
        let relative_bin = temp.path().join(&relative);
        fs::create_dir_all(&bin).expect("create bin");
        fs::create_dir_all(&relative_bin).expect("create relative bin");

        let dirs = readable_path_dirs_from_value(
            Some(
                env::join_paths([
                    bin.as_path(),
                    Path::new("/definitely/missing"),
                    relative.as_path(),
                ])
                .expect("join PATH"),
            ),
            temp.path(),
        );

        assert!(dirs.contains(&bin.canonicalize().expect("canonical bin")));
        assert!(dirs.contains(&relative_bin.canonicalize().expect("canonical relative bin")));
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn readable_path_dirs_from_env_returns_empty_without_path() {
        let temp = tempdir().expect("tempdir");
        let dirs = readable_path_dirs_from_value(None, temp.path());

        assert!(dirs.is_empty());
    }

    #[test]
    fn missing_readable_path_is_skipped() {
        let temp = tempdir().expect("tempdir");
        let readable = temp.path().join("docs");
        let missing = temp.path().join("missing");
        fs::create_dir_all(&readable).expect("create readable");

        let resolved =
            resolve_optional_existing_paths(&[readable.clone(), missing], "readable path")
                .expect("resolved paths");

        assert_eq!(
            resolved,
            vec![readable.canonicalize().expect("canonical readable")]
        );
    }

    #[test]
    fn missing_blocked_path_is_skipped() {
        let temp = tempdir().expect("tempdir");
        let blocked = temp.path().join("secret.txt");
        fs::write(&blocked, "secret").expect("write blocked");
        let missing = temp.path().join("missing.txt");

        let resolved = resolve_optional_existing_paths(&[blocked.clone(), missing], "blocked path")
            .expect("resolved paths");

        assert_eq!(
            resolved,
            vec![blocked.canonicalize().expect("canonical blocked")]
        );
    }

    #[test]
    fn blocked_directory_is_masked_with_tmpfs() {
        let temp = tempdir().expect("tempdir");
        let sandbox = temp.path().join("workspace");
        let blocked = sandbox.join("secret");
        fs::create_dir_all(&blocked).expect("create blocked");

        let policy = FilesystemPolicy {
            sandbox_path: sandbox,
            readable_paths: Vec::new(),
            writable_host_tmp: false,
            blocked_paths: vec![blocked.clone()],
        };

        let args = create_filesystem_args(&policy, None).expect("filesystem args");
        let blocked = path_to_string(&blocked);
        assert!(
            args.args
                .windows(4)
                .any(|window| { window == ["--perms", "000", "--tmpfs", blocked.as_str(),] })
        );
        assert!(
            args.args
                .windows(2)
                .any(|window| window == ["--remount-ro", blocked.as_str()])
        );
    }

    #[test]
    fn blocked_file_uses_bind_data_mask() {
        let temp = tempdir().expect("tempdir");
        let sandbox = temp.path().join("workspace");
        fs::create_dir_all(&sandbox).expect("create sandbox");
        let blocked = sandbox.join("secret.txt");
        fs::write(&blocked, "secret").expect("write blocked file");

        let policy = FilesystemPolicy {
            sandbox_path: sandbox,
            readable_paths: Vec::new(),
            writable_host_tmp: false,
            blocked_paths: vec![blocked.clone()],
        };

        let args = create_filesystem_args(&policy, None).expect("filesystem args");
        assert!(
            args.args.windows(4).any(|window| {
                window[0] == "--perms"
                    && window[1] == "000"
                    && window[2] == "--ro-bind-data"
                    && window[3].parse::<i32>().is_ok()
            }),
            "blocked file should install ro-bind-data",
        );
    }
}
