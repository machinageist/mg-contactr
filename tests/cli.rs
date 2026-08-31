#![cfg(target_os = "linux")]

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self, argument: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mg-contacts"));
        command
            .env_clear()
            .env("HOME", self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_DATA_HOME", self.root.path().join("data"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_CACHE_HOME", self.root.path().join("cache"))
            .env(
                "MG_CONTACTS_DATABASE_URL",
                "postgres://user:database-secret@localhost/contacts?sslkey=%2Fprivate%2Fkey",
            )
            .arg(argument);
        command
    }

    fn run(&self, argument: &str, input: &str) -> Output {
        if !input.is_empty() {
            return self.run_in_pty(argument, input);
        }
        let mut child = self
            .command(argument)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn run_in_pty(&self, argument: &str, input: &str) -> Output {
        let command_line = format!("{} {argument}", env!("CARGO_BIN_EXE_mg-contacts"));
        let mut command = Command::new("script");
        command
            .args(["-qefc", &command_line, "/dev/null"])
            .env_clear()
            .env("HOME", self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_DATA_HOME", self.root.path().join("data"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_CACHE_HOME", self.root.path().join("cache"))
            .env(
                "MG_CONTACTS_DATABASE_URL",
                "postgres://user:***@localhost/contacts?sslkey=%2Fprivate%2Fkey",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(100));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn config_dir(&self) -> PathBuf {
        self.root.path().join("config/mg-contacts")
    }

    fn key_file(&self) -> PathBuf {
        self.root.path().join("data/mg-contacts/keyring.json")
    }

    fn write_config(&self, bytes: &[u8], mode: u32) {
        fs::create_dir_all(self.config_dir()).unwrap();
        fs::set_permissions(self.config_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = self.config_dir().join("config.toml");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).unwrap()
}

fn pty_payload(output: &Output) -> String {
    stdout(output)
        .replace('\r', "")
        .replace("New passphrase: \n", "")
        .replace("Confirm passphrase: \n", "")
        .replace("Passphrase: \n", "")
}

fn assert_redacted(output: &Output) {
    let combined = format!("{}{}", stdout(output), stderr(output));
    for secret in ["database-secret", "/private/key", "sslkey", "user:"] {
        assert!(
            !combined.contains(secret),
            "output leaked {secret}: {combined}"
        );
    }
}

#[test]
fn status_is_stable_redacted_and_does_not_initialize_a_key() {
    let fixture = Fixture::new();
    let output = fixture.run("status", "");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        "key=not_initialized; PostgreSQL (Environment; credentials, parameters, and paths redacted)\n"
    );
    assert_eq!(stderr(&output), "");
    assert!(!fixture.key_file().exists());
    assert_redacted(&output);
}

#[test]
fn setup_then_status_truthfully_reports_process_exit_as_locked() {
    let fixture = Fixture::new();
    let setup = fixture.run("setup", &format!("{PASSPHRASE}\n{PASSPHRASE}\n"));
    assert_eq!(setup.status.code(), Some(0), "{}", stderr(&setup));
    assert_eq!(
        pty_payload(&setup),
        "key_initialized; current_command=authenticated; next_process=locked\n"
    );
    assert_redacted(&setup);

    let status = fixture.run("status", "");
    assert_eq!(status.status.code(), Some(0));
    assert!(stdout(&status).starts_with("key=locked; PostgreSQL (Environment;"));
    assert_eq!(
        fs::metadata(fixture.key_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn setup_rejects_weak_and_mismatched_passphrases_without_artifacts() {
    for (input, message) in [
        (
            "short\nshort\n",
            "passphrase must contain at least 12 characters",
        ),
        (
            "correct horse battery staple\ndifferent horse battery staple\n",
            "passphrase confirmation did not match",
        ),
    ] {
        let fixture = Fixture::new();
        let output = fixture.run("setup", input);
        assert_eq!(output.status.code(), Some(65));
        assert_eq!(stderr(&output), "");
        assert!(pty_payload(&output).ends_with(&format!("key_lifecycle_failed: {message}\n")));
        assert!(!fixture.key_file().exists());
        assert_redacted(&output);
    }
}

#[test]
fn verify_passphrase_has_truthful_command_scoped_semantics() {
    let fixture = Fixture::new();
    let setup = fixture.run("setup", &format!("{PASSPHRASE}\n{PASSPHRASE}\n"));
    assert!(setup.status.success());

    let wrong = fixture.run("verify-passphrase", "definitely wrong\n");
    assert_eq!(wrong.status.code(), Some(65));
    assert_eq!(stderr(&wrong), "");
    assert!(pty_payload(&wrong).ends_with(
        "key_lifecycle_failed: passphrase is invalid or could not authenticate the key\n"
    ));

    let correct = fixture.run("verify-passphrase", &format!("{PASSPHRASE}\n"));
    assert_eq!(correct.status.code(), Some(0), "{}", stderr(&correct));
    assert_eq!(
        pty_payload(&correct),
        "passphrase_verified; authentication_ends_with=this_command\n"
    );
    let status = fixture.run("status", "");
    assert!(stdout(&status).starts_with("key=locked;"));
}

#[test]
fn malformed_oversized_and_insecure_config_have_stable_redacted_failures() {
    let fixtures: Vec<(Fixture, Vec<u8>, u32, &str)> = vec![
        (
            Fixture::new(),
            b"[databse]\nurl='postgres://localhost/secret-value'".to_vec(),
            0o600,
            "config_invalid: configuration file is invalid\n",
        ),
        (
            Fixture::new(),
            vec![b'x'; 64 * 1024 + 1],
            0o600,
            "config_invalid: configuration file exceeds the 64 KiB limit\n",
        ),
        (
            Fixture::new(),
            b"[database]\nurl='postgres://localhost/db'".to_vec(),
            0o644,
            "config_invalid: configuration file is not private\n",
        ),
        (
            Fixture::new(),
            b"[database]\nurl='postgres://localhost/db'".to_vec(),
            0o666,
            "config_invalid: configuration file is not private\n",
        ),
    ];
    for (fixture, contents, mode, expected) in fixtures {
        fixture.write_config(&contents, mode);
        let output = fixture.run("status", "");
        assert_eq!(output.status.code(), Some(78));
        assert_eq!(stdout(&output), "");
        assert_eq!(stderr(&output), expected);
        assert_redacted(&output);
        assert!(!stderr(&output).contains(fixture.root.path().to_str().unwrap()));
    }
}

#[test]
fn hard_linked_and_non_regular_configs_are_reported_as_insecure() {
    let fixture = Fixture::new();
    fixture.write_config(b"[database]\nurl='postgres://localhost/db'", 0o600);
    fs::hard_link(
        fixture.config_dir().join("config.toml"),
        fixture.root.path().join("config-alias"),
    )
    .unwrap();
    let output = fixture.run("status", "");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        stderr(&output),
        "config_invalid: configuration file is not private\n"
    );

    let fixture = Fixture::new();
    fs::create_dir_all(fixture.config_dir()).unwrap();
    fs::set_permissions(fixture.config_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(fixture.config_dir().join("config.toml")).unwrap();
    let output = fixture.run("status", "");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        stderr(&output),
        "config_invalid: configuration file is not private\n"
    );
}

#[test]
fn symlink_config_and_insecure_directory_are_rejected_without_mutation() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.config_dir()).unwrap();
    fs::set_permissions(fixture.config_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    let target = fixture.root.path().join("secret-config");
    fs::write(&target, b"[database]\nurl='postgres://localhost/db'").unwrap();
    std::os::unix::fs::symlink(&target, fixture.config_dir().join("config.toml")).unwrap();
    let output = fixture.run("status", "");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        stderr(&output),
        "config_invalid: configuration file is not private\n"
    );

    let fixture = Fixture::new();
    let app_dir = fixture.config_dir();
    fs::create_dir_all(&app_dir).unwrap();
    fs::set_permissions(&app_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let output = fixture.run("status", "");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        stderr(&output),
        "config_invalid: configuration directory is not private\n"
    );
    assert_eq!(
        fs::metadata(app_dir).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn removed_stateful_commands_are_usage_errors() {
    let fixture = Fixture::new();
    for obsolete in ["unlock", "lock"] {
        let output = fixture.run(obsolete, "");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(stdout(&output), "");
        assert!(stderr(&output).contains("unrecognized subcommand"));
        assert!(!fixture.key_file().exists());
    }
}

#[test]
fn remote_database_failure_is_redacted_and_uses_config_exit_code() {
    let fixture = Fixture::new();
    let output = fixture
        .command("status")
        .env(
            "MG_CONTACTS_DATABASE_URL",
            "postgres://user:top-secret@example.test/private",
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "config_invalid: database configuration is local-only and must use localhost, loopback, or a Unix socket\n"
    );
    assert!(!format!("{}{}", stdout(&output), stderr(&output)).contains("top-secret"));
}

#[allow(dead_code)]
fn _path_is_used_for_rustfmt(_: &Path) {}
