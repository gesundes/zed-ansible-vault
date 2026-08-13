use std::fs;
use std::path::Path;
use std::process::Command;

fn manifest_version(path: &Path) -> String {
    let manifest = fs::read_to_string(path).expect("read manifest");
    manifest
        .lines()
        .find_map(|line| {
            line.strip_prefix("version = \"")
                .and_then(|version| version.strip_suffix('"'))
        })
        .unwrap_or_else(|| panic!("version is missing from {}", path.display()))
        .to_string()
}

#[test]
fn zed_extension_and_companion_versions_match() {
    let extension_manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../extension.toml");
    assert_eq!(
        manifest_version(&extension_manifest),
        env!("CARGO_PKG_VERSION"),
        "extension.toml and the companion crate must be versioned together"
    );
}

#[test]
fn companion_reports_its_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_ansible-vault-lsp"))
        .arg("--version")
        .output()
        .expect("run companion --version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 version")
            .trim(),
        env!("CARGO_PKG_VERSION")
    );
    assert!(output.stderr.is_empty());
}
