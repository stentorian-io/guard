use sentinel_cli::install::marker_block::{install, strip, BEGIN_MARKER};

#[test]
fn marker_in_three_rc_files_install_and_strip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zsh = dir.path().join(".zshrc");
    let bash = dir.path().join(".bashrc");
    let bp = dir.path().join(".bash_profile");
    for p in [&zsh, &bash, &bp] {
        std::fs::write(p, "# user content\n").unwrap();
        install(p).expect("install");
        assert!(std::fs::read_to_string(p).unwrap().contains(BEGIN_MARKER));
    }
    for p in [&zsh, &bash, &bp] {
        strip(p).expect("strip");
        assert!(!std::fs::read_to_string(p).unwrap().contains(BEGIN_MARKER));
    }
}
