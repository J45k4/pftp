use std::process::{Command, Stdio};
use std::fs;

#[test]
fn transfer_small_file() {
    let bin = env!("CARGO_BIN_EXE_pftp");
    let tmp = tempfile::tempdir().unwrap();
    let in_file = tmp.path().join("input.txt");
    let out_file = tmp.path().join("output.txt");
    fs::write(&in_file, b"hello world").unwrap();

    let mut server = Command::new(bin)
        .args(["server", "--listen", "127.0.0.1:50000", "--output"])
        .arg(&out_file)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let status = Command::new(bin)
        .args(["client", "--server", "127.0.0.1:50000", "--file"])
        .arg(&in_file)
        .status()
        .unwrap();
    assert!(status.success());

    let server_status = server.wait().unwrap();
    assert!(server_status.success());

    let sent = fs::read(&in_file).unwrap();
    let recv = fs::read(&out_file).unwrap();
    assert_eq!(sent, recv);
}
