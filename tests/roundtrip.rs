use noer22::cli::{CipherChoice, ListArgs, PackArgs, UnpackArgs, VerifyArgs};
use noer22::error::NoerError;
use noer22::utils::RelPathSet;
use noer22::{pack, unpack};
use std::fs;
use std::path::{Path, PathBuf};

fn pack_args(root: &Path, inputs: Vec<PathBuf>, password: &str) -> PackArgs {
    PackArgs {
        inputs,
        output: root.join("archive.noer"),
        password: password.to_string(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 32,
        kdf_iters: 2,
        kdf_parallelism: 1,
        threads: Some(1),
    }
}

#[test]
fn roundtrip_pack_unpack() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("data/sub")).unwrap();
    fs::create_dir_all(root.join("data/empty")).unwrap();
    fs::write(root.join("data/hello.txt"), b"hello world").unwrap();
    fs::write(root.join("data/sub/nums.bin"), b"1234567890").unwrap();

    pack::pack(pack_args(root, vec![root.join("data")], "test_password")).unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: "test_password".to_string(),
        output: Some(root.join("out")),
    })
    .unwrap();

    let a = fs::read(root.join("out/data/hello.txt")).unwrap();
    let b = fs::read(root.join("out/data/sub/nums.bin")).unwrap();
    assert_eq!(a, b"hello world");
    assert_eq!(b, b"1234567890");
    assert!(root.join("out/data/empty").is_dir());
}

#[test]
fn wrong_password_unpack_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/file.txt"), b"secret").unwrap();

    pack::pack(pack_args(root, vec![root.join("data")], "correct_password")).unwrap();

    let err = unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: "wrong_password".to_string(),
        output: Some(root.join("out")),
    })
    .unwrap_err();

    assert!(matches!(err, NoerError::AuthenticationFailed));
}

#[test]
fn list_verify_and_inspect_work() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("docs/sub")).unwrap();
    fs::write(root.join("docs/readme.txt"), b"content").unwrap();
    fs::write(root.join("docs/sub/note.md"), b"note").unwrap();

    pack::pack(pack_args(root, vec![root.join("docs")], "list_password")).unwrap();

    let overview = unpack::inspect_archive(&root.join("archive.noer"), "list_password").unwrap();
    assert_eq!(overview.file_count, 2);
    assert!(overview.dir_count >= 1);
    assert!(overview.total_entries >= 3);
    assert!(overview.total_bytes >= 11);

    unpack::list(ListArgs {
        archive: root.join("archive.noer"),
        password: "list_password".to_string(),
        long: true,
    })
    .unwrap();

    unpack::verify(VerifyArgs {
        archive: root.join("archive.noer"),
        password: "list_password".to_string(),
    })
    .unwrap();
}

#[test]
fn verify_wrong_password_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("secure")).unwrap();
    fs::write(root.join("secure/payload.bin"), b"123456").unwrap();

    pack::pack(pack_args(root, vec![root.join("secure")], "verify_ok")).unwrap();

    let err = unpack::verify(VerifyArgs {
        archive: root.join("archive.noer"),
        password: "verify_bad".to_string(),
    })
    .unwrap_err();

    assert!(matches!(err, NoerError::AuthenticationFailed));
}

#[test]
fn empty_root_directory_is_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("empty_root")).unwrap();

    pack::pack(pack_args(
        root,
        vec![root.join("empty_root")],
        "empty_password",
    ))
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: "empty_password".to_string(),
        output: Some(root.join("out")),
    })
    .unwrap();

    let restored = root.join("out/empty_root");
    assert!(restored.is_dir());
    let entries: Vec<_> = fs::read_dir(restored).unwrap().collect();
    assert!(entries.is_empty());
}

#[test]
fn duplicate_input_root_names_are_disambiguated() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("left/data")).unwrap();
    fs::create_dir_all(root.join("right/data")).unwrap();
    fs::write(root.join("left/data/a.txt"), b"left").unwrap();
    fs::write(root.join("right/data/b.txt"), b"right").unwrap();

    pack::pack(pack_args(
        root,
        vec![root.join("left/data"), root.join("right/data")],
        "dup_password",
    ))
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: "dup_password".to_string(),
        output: Some(root.join("out")),
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join("out/data_1/a.txt")).unwrap(),
        b"left".as_slice()
    );
    assert_eq!(
        fs::read(root.join("out/data_2/b.txt")).unwrap(),
        b"right".as_slice()
    );
}

#[test]
fn rel_path_set_rejects_conflicting_paths() {
    let mut set = RelPathSet::default();

    set.insert("folder/file.txt", false).unwrap();

    let err_same = set.insert("folder/file.txt", true).unwrap_err();
    match err_same {
        NoerError::InvalidFormat(msg) => {
            assert!(msg.contains("path conflict") || msg.contains("duplicate"))
        }
        other => panic!("unexpected error: {other}"),
    }

    let mut set2 = RelPathSet::default();
    set2.insert("parent", false).unwrap();
    let err_parent = set2.insert("parent/child.txt", false).unwrap_err();
    match err_parent {
        NoerError::InvalidFormat(msg) => assert!(msg.contains("file parent")),
        other => panic!("unexpected error: {other}"),
    }
}
