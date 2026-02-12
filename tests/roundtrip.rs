use age::secrecy::ExposeSecret;
use noer22::cli::{ChecksumChoice, CipherChoice, ListArgs, PackArgs, UnpackArgs, VerifyArgs};
use noer22::error::NoerError;
use noer22::utils::RelPathSet;
use noer22::{pack, unpack};
use std::fs;
use std::path::{Path, PathBuf};

fn pack_args(root: &Path, inputs: Vec<PathBuf>, password: &str) -> PackArgs {
    PackArgs {
        inputs,
        output: root.join("archive.noer"),
        password: Some(password.to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: None,
        checksum: None,
        checksum_output: None,
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
        password: Some("test_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
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
        password: Some("wrong_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
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
        password: Some("list_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        long: true,
    })
    .unwrap();

    unpack::verify(VerifyArgs {
        archive: root.join("archive.noer"),
        password: Some("list_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        checksum_file: None,
        checksum_algo: None,
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
        password: Some("verify_bad".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        checksum_file: None,
        checksum_algo: None,
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
        password: Some("empty_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
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
        password: Some("dup_password".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
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

#[test]
fn keyfile_only_roundtrip_and_missing_keyfile_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/value.txt"), b"keyfile payload").unwrap();
    fs::write(root.join("secret.key"), b"this_is_a_binaryish_keyfile_seed").unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("src")],
        output: root.join("archive_keyfile.noer"),
        password: None,
        keyfile: Some(root.join("secret.key")),
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: None,
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("archive_keyfile.noer"),
        password: None,
        keyfile: Some(root.join("secret.key")),
        age_identities: Vec::new(),
        output: Some(root.join("out_keyfile")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join("out_keyfile/src/value.txt")).unwrap(),
        b"keyfile payload"
    );

    let err = unpack::unpack(UnpackArgs {
        archive: root.join("archive_keyfile.noer"),
        password: Some("fallback_pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out_fail")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();

    match err {
        NoerError::InvalidFormat(msg) => assert!(msg.contains("requires keyfile")),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn checksum_sidecar_allows_verify_without_password() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(root.join("docs/readme.txt"), b"checksum-me").unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("docs")],
        output: root.join("archive_checksum.noer"),
        password: Some("checkpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: None,
        checksum: Some(ChecksumChoice::Sha256),
        checksum_output: None,
    })
    .unwrap();

    unpack::verify(VerifyArgs {
        archive: root.join("archive_checksum.noer"),
        password: None,
        keyfile: None,
        age_identities: Vec::new(),
        checksum_file: Some(root.join("archive_checksum.noer.sha256")),
        checksum_algo: None,
    })
    .unwrap();
}

#[test]
fn incremental_mode_packs_only_changed_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(root.join("docs/a.txt"), b"v1-a").unwrap();
    fs::write(root.join("docs/b.txt"), b"v1-b").unwrap();

    let index_path = root.join("delta-index.json");

    pack::pack(PackArgs {
        inputs: vec![root.join("docs")],
        output: root.join("full.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: Some(index_path.clone()),
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    fs::write(root.join("docs/a.txt"), b"v2-a-changed").unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("docs")],
        output: root.join("delta.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: Some(index_path),
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    let overview = unpack::inspect_archive(&root.join("delta.noer"), "incpass").unwrap();
    assert_eq!(overview.file_count, 1);
    assert!(overview.entries.iter().any(|e| e.path.ends_with("a.txt")));
    assert!(!overview.entries.iter().any(|e| e.path.ends_with("b.txt")));
}

#[test]
fn incremental_tombstone_deletes_removed_files_on_unpack() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(root.join("docs/a.txt"), b"keep").unwrap();
    fs::write(root.join("docs/b.txt"), b"remove-me").unwrap();

    let index_path = root.join("delta-index.json");

    pack::pack(PackArgs {
        inputs: vec![root.join("docs")],
        output: root.join("full.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: Some(index_path.clone()),
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("full.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    fs::remove_file(root.join("docs/b.txt")).unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("docs")],
        output: root.join("delta-delete.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: Some(index_path),
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    let delta_overview =
        unpack::inspect_archive(&root.join("delta-delete.noer"), "incpass").unwrap();
    assert!(delta_overview.deleted_count >= 1);
    assert!(delta_overview
        .entries
        .iter()
        .any(|e| e.deleted && e.path.ends_with("b.txt")));

    unpack::unpack(UnpackArgs {
        archive: root.join("delta-delete.noer"),
        password: Some("incpass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    assert!(!root.join("out/docs/b.txt").exists());
    assert_eq!(fs::read(root.join("out/docs/a.txt")).unwrap(), b"keep");
}

#[test]
fn parallel_crypto_pack_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("bulk/sub")).unwrap();
    fs::write(root.join("bulk/a.txt"), b"alpha").unwrap();
    fs::write(root.join("bulk/sub/b.txt"), b"beta").unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("bulk")],
        output: root.join("parallel.noer"),
        password: Some("parallelpass".to_string()),
        keyfile: None,
        age_recipients: Vec::new(),
        level: 6,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(4),
        parallel_crypto: true,
        incremental_index: None,
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("parallel.noer"),
        password: Some("parallelpass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out_parallel")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join("out_parallel/bulk/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        fs::read(root.join("out_parallel/bulk/sub/b.txt")).unwrap(),
        b"beta"
    );
}

#[test]
fn age_recipient_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("secure")).unwrap();
    fs::write(root.join("secure/note.txt"), b"age-protected").unwrap();

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let identity_path = root.join("age-identity.txt");
    fs::write(
        &identity_path,
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();

    pack::pack(PackArgs {
        inputs: vec![root.join("secure")],
        output: root.join("archive_age.noer"),
        password: None,
        keyfile: None,
        age_recipients: vec![recipient],
        level: 3,
        cipher: CipherChoice::ChaCha20Poly1305,
        kdf_mem: 64,
        kdf_iters: 3,
        kdf_parallelism: 1,
        threads: Some(1),
        parallel_crypto: false,
        incremental_index: None,
        checksum: None,
        checksum_output: None,
    })
    .unwrap();

    unpack::unpack(UnpackArgs {
        archive: root.join("archive_age.noer"),
        password: None,
        keyfile: None,
        age_identities: vec![identity_path.clone()],
        output: Some(root.join("out_age")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join("out_age/secure/note.txt")).unwrap(),
        b"age-protected"
    );

    unpack::verify(VerifyArgs {
        archive: root.join("archive_age.noer"),
        password: None,
        keyfile: None,
        age_identities: vec![identity_path],
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();
}

#[test]
fn pack_refuses_overwrite_existing_output() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/data.txt"), b"value").unwrap();
    fs::write(root.join("archive.noer"), b"existing").unwrap();

    let err = pack::pack(pack_args(root, vec![root.join("src")], "pass")).unwrap_err();
    match err {
        NoerError::InvalidFormat(msg) => assert!(msg.contains("output already exists")),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn unpack_full_refuses_overwrite_conflicts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/file.txt"), b"archive-data").unwrap();
    pack::pack(pack_args(root, vec![root.join("data")], "pass")).unwrap();

    fs::create_dir_all(root.join("out/data")).unwrap();
    fs::write(root.join("out/data/file.txt"), b"keep-me").unwrap();

    let err = unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();

    match err {
        NoerError::InvalidFormat(msg) => assert!(msg.contains("refusing to overwrite")),
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        fs::read(root.join("out/data/file.txt")).unwrap(),
        b"keep-me"
    );
}

#[test]
fn tampered_and_truncated_archive_fail_safe() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/secret.bin"), b"top-secret").unwrap();
    pack::pack(pack_args(root, vec![root.join("data")], "pass")).unwrap();

    let original = fs::read(root.join("archive.noer")).unwrap();

    let mut tampered_header = original.clone();
    tampered_header[0] ^= 0x80;
    fs::write(root.join("tampered-header.noer"), &tampered_header).unwrap();

    let err = unpack::verify(VerifyArgs {
        archive: root.join("tampered-header.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();
    assert!(matches!(err, NoerError::InvalidFormat(_)));

    let mut tampered_payload = original.clone();
    let payload_idx = tampered_payload.len() / 2;
    tampered_payload[payload_idx] ^= 0x33;
    fs::write(root.join("tampered-payload.noer"), &tampered_payload).unwrap();

    let err = unpack::verify(VerifyArgs {
        archive: root.join("tampered-payload.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        NoerError::AuthenticationFailed | NoerError::InvalidFormat(_)
    ));

    let out_corrupt = root.join("out_corrupt");
    let err = unpack::unpack(UnpackArgs {
        archive: root.join("tampered-payload.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(out_corrupt.clone()),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        NoerError::AuthenticationFailed | NoerError::InvalidFormat(_)
    ));
    assert!(!out_corrupt.exists());

    let truncated_len = original.len() / 3;
    fs::write(
        root.join("truncated.noer"),
        &original[..truncated_len.max(1)],
    )
    .unwrap();

    let out_trunc = root.join("out_trunc");
    let err = unpack::unpack(UnpackArgs {
        archive: root.join("truncated.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(out_trunc.clone()),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        NoerError::AuthenticationFailed | NoerError::InvalidFormat(_)
    ));
    assert!(!out_trunc.exists());
}

#[test]
fn fuzz_like_corruption_never_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/blob.txt"), b"fuzz-target").unwrap();
    pack::pack(pack_args(root, vec![root.join("data")], "pass")).unwrap();
    let original = fs::read(root.join("archive.noer")).unwrap();

    for i in 0usize..32 {
        let mut mutated = original.clone();
        let idx = 64 + ((i * 7919) % (mutated.len().saturating_sub(64).max(1)));
        let mut delta = (i as u8).wrapping_mul(17).wrapping_add(1);
        if delta == 0 {
            delta = 0xA5;
        }
        mutated[idx] ^= delta;
        let path = root.join(format!("mut_{i:02}.noer"));
        fs::write(&path, mutated).unwrap();

        let result = unpack::verify(VerifyArgs {
            archive: path,
            password: Some("pass".to_string()),
            keyfile: None,
            age_identities: Vec::new(),
            checksum_file: None,
            checksum_algo: None,
        });
        assert!(result.is_err(), "mutated archive unexpectedly verified");
    }
}

#[test]
fn weird_names_and_many_small_files_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();

    fs::write(data.join("space name.txt"), b"space").unwrap();
    fs::write(data.join("symbols_#[]{}!.txt"), b"symbols").unwrap();
    fs::write(data.join("unicode_arquivo_olA_\u{00FC}.txt"), b"unicode").unwrap();
    fs::write(data.join("empty.bin"), b"").unwrap();

    let deep = data
        .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .join("cccccccccccccccccccccccccccccc");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep.txt"), b"deep").unwrap();

    let small = data.join("small");
    fs::create_dir_all(&small).unwrap();
    for i in 0..1200usize {
        fs::write(small.join(format!("f_{i:04}.txt")), format!("v{i}")).unwrap();
    }

    pack::pack(pack_args(root, vec![data.clone()], "pass")).unwrap();
    unpack::unpack(UnpackArgs {
        archive: root.join("archive.noer"),
        password: Some("pass".to_string()),
        keyfile: None,
        age_identities: Vec::new(),
        output: Some(root.join("out")),
        checksum_file: None,
        checksum_algo: None,
    })
    .unwrap();

    assert_eq!(
        fs::read(root.join("out/data/space name.txt")).unwrap(),
        b"space".as_slice()
    );
    assert_eq!(
        fs::read(root.join("out/data/symbols_#[]{}!.txt")).unwrap(),
        b"symbols".as_slice()
    );
    assert_eq!(
        fs::read(root.join("out/data/unicode_arquivo_olA_\u{00FC}.txt")).unwrap(),
        b"unicode".as_slice()
    );
    assert_eq!(fs::read(root.join("out/data/empty.bin")).unwrap().len(), 0);
    assert_eq!(
        fs::read(
            root.join(
                "out/data/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/cccccccccccccccccccccccccccccc/deep.txt",
            ),
        )
        .unwrap(),
        b"deep".as_slice()
    );
    assert_eq!(
        fs::read(root.join("out/data/small/f_0999.txt")).unwrap(),
        b"v999".as_slice()
    );
}
