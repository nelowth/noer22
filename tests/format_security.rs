use noer22::format::{
    CompressionAlgo, CryptoAlgo, Header, HeaderFlags, KdfParams, HEADER_SIZE, KDF_ITERS_MAX,
    KDF_MEM_MAX_MIB,
};

fn base_header() -> Header {
    Header::new(
        CompressionAlgo::Zstd,
        CryptoAlgo::ChaCha20Poly1305,
        [7u8; 16],
        [1u8, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0],
        KdfParams {
            mem_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        },
        HeaderFlags::default(),
    )
}

#[test]
fn header_rejects_unknown_flags() {
    let mut bytes = base_header().to_bytes();
    bytes[52] |= 0b1000_0000;
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err.to_string().contains("unknown header flags"));
}

#[test]
fn header_rejects_nonzero_reserved_tail() {
    let mut bytes = base_header().to_bytes();
    bytes[HEADER_SIZE - 1] = 1;
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err.to_string().contains("reserved"));
}

#[test]
fn header_rejects_out_of_range_kdf() {
    let mut bytes = base_header().to_bytes();
    let mem_too_large = (KDF_MEM_MAX_MIB + 1) * 1024;
    bytes[40..44].copy_from_slice(&mem_too_large.to_le_bytes());
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err
        .to_string()
        .contains("kdf parameters outside supported range"));

    let mut bytes = base_header().to_bytes();
    let iters_too_large = KDF_ITERS_MAX + 1;
    bytes[44..48].copy_from_slice(&iters_too_large.to_le_bytes());
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err
        .to_string()
        .contains("kdf parameters outside supported range"));
}

#[test]
fn header_rejects_invalid_kdf_zero_and_non_mib_memory() {
    let mut bytes = base_header().to_bytes();
    bytes[40..44].copy_from_slice(&0u32.to_le_bytes());
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err.to_string().contains("invalid kdf parameters"));

    let mut bytes = base_header().to_bytes();
    bytes[40..44].copy_from_slice(&(65537u32).to_le_bytes());
    let err = Header::from_bytes(bytes).unwrap_err();
    assert!(err
        .to_string()
        .contains("kdf memory must be expressed in MiB"));
}
