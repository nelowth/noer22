use std::io::{self, Read, Write};
use zstd::zstd_safe::{CParameter, Strategy};

pub fn compress_reader_to_writer<R: Read, W: Write>(
    reader: &mut R,
    writer: W,
    level: i32,
    threads: usize,
    total_size: Option<u64>,
) -> io::Result<W> {
    let threads = threads.max(1);
    let mut encoder = zstd::stream::Encoder::new(writer, level)?;
    if let Some(size) = total_size {
        let _ = encoder.set_pledged_src_size(Some(size));
        let _ = encoder.include_contentsize(true);
    }
    if threads > 1 {
        encoder
            .multithread(threads as u32)
            .map_err(io::Error::other)?;
    }
    let _ = encoder.set_parameter(CParameter::Strategy(strategy_for_level(level)));
    if let Some(size) = total_size {
        let _ = encoder.set_parameter(CParameter::WindowLog(window_log_for_size(size)));
    }
    if should_enable_ldm(total_size, level) {
        let _ = encoder.set_parameter(CParameter::EnableLongDistanceMatching(true));
        if let Some(size) = total_size {
            let (min_match, hash_log, bucket_log, rate_log) = ldm_params(size, level);
            let _ = encoder.set_parameter(CParameter::LdmMinMatch(min_match));
            let _ = encoder.set_parameter(CParameter::LdmHashLog(hash_log));
            let _ = encoder.set_parameter(CParameter::LdmBucketSizeLog(bucket_log));
            let _ = encoder.set_parameter(CParameter::LdmHashRateLog(rate_log));
        }
    }
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buf[..n])?;
    }
    encoder.finish()
}

fn should_enable_ldm(total_size: Option<u64>, level: i32) -> bool {
    if level >= 9 {
        return true;
    }
    matches!(total_size, Some(size) if size >= 16 * 1024 * 1024)
}

fn window_log_for_size(size: u64) -> u32 {
    if size >= 2_u64.pow(31) {
        31
    } else if size >= 2_u64.pow(30) {
        30
    } else if size >= 2_u64.pow(29) {
        29
    } else if size >= 2_u64.pow(28) {
        28
    } else if size >= 2_u64.pow(27) {
        27
    } else if size >= 2_u64.pow(26) {
        26
    } else {
        23
    }
}

fn strategy_for_level(level: i32) -> Strategy {
    match level {
        l if l <= 2 => Strategy::ZSTD_fast,
        l if l <= 4 => Strategy::ZSTD_dfast,
        l if l <= 6 => Strategy::ZSTD_greedy,
        l if l <= 8 => Strategy::ZSTD_lazy,
        l if l <= 10 => Strategy::ZSTD_lazy2,
        l if l <= 13 => Strategy::ZSTD_btlazy2,
        l if l <= 16 => Strategy::ZSTD_btopt,
        l if l <= 19 => Strategy::ZSTD_btultra,
        _ => Strategy::ZSTD_btultra2,
    }
}

fn ldm_params(size: u64, level: i32) -> (u32, u32, u32, u32) {
    let (min_match, hash_log) = if level >= 16 || size >= 1024 * 1024 * 1024 {
        (64, 24)
    } else if level >= 12 || size >= 256 * 1024 * 1024 {
        (48, 23)
    } else {
        (32, 22)
    };
    let bucket_log = if size >= 512 * 1024 * 1024 { 25 } else { 24 };
    let rate_log = if level >= 16 { 8 } else { 7 };
    (min_match, hash_log, bucket_log, rate_log)
}
