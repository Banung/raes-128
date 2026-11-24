//! GPUI-independent disk file encryption and decryption controller for AES-128.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::aes::{
    AesError, CipherMode, FirstBlockModeTrace, decrypt_with_trace, encrypt_with_trace,
};

use super::controller::{KeyFormat, parse_key_and_iv_fields};

/// Maximum input file size allowed for in-memory encryption and decryption (128 MiB).
pub const MAX_FILE_SIZE_BYTES: u64 = 128 * 1024 * 1024;

/// Errors returned by disk file encryption and decryption operations.
#[derive(Debug)]
pub enum FileCryptoError {
    EmptyInputPath,
    EmptyOutputPath,
    InputIsDirectory(PathBuf),
    InputNotRegularFile(PathBuf),
    OutputIsDirectory(PathBuf),
    SameInputAndOutputPath(PathBuf),
    FileTooLarge {
        actual: u64,
        max: u64,
    },
    Crypto(AesError),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for FileCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputPath => write!(f, "input file path is empty"),
            Self::EmptyOutputPath => write!(f, "output file path is empty"),
            Self::InputIsDirectory(path) => {
                write!(f, "input path is a directory: {}", path.display())
            }
            Self::InputNotRegularFile(path) => {
                write!(f, "input path is not a regular file: {}", path.display())
            }
            Self::OutputIsDirectory(path) => {
                write!(f, "output path is a directory: {}", path.display())
            }
            Self::SameInputAndOutputPath(path) => {
                write!(
                    f,
                    "input and output paths refer to the same file: {}",
                    path.display()
                )
            }
            Self::FileTooLarge { actual, max } => {
                write!(
                    f,
                    "input file is too large ({actual} bytes exceeds limit of {max} bytes)"
                )
            }
            Self::Crypto(err) => write!(f, "{err}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "failed to {operation} '{}': {source}", path.display()),
        }
    }
}

impl std::error::Error for FileCryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::EmptyInputPath
            | Self::EmptyOutputPath
            | Self::InputIsDirectory(_)
            | Self::InputNotRegularFile(_)
            | Self::OutputIsDirectory(_)
            | Self::SameInputAndOutputPath(_)
            | Self::FileTooLarge { .. } => None,
        }
    }
}

impl From<AesError> for FileCryptoError {
    fn from(err: AesError) -> Self {
        Self::Crypto(err)
    }
}

/// Parameters collected from the UI to encrypt or decrypt a file on disk.
#[derive(Debug, Clone, Copy)]
pub struct FileCryptoRequest<'a> {
    pub mode: CipherMode,
    pub key_format: KeyFormat,
    pub key_text: &'a str,
    pub iv_format: KeyFormat,
    pub iv_text: &'a str,
    pub input_path: &'a Path,
    pub output_path: &'a Path,
}

/// Output paths, byte counts, and optional block-0 trace returned by [`encrypt_file`] and [`decrypt_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCryptoSuccess {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub trace: Option<FirstBlockModeTrace>,
}

/// Computes a default output path in the same directory as `input` for encrypt or decrypt.
pub fn suggested_output_path(input: &Path, encrypt_op: bool) -> PathBuf {
    let Some(file_name) = input.file_name() else {
        return input.to_path_buf();
    };

    if encrypt_op {
        let mut name = file_name.to_os_string();
        name.push(".enc");
        return input.with_file_name(name);
    }

    if let Some(name_str) = file_name.to_str()
        && let Some(stripped) = name_str.strip_suffix(".enc")
        && !stripped.is_empty()
    {
        return input.with_file_name(stripped);
    }

    let mut name = file_name.to_os_string();
    name.push(".dec");
    input.with_file_name(name)
}

/// Validates paths, key/IV, and file metadata, then encrypts `input_path` to `output_path`.
pub fn encrypt_file(req: &FileCryptoRequest<'_>) -> Result<FileCryptoSuccess, FileCryptoError> {
    process_file(req, encrypt_with_trace)
}

/// Validates paths, key/IV, and file metadata, then decrypts `input_path` to `output_path`.
pub fn decrypt_file(req: &FileCryptoRequest<'_>) -> Result<FileCryptoSuccess, FileCryptoError> {
    process_file(req, decrypt_with_trace)
}

fn process_file(
    req: &FileCryptoRequest<'_>,
    cipher_op: fn(
        CipherMode,
        &[u8],
        Option<&[u8]>,
        &[u8],
    ) -> Result<(Vec<u8>, Option<FirstBlockModeTrace>), AesError>,
) -> Result<FileCryptoSuccess, FileCryptoError> {
    validate_paths_and_metadata(req.input_path, req.output_path)?;

    let (key, iv) = parse_key_and_iv_fields(
        req.mode,
        req.key_format,
        req.key_text,
        req.iv_format,
        req.iv_text,
    )?;

    let input_bytes = read_regular_file_bounded(req.input_path, MAX_FILE_SIZE_BYTES)?;

    let (output_bytes, trace) = cipher_op(
        req.mode,
        &key,
        iv.as_ref().map(|bytes| bytes.as_slice()),
        &input_bytes,
    )?;

    write_bytes_atomically(req.output_path, &output_bytes)?;

    Ok(FileCryptoSuccess {
        input_path: req.input_path.to_path_buf(),
        output_path: req.output_path.to_path_buf(),
        input_bytes: input_bytes.len(),
        output_bytes: output_bytes.len(),
        trace,
    })
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, FileCryptoError> {
    let file = File::open(path).map_err(|source| FileCryptoError::Io {
        operation: "open input file",
        path: path.to_path_buf(),
        source,
    })?;

    let meta = file.metadata().map_err(|source| FileCryptoError::Io {
        operation: "inspect input file",
        path: path.to_path_buf(),
        source,
    })?;

    if meta.is_dir() {
        return Err(FileCryptoError::InputIsDirectory(path.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(FileCryptoError::InputNotRegularFile(path.to_path_buf()));
    }
    if meta.len() > max_bytes {
        return Err(FileCryptoError::FileTooLarge {
            actual: meta.len(),
            max: max_bytes,
        });
    }

    let initial_cap = usize::try_from(meta.len().min(max_bytes)).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(initial_cap);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| FileCryptoError::Io {
            operation: "read input file",
            path: path.to_path_buf(),
            source,
        })?;

    if (buf.len() as u64) > max_bytes {
        return Err(FileCryptoError::FileTooLarge {
            actual: buf.len() as u64,
            max: max_bytes,
        });
    }

    Ok(buf)
}

fn validate_paths_and_metadata(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), FileCryptoError> {
    if input_path.as_os_str().is_empty() {
        return Err(FileCryptoError::EmptyInputPath);
    }
    if output_path.as_os_str().is_empty() {
        return Err(FileCryptoError::EmptyOutputPath);
    }

    let meta = std::fs::metadata(input_path).map_err(|source| FileCryptoError::Io {
        operation: "inspect input file",
        path: input_path.to_path_buf(),
        source,
    })?;

    if meta.is_dir() {
        return Err(FileCryptoError::InputIsDirectory(input_path.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(FileCryptoError::InputNotRegularFile(
            input_path.to_path_buf(),
        ));
    }
    if meta.len() > MAX_FILE_SIZE_BYTES {
        return Err(FileCryptoError::FileTooLarge {
            actual: meta.len(),
            max: MAX_FILE_SIZE_BYTES,
        });
    }

    if std::fs::metadata(output_path).is_ok_and(|out_meta| out_meta.is_dir()) {
        return Err(FileCryptoError::OutputIsDirectory(
            output_path.to_path_buf(),
        ));
    }

    if paths_refer_to_same_file(input_path, output_path) {
        return Err(FileCryptoError::SameInputAndOutputPath(
            output_path.to_path_buf(),
        ));
    }

    Ok(())
}

fn parent_dir_or_dot(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn paths_refer_to_same_file(input_path: &Path, output_path: &Path) -> bool {
    if input_path == output_path {
        return true;
    }

    let Ok(canonical_input) = std::fs::canonicalize(input_path) else {
        return false;
    };

    let canonical_output = match std::fs::canonicalize(output_path) {
        Ok(path) => path,
        Err(_) => {
            let Some(file_name) = output_path.file_name() else {
                return false;
            };
            let Ok(canonical_parent) = std::fs::canonicalize(parent_dir_or_dot(output_path))
            else {
                return false;
            };
            canonical_parent.join(file_name)
        }
    };

    canonical_input == canonical_output
}

fn write_bytes_atomically(output_path: &Path, data: &[u8]) -> Result<(), FileCryptoError> {
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent_dir = parent_dir_or_dot(output_path);
    let pid = std::process::id();

    let (mut file, tmp_path) = loop {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = parent_dir.join(format!(".raes-128.{pid}.{seq}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => break (file, tmp_path),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(FileCryptoError::Io {
                    operation: "create temporary output file",
                    path: tmp_path,
                    source,
                });
            }
        }
    };

    if let Err(source) = file.write_all(data) {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FileCryptoError::Io {
            operation: "write temporary output file",
            path: tmp_path,
            source,
        });
    }

    if let Err(source) = file.flush() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FileCryptoError::Io {
            operation: "flush temporary output file",
            path: tmp_path,
            source,
        });
    }

    drop(file);

    if let Err(source) = std::fs::rename(&tmp_path, output_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FileCryptoError::Io {
            operation: "rename temporary output file",
            path: output_path.to_path_buf(),
            source,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const HEX_KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const HEX_IV: &str = "101112131415161718191a1b1c1d1e1f";

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
            let pid = std::process::id();
            loop {
                let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!("raes_128_{label}_{pid}_{seq}"));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                    Err(err) => panic!("failed to create temp test dir {}: {err}", path.display()),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn base_request<'a>(
        mode: CipherMode,
        input_path: &'a Path,
        output_path: &'a Path,
    ) -> FileCryptoRequest<'a> {
        FileCryptoRequest {
            mode,
            key_format: KeyFormat::Hex,
            key_text: HEX_KEY,
            iv_format: KeyFormat::Hex,
            iv_text: HEX_IV,
            input_path,
            output_path,
        }
    }

    #[test]
    fn round_trip_arbitrary_binary_file_all_modes() {
        let dir = TempDirGuard::new("binary_round_trip");
        let mut payload = Vec::with_capacity(256 * 3 + 7);
        for _ in 0..3 {
            payload.extend(0u8..=255u8);
        }
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80]);

        for mode in CipherMode::ALL {
            let tag = mode.name().to_lowercase();
            let plain_path = dir.path().join(format!("sample_{tag}.bin"));
            let enc_path = suggested_output_path(&plain_path, true);
            let dec_path = dir.path().join(format!("restored_{tag}.bin"));

            std::fs::write(&plain_path, &payload).unwrap();

            let enc = encrypt_file(&base_request(mode, &plain_path, &enc_path))
                .expect("file encrypt should succeed");
            assert_eq!(enc.input_path, plain_path);
            assert_eq!(enc.output_path, enc_path);
            assert_eq!(enc.input_bytes, payload.len());
            assert_ne!(std::fs::read(&enc_path).unwrap(), payload);

            let dec = decrypt_file(&base_request(mode, &enc_path, &dec_path))
                .expect("file decrypt should succeed");
            assert_eq!(dec.input_path, enc_path);
            assert_eq!(dec.output_path, dec_path);
            assert_eq!(dec.input_bytes, enc.output_bytes);
            assert_eq!(dec.output_bytes, payload.len());
            assert_eq!(std::fs::read(&dec_path).unwrap(), payload);
        }
    }

    #[test]
    fn round_trip_empty_file_all_modes() {
        let dir = TempDirGuard::new("empty_round_trip");
        let plain_path = dir.path().join("empty.bin");
        std::fs::write(&plain_path, b"").unwrap();

        for mode in CipherMode::ALL {
            let tag = mode.name().to_lowercase();
            let enc_path = dir.path().join(format!("empty_{tag}.enc"));
            let dec_path = dir.path().join(format!("empty_{tag}.dec"));

            let enc = encrypt_file(&base_request(mode, &plain_path, &enc_path))
                .expect("empty file encrypt should succeed");
            assert_eq!(enc.input_bytes, 0);

            let dec = decrypt_file(&base_request(mode, &enc_path, &dec_path))
                .expect("empty file decrypt should succeed");
            assert_eq!(dec.output_bytes, 0);
            assert!(std::fs::read(&dec_path).unwrap().is_empty());
        }
    }

    #[test]
    fn suggested_output_path_handles_edge_cases() {
        assert_eq!(
            suggested_output_path(Path::new("photo.png"), true),
            PathBuf::from("photo.png.enc")
        );
        assert_eq!(
            suggested_output_path(Path::new("archive"), true),
            PathBuf::from("archive.enc")
        );
        assert_eq!(
            suggested_output_path(Path::new("photo.png.enc"), false),
            PathBuf::from("photo.png")
        );
        assert_eq!(
            suggested_output_path(Path::new(".enc"), false),
            PathBuf::from(".enc.dec")
        );
        assert_eq!(
            suggested_output_path(Path::new("data.bin"), false),
            PathBuf::from("data.bin.dec")
        );
        assert_eq!(
            suggested_output_path(Path::new("/tmp/dir/a.txt"), true),
            PathBuf::from("/tmp/dir/a.txt.enc")
        );
        assert_eq!(
            suggested_output_path(Path::new("/tmp/dir/a.txt.enc"), false),
            PathBuf::from("/tmp/dir/a.txt")
        );
    }

    #[test]
    fn rejects_invalid_paths_and_directories() {
        let dir = TempDirGuard::new("path_errors");
        let file_path = dir.path().join("sample.bin");
        std::fs::write(&file_path, b"hello").unwrap();
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let empty_in = encrypt_file(&base_request(CipherMode::Ecb, Path::new(""), &file_path));
        assert!(matches!(empty_in, Err(FileCryptoError::EmptyInputPath)));

        let empty_out = encrypt_file(&base_request(CipherMode::Ecb, &file_path, Path::new("")));
        assert!(matches!(empty_out, Err(FileCryptoError::EmptyOutputPath)));

        let missing = dir.path().join("does_not_exist.bin");
        let missing_err = encrypt_file(&base_request(CipherMode::Ecb, &missing, &file_path));
        assert!(matches!(
            missing_err,
            Err(FileCryptoError::Io {
                operation: "inspect input file",
                ..
            })
        ));
        assert!(missing_err.unwrap_err().source().is_some());

        let dir_in = encrypt_file(&base_request(
            CipherMode::Ecb,
            &subdir,
            &dir.path().join("out.enc"),
        ));
        assert!(matches!(dir_in, Err(FileCryptoError::InputIsDirectory(_))));

        let dir_out = encrypt_file(&base_request(CipherMode::Ecb, &file_path, &subdir));
        assert!(matches!(
            dir_out,
            Err(FileCryptoError::OutputIsDirectory(_))
        ));
    }

    #[test]
    fn rejects_same_input_and_output_path_including_canonical_alias() {
        let dir = TempDirGuard::new("same_path");
        let file_path = dir.path().join("sample.bin");
        std::fs::write(&file_path, b"do not clobber").unwrap();

        let literal = encrypt_file(&base_request(CipherMode::Cbc, &file_path, &file_path));
        assert!(matches!(
            literal,
            Err(FileCryptoError::SameInputAndOutputPath(_))
        ));

        let alias_path = dir.path().join(".").join("sample.bin");
        let canonical_err =
            decrypt_file(&base_request(CipherMode::Cbc, &file_path, &alias_path));
        assert!(matches!(
            canonical_err,
            Err(FileCryptoError::SameInputAndOutputPath(_))
        ));

        assert_eq!(std::fs::read(&file_path).unwrap(), b"do not clobber");
    }

    #[test]
    fn validates_key_and_iv_before_writing_output() {
        let dir = TempDirGuard::new("key_iv_validation");
        let input_path = dir.path().join("plain.txt");
        let output_path = dir.path().join("plain.txt.enc");
        std::fs::write(&input_path, b"secret").unwrap();

        let bad_key = FileCryptoRequest {
            key_text: "short",
            key_format: KeyFormat::Utf8,
            ..base_request(CipherMode::Ecb, &input_path, &output_path)
        };
        let err = encrypt_file(&bad_key).unwrap_err();
        assert!(matches!(
            err,
            FileCryptoError::Crypto(AesError::InvalidKeyLength {
                expected: 16,
                actual: 5
            })
        ));
        assert!(err.source().is_some());
        assert!(!output_path.exists());

        let non_hex_key = FileCryptoRequest {
            key_text: "not-valid-hex",
            ..base_request(CipherMode::Ecb, &input_path, &output_path)
        };
        assert!(matches!(
            encrypt_file(&non_hex_key),
            Err(FileCryptoError::Crypto(AesError::InvalidHex(_)))
        ));
        assert!(!output_path.exists());

        let missing_iv = FileCryptoRequest {
            iv_text: "   ",
            ..base_request(CipherMode::Cbc, &input_path, &output_path)
        };
        assert!(matches!(
            encrypt_file(&missing_iv),
            Err(FileCryptoError::Crypto(AesError::MissingIv))
        ));
        assert!(!output_path.exists());

        let bad_iv = FileCryptoRequest {
            iv_text: "0011",
            ..base_request(CipherMode::Ctr, &input_path, &output_path)
        };
        assert!(matches!(
            encrypt_file(&bad_iv),
            Err(FileCryptoError::Crypto(AesError::InvalidIvLength {
                expected: 16,
                actual: 2
            }))
        ));
        assert!(!output_path.exists());
    }

    #[test]
    fn failed_decrypt_leaves_no_output_or_temp_files() {
        let dir = TempDirGuard::new("failed_decrypt");
        let bad_cipher_path = dir.path().join("corrupt.enc");
        std::fs::write(&bad_cipher_path, b"not-a-valid-block").unwrap();

        let non_existent_out = dir.path().join("should_not_exist.dec");
        let err = decrypt_file(&base_request(
            CipherMode::Cbc,
            &bad_cipher_path,
            &non_existent_out,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            FileCryptoError::Crypto(AesError::InvalidCiphertextLength { actual: 17 })
        ));
        assert!(!non_existent_out.exists());

        let existing_out = dir.path().join("existing.dec");
        std::fs::write(&existing_out, b"original-contents").unwrap();
        let bad_padding_path = dir.path().join("bad_pad.enc");
        std::fs::write(&bad_padding_path, [0x42u8; 16]).unwrap();

        let err_pad = decrypt_file(&base_request(
            CipherMode::Cbc,
            &bad_padding_path,
            &existing_out,
        ))
        .unwrap_err();
        assert!(matches!(
            err_pad,
            FileCryptoError::Crypto(AesError::InvalidPadding)
        ));
        assert_eq!(std::fs::read(&existing_out).unwrap(), b"original-contents");

        let mut entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["bad_pad.enc", "corrupt.enc", "existing.dec"]);
    }

    #[test]
    fn read_regular_file_bounded_enforces_max_bytes() {
        let dir = TempDirGuard::new("bounded_read");
        let exact_path = dir.path().join("exact_16.bin");
        let exact_data = [0xabu8; 16];
        std::fs::write(&exact_path, exact_data).unwrap();

        let read_back = read_regular_file_bounded(&exact_path, 16).unwrap();
        assert_eq!(read_back, exact_data);

        let too_large_path = dir.path().join("over_17.bin");
        std::fs::write(&too_large_path, [0xcdu8; 17]).unwrap();

        let err = read_regular_file_bounded(&too_large_path, 16).unwrap_err();
        assert!(matches!(
            err,
            FileCryptoError::FileTooLarge {
                actual: 17,
                max: 16
            }
        ));
        assert!(err.source().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_regular_input_file_without_reading() {
        let dir = TempDirGuard::new("non_regular");
        let out_path = dir.path().join("zero.enc");

        let err = encrypt_file(&base_request(
            CipherMode::Ecb,
            Path::new("/dev/zero"),
            &out_path,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            FileCryptoError::InputNotRegularFile(ref path) if path == Path::new("/dev/zero")
        ));
        assert!(err.source().is_none());
        assert!(err.to_string().contains("not a regular file"));
        assert!(!out_path.exists());
    }
}
