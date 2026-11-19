//! Pure-Rust hexadecimal and RFC 4648 Base64 encoders and decoders.

use super::AesError;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes a byte slice as lowercase hexadecimal text.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize] as char);
        out.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text (case-insensitive, surrounding whitespace trimmed) into bytes.
pub fn hex_decode(input: &str) -> Result<Vec<u8>, AesError> {
    let trimmed = input.trim();
    if trimmed.len() % 2 != 0 {
        return Err(AesError::InvalidHex(format!(
            "odd hex length: {} characters",
            trimmed.len()
        )));
    }

    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (idx, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = decode_hex_nibble(pair[0], idx * 2)?;
        let lo = decode_hex_nibble(pair[1], idx * 2 + 1)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8, pos: usize) -> Result<u8, AesError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AesError::InvalidHex(format!(
            "invalid hex character {:?} at offset {pos}",
            byte as char
        ))),
    }
}

/// Encodes a byte slice using standard RFC 4648 Base64 with `=` padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        out.push(BASE64_ALPHABET[b0 >> 2] as char);
        out.push(BASE64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes standard RFC 4648 Base64 text (ignoring ASCII whitespace) into bytes.
///
/// Rejects non-multiple-of-4 lengths, invalid characters, misplaced `=` padding,
/// and non-zero unused trailing bits before padding.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, AesError> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    if cleaned.len() % 4 != 0 {
        return Err(AesError::InvalidBase64(format!(
            "length {} is not a multiple of 4",
            cleaned.len()
        )));
    }

    let num_chunks = cleaned.len() / 4;
    let mut out = Vec::with_capacity(num_chunks * 3);

    for (chunk_idx, chunk) in cleaned.chunks_exact(4).enumerate() {
        let is_last = chunk_idx + 1 == num_chunks;
        let a = decode_b64_char(chunk[0])?;
        let b = decode_b64_char(chunk[1])?;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') if is_last => {
                if (b & 0x0f) != 0 {
                    return Err(AesError::InvalidBase64(
                        "non-zero trailing bits before '==' padding".to_string(),
                    ));
                }
                out.push((a << 2) | (b >> 4));
            }
            (b'=', _) => {
                return Err(AesError::InvalidBase64(
                    "invalid '=' padding placement".to_string(),
                ));
            }
            (c_byte, b'=') if is_last => {
                let c = decode_b64_char(c_byte)?;
                if (c & 0x03) != 0 {
                    return Err(AesError::InvalidBase64(
                        "non-zero trailing bits before '=' padding".to_string(),
                    ));
                }
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
            }
            (_, b'=') => {
                return Err(AesError::InvalidBase64(
                    "padding '=' may only appear at the end of input".to_string(),
                ));
            }
            (c_byte, d_byte) => {
                let c = decode_b64_char(c_byte)?;
                let d = decode_b64_char(d_byte)?;
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
                out.push(((c & 0x03) << 6) | d);
            }
        }
    }

    Ok(out)
}

fn decode_b64_char(byte: u8) -> Result<u8, AesError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(AesError::InvalidBase64(format!(
            "invalid base64 character {:?}",
            byte as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_case_tolerance() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());

        let raw = [0x00, 0x0f, 0x10, 0xab, 0xcd, 0xef, 0xff];
        assert_eq!(hex_encode(&raw), "000f10abcdefff");
        assert_eq!(hex_decode("  000F10AbCdEfFF \n\t").unwrap(), raw);
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert!(matches!(hex_decode("abc"), Err(AesError::InvalidHex(_))));
        assert!(matches!(hex_decode("0g"), Err(AesError::InvalidHex(_))));
        assert!(matches!(hex_decode("12 34"), Err(AesError::InvalidHex(_))));
    }

    #[test]
    fn base64_rfc4648_vectors() {
        let vectors = [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "Zg=="),
            (b"fo".as_slice(), "Zm8="),
            (b"foo".as_slice(), "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg=="),
            (b"fooba".as_slice(), "Zm9vYmE="),
            (b"foobar".as_slice(), "Zm9vYmFy"),
        ];

        for (raw, encoded) in vectors {
            assert_eq!(base64_encode(raw), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), raw);
        }
    }

    #[test]
    fn base64_ignores_ascii_whitespace() {
        let decoded = base64_decode("  Zm9v\n YmFy \t").unwrap();
        assert_eq!(decoded, b"foobar");
    }

    #[test]
    fn base64_rejects_malformed_inputs() {
        // Bad length
        assert!(matches!(base64_decode("Zg="), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("abcde"), Err(AesError::InvalidBase64(_))));

        // Invalid characters (including URL-safe '-'/'_')
        assert!(matches!(base64_decode("Zm9-"), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("Zm9_"), Err(AesError::InvalidBase64(_))));

        // Misplaced padding
        assert!(matches!(base64_decode("===="), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("Z=g="), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("Zg=A"), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("Zm8=Zm8="), Err(AesError::InvalidBase64(_))));

        // Non-canonical trailing bits before padding
        assert!(matches!(base64_decode("AB=="), Err(AesError::InvalidBase64(_))));
        assert!(matches!(base64_decode("Zm9="), Err(AesError::InvalidBase64(_))));
    }
}
