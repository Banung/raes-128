//! Step-by-step AES-128 trace data structures, formatting, and verification tests.

use std::fmt::Write;

use super::cipher::BLOCK_SIZE;
use super::encoding::hex_encode;
use super::modes::CipherMode;

/// Direction of an AES-128 cipher or mode operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDirection {
    Encrypt,
    Decrypt,
}

impl TraceDirection {
    /// Returns the human-readable label for this direction.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

/// A single AES-128 transformation step and its resulting 16-byte state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStep {
    pub name: &'static str,
    pub state: [u8; BLOCK_SIZE],
    pub round_key: Option<[u8; BLOCK_SIZE]>,
}

/// Recorded transformation steps for a single AES-128 round (`0..=10`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTrace {
    pub title: String,
    pub round_index: usize,
    pub steps: Vec<TraceStep>,
}

/// Complete 11-round (`0..=10`) trace of a single 16-byte AES-128 block operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTrace {
    pub direction: TraceDirection,
    pub cipher_input: [u8; BLOCK_SIZE],
    pub cipher_output: [u8; BLOCK_SIZE],
    pub round_keys: [[u8; BLOCK_SIZE]; 11],
    pub rounds: Vec<RoundTrace>,
}

impl BlockTrace {
    /// Returns the three key summary rounds: Initial Round (0), Round 1, and Final Round (10).
    pub fn summary_rounds(&self) -> [&RoundTrace; 3] {
        [&self.rounds[0], &self.rounds[1], &self.rounds[10]]
    }

    /// Returns all 11 recorded rounds (`0..=10`).
    pub fn all_rounds(&self) -> &[RoundTrace] {
        &self.rounds
    }
}

/// First-block trace combining mode-level chaining/keystream context with the AES core trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstBlockModeTrace {
    pub mode: CipherMode,
    pub operation: TraceDirection,
    pub note: String,
    pub source_block: Vec<u8>,
    pub iv: Option<[u8; BLOCK_SIZE]>,
    pub result_block: Vec<u8>,
    pub block_trace: BlockTrace,
}

/// Formats a 16-byte AES state as a 4-row column-major 4x4 hexadecimal matrix (FIPS 197).
pub fn format_state_matrix(state: &[u8; BLOCK_SIZE]) -> [String; 4] {
    std::array::from_fn(|r| {
        format!(
            "{:02x} {:02x} {:02x} {:02x}",
            state[r],
            state[4 + r],
            state[8 + r],
            state[12 + r]
        )
    })
}

/// Formats a [`FirstBlockModeTrace`] as a deterministic monospace report.
///
/// When `show_all_rounds` is `false`, only Initial Round (0), Round 1, Final Round (10),
/// and keys `K0`, `K1`, `K10` are shown; when `true`, all 11 rounds and keys `K0..=K10`
/// are included.
pub fn format_trace_text(trace: &FirstBlockModeTrace, show_all_rounds: bool) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== AES-128 Step-by-Step Trace (Block 0) ===");
    let _ = writeln!(out, "Mode:                  AES-128-{}", trace.mode.name());
    let _ = writeln!(out, "Operation:             {}", trace.operation.label());
    let _ = writeln!(
        out,
        "Cipher Core Direction: {}",
        trace.block_trace.direction.label()
    );
    let _ = writeln!(out, "Mode Block-0 Note:     {}", trace.note);
    let _ = writeln!(out);

    let _ = writeln!(out, "--- Block-0 Summary ---");
    let _ = writeln!(
        out,
        "Source Block (hex):    {}",
        hex_encode(&trace.source_block)
    );
    if let Some(iv) = &trace.iv {
        let _ = writeln!(out, "IV / Counter (hex):    {}", hex_encode(iv));
    }
    let _ = writeln!(
        out,
        "Cipher Input (hex):    {}",
        hex_encode(&trace.block_trace.cipher_input)
    );
    for row in format_state_matrix(&trace.block_trace.cipher_input) {
        let _ = writeln!(out, "                       [ {row} ]");
    }
    let _ = writeln!(
        out,
        "Cipher Output (hex):   {}",
        hex_encode(&trace.block_trace.cipher_output)
    );
    let _ = writeln!(
        out,
        "Mode Output Block 0:   {}",
        hex_encode(&trace.result_block)
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "--- Round Keys ---");
    if show_all_rounds {
        for (idx, rk) in trace.block_trace.round_keys.iter().enumerate() {
            let _ = writeln!(out, "K{idx:<2} = {}", hex_encode(rk));
        }
    } else {
        for idx in [0usize, 1, 10] {
            let _ = writeln!(
                out,
                "K{idx:<2} = {}",
                hex_encode(&trace.block_trace.round_keys[idx])
            );
        }
        let _ = writeln!(out, "(Intermediate keys K2..=K9 omitted in summary view)");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "--- Rounds ---");
    if show_all_rounds {
        for round in trace.block_trace.all_rounds() {
            write_round_section(&mut out, round);
        }
    } else {
        let [initial, round_1, final_round] = trace.block_trace.summary_rounds();
        write_round_section(&mut out, initial);
        write_round_section(&mut out, round_1);
        let _ = writeln!(out, "[... Omitted intermediate rounds 2..=9 in summary view ...]");
        let _ = writeln!(out);
        write_round_section(&mut out, final_round);
    }

    out
}

fn write_round_section(out: &mut String, round: &RoundTrace) {
    let _ = writeln!(out, "{}", round.title);
    for step in &round.steps {
        let _ = writeln!(out, "  {:<13} State: {}", step.name, hex_encode(&step.state));
        if let Some(rk) = &step.round_key {
            let _ = writeln!(out, "                RoundKey: {}", hex_encode(rk));
        }
        for row in format_state_matrix(&step.state) {
            let _ = writeln!(out, "                [ {row} ]");
        }
    }
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::cipher::Aes128;
    use crate::aes::encoding::hex_decode;
    use crate::aes::modes::{decrypt, decrypt_with_trace, encrypt, encrypt_with_trace};

    const APPENDIX_B_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const APPENDIX_B_PLAINTEXT: &str = "3243f6a8885a308d313198a2e0370734";

    #[test]
    fn format_state_matrix_matches_fips_197_column_major_layout() {
        let state: [u8; BLOCK_SIZE] = hex_decode(APPENDIX_B_PLAINTEXT)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            format_state_matrix(&state),
            [
                "32 88 31 e0".to_string(),
                "43 5a 31 37".to_string(),
                "f6 30 98 07".to_string(),
                "a8 8d a2 34".to_string(),
            ]
        );
    }

    #[test]
    fn fips_197_appendix_b_block_trace_values() {
        let key: [u8; BLOCK_SIZE] = hex_decode(APPENDIX_B_KEY).unwrap().try_into().unwrap();
        let plaintext: [u8; BLOCK_SIZE] = hex_decode(APPENDIX_B_PLAINTEXT)
            .unwrap()
            .try_into()
            .unwrap();

        let cipher = Aes128::new(key);
        let (ciphertext, trace) = cipher.encrypt_block_with_trace(plaintext);

        assert_eq!(trace.direction, TraceDirection::Encrypt);
        assert_eq!(trace.cipher_input, plaintext);
        assert_eq!(trace.cipher_output, ciphertext);
        assert_eq!(trace.all_rounds().len(), 11);

        // Round 0: AddRoundKey
        assert_eq!(trace.rounds[0].round_index, 0);
        assert_eq!(trace.rounds[0].steps.len(), 1);
        assert_eq!(trace.rounds[0].steps[0].name, "AddRoundKey");
        assert_eq!(
            hex_encode(&trace.rounds[0].steps[0].state),
            "193de3bea0f4e22b9ac68d2ae9f84808"
        );
        assert_eq!(trace.rounds[0].steps[0].round_key, Some(key));

        // Round 1: SubBytes, ShiftRows, MixColumns, AddRoundKey
        assert_eq!(trace.rounds[1].round_index, 1);
        assert_eq!(trace.rounds[1].steps.len(), 4);
        assert_eq!(trace.rounds[1].steps[0].name, "SubBytes");
        assert_eq!(
            hex_encode(&trace.rounds[1].steps[0].state),
            "d42711aee0bf98f1b8b45de51e415230"
        );
        assert_eq!(trace.rounds[1].steps[1].name, "ShiftRows");
        assert_eq!(
            hex_encode(&trace.rounds[1].steps[1].state),
            "d4bf5d30e0b452aeb84111f11e2798e5"
        );
        assert_eq!(trace.rounds[1].steps[2].name, "MixColumns");
        assert_eq!(
            hex_encode(&trace.rounds[1].steps[2].state),
            "046681e5e0cb199a48f8d37a2806264c"
        );
        assert_eq!(trace.rounds[1].steps[3].name, "AddRoundKey");
        assert_eq!(
            hex_encode(&trace.rounds[1].steps[3].round_key.unwrap()),
            "a0fafe1788542cb123a339392a6c7605"
        );
        assert_eq!(
            hex_encode(&trace.rounds[1].steps[3].state),
            "a49c7ff2689f352b6b5bea43026a5049"
        );

        // Round 10: SubBytes, ShiftRows, AddRoundKey
        assert_eq!(trace.rounds[10].round_index, 10);
        assert_eq!(trace.rounds[10].steps.len(), 3);
        assert_eq!(trace.rounds[10].steps[2].name, "AddRoundKey");
        assert_eq!(
            hex_encode(&trace.rounds[10].steps[2].round_key.unwrap()),
            "d014f9a8c9ee2589e13f0cc8b6630ca6"
        );
        assert_eq!(
            hex_encode(&trace.rounds[10].steps[2].state),
            "3925841d02dc09fbdc118597196a0b32"
        );
        assert_eq!(hex_encode(&ciphertext), "3925841d02dc09fbdc118597196a0b32");

        // summary_rounds returns [round 0, round 1, round 10]
        let summary = trace.summary_rounds();
        assert_eq!(summary[0], &trace.rounds[0]);
        assert_eq!(summary[1], &trace.rounds[1]);
        assert_eq!(summary[2], &trace.rounds[10]);

        // decrypt_block_with_trace matches decrypt_block and recovers plaintext
        let (recovered, dec_trace) = cipher.decrypt_block_with_trace(ciphertext);
        assert_eq!(recovered, plaintext);
        assert_eq!(recovered, cipher.decrypt_block(ciphertext));
        assert_eq!(dec_trace.direction, TraceDirection::Decrypt);
        assert_eq!(dec_trace.cipher_input, ciphertext);
        assert_eq!(dec_trace.cipher_output, plaintext);
        assert_eq!(dec_trace.all_rounds().len(), 11);
        assert_eq!(dec_trace.rounds[0].steps[0].round_key, Some(trace.round_keys[10]));
        assert_eq!(dec_trace.rounds[10].steps[2].round_key, Some(trace.round_keys[0]));
    }

    #[test]
    fn format_trace_text_summary_and_full_views() {
        let key = hex_decode(APPENDIX_B_KEY).unwrap();
        let pt = hex_decode(APPENDIX_B_PLAINTEXT).unwrap();
        let (_, trace) = encrypt_with_trace(CipherMode::Ecb, &key, None, &pt).unwrap();
        let trace = trace.expect("ECB always produces a block-0 trace");

        let summary_text = format_trace_text(&trace, false);
        assert!(summary_text.contains("Initial Round"));
        assert!(summary_text.contains("Round 1"));
        assert!(summary_text.contains("Final Round"));
        assert!(summary_text.contains("SubBytes"));
        assert!(summary_text.contains("ShiftRows"));
        assert!(summary_text.contains("MixColumns"));
        assert!(summary_text.contains("AddRoundKey"));
        assert!(!summary_text.contains("Round 5"));

        let full_text = format_trace_text(&trace, true);
        assert!(full_text.contains("Round 5"));
        assert!(full_text.contains("K5"));
    }

    #[test]
    fn modes_with_trace_match_standard_encrypt_decrypt_across_all_modes() {
        let key = hex_decode(APPENDIX_B_KEY).unwrap();
        let iv = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();

        for mode in CipherMode::ALL {
            let mode_iv = mode.requires_iv().then_some(iv.as_slice());

            for len in [0usize, 1, 15, 16, 17, 40] {
                let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
                let expected_ct = encrypt(mode, &key, mode_iv, &pt).unwrap();
                let (ct, enc_trace) = encrypt_with_trace(mode, &key, mode_iv, &pt).unwrap();
                assert_eq!(
                    ct,
                    expected_ct,
                    "encrypt_with_trace mismatch for mode {} len {len}",
                    mode.name()
                );

                let expected_pt = decrypt(mode, &key, mode_iv, &ct).unwrap();
                let (recovered, dec_trace) = decrypt_with_trace(mode, &key, mode_iv, &ct).unwrap();
                assert_eq!(
                    recovered,
                    expected_pt,
                    "decrypt_with_trace mismatch for mode {} len {len}",
                    mode.name()
                );

                if len == 0 && matches!(mode, CipherMode::Cfb | CipherMode::Ofb | CipherMode::Ctr) {
                    assert!(
                        enc_trace.is_none(),
                        "empty {} encrypt should return trace == None",
                        mode.name()
                    );
                    assert!(
                        dec_trace.is_none(),
                        "empty {} decrypt should return trace == None",
                        mode.name()
                    );
                } else {
                    let enc_t = enc_trace.expect("non-empty or padded mode should have trace");
                    let dec_t = dec_trace.expect("non-empty or padded mode should have trace");
                    assert_eq!(enc_t.mode, mode);
                    assert_eq!(enc_t.operation, TraceDirection::Encrypt);
                    assert_eq!(dec_t.mode, mode);
                    assert_eq!(dec_t.operation, TraceDirection::Decrypt);
                    if matches!(mode, CipherMode::Cfb | CipherMode::Ofb | CipherMode::Ctr) {
                        assert_eq!(dec_t.block_trace.direction, TraceDirection::Encrypt);
                    } else {
                        assert_eq!(dec_t.block_trace.direction, TraceDirection::Decrypt);
                    }
                }
            }
        }
    }
}
