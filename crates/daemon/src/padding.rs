//! EDNS(0) block padding for encrypted DNS queries (RFC 8467).
//!
//! Implements `specs/wp8-transport-privacy.md` §3.
//!
//! ## Behaviour
//!
//! - Every query sent over an **encrypted** rung (DoH h2, ODoH) carries an
//!   EDNS(0) Padding option (code 12) that brings the serialized DNS message to
//!   a multiple of 128 octets.
//! - Do53 rungs are **never** padded (RFC 7830 §6: padding on cleartext is a
//!   tracking vector, not a defence).
//! - DoH3 (hickory h3 rungs): hickory owns the QUIC serialization path; no
//!   seam is exposed.  Those rungs are unpadded in v1.  See the module doc in
//!   `upstream.rs` for the full seam-decision rationale.
//! - Gated by `privacy.doh_padding` (checked at rung-construction time in
//!   `upstream.rs` and `odoh.rs`).
//!
//! ## RFC 8467 algorithm (for QUERY messages)
//!
//! 1. Serialize the DNS message without padding.
//! 2. If no OPT record is present, add one (EDNS(0), zero options, max-payload
//!    4096, version 0).
//! 3. Compute the amount of padding needed to bring the TOTAL serialized length
//!    to a multiple of 128.  The Padding option header is 4 bytes (2-byte code
//!    + 2-byte length), plus the zero-filled padding data.
//! 4. Insert an `EdnsOption::Unknown(12, vec![0u8; padding_data_len])` option.
//!    This maps to `EdnsCode::Padding` on the wire.
//! 5. Re-serialize with the OPT record in place.
//!
//! The final wire length is guaranteed `% 128 == 0`.

use hickory_proto::{
    op::{Edns, Message},
    rr::rdata::opt::EdnsOption,
};
use thiserror::Error;

/// Padding block size (octets) per RFC 8467 §4.1.
pub(crate) const PADDING_BLOCK: usize = 128;

/// EDNS option code for Padding (RFC 7830).
///
/// `EdnsOption::Unknown(PADDING_CODE, data)` serialises as option-code 12 on
/// the wire.  hickory-proto 0.26.1 has `EdnsCode::Padding` as a variant but
/// no corresponding `EdnsOption::Padding` variant — the `Unknown` path is the
/// correct insertion mechanism.
const PADDING_CODE: u16 = 12;

/// Errors from the padding module.
#[derive(Debug, Error)]
pub enum PaddingError {
    /// Failed to build or serialize the DNS message.
    #[error("padding build error: {0}")]
    Build(String),
    /// The resulting message length is not a multiple of the block size.
    ///
    /// This is an internal invariant violation — should never happen.
    #[error("padding invariant violated: len={len} block={block}")]
    Invariant { len: usize, block: usize },
}

/// Apply RFC 8467 EDNS(0) block padding to a serialized DNS query.
///
/// `wire` must be a valid DNS wire-format message.  The function:
/// 1. Parses the message.
/// 2. Ensures an EDNS(0) OPT record is present (adds one if absent).
/// 3. Appends a Padding option with enough zero bytes to bring the
///    total serialized length to the next multiple of 128.
/// 4. Returns the new wire bytes.
///
/// # Errors
///
/// Returns `PaddingError::Build` if the message cannot be parsed or
/// re-serialized.  Returns `PaddingError::Invariant` if the invariant
/// `len % 128 == 0` is not met after applying padding (should never happen).
///
/// # Guarantee
///
/// On success: `result.len() % PADDING_BLOCK == 0`.
pub fn pad_dns_query(wire: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let mut msg =
        Message::from_vec(wire).map_err(|e| PaddingError::Build(format!("parse: {e}")))?;

    // Ensure an OPT record is present.
    if msg.edns.is_none() {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_version(0);
        msg.edns = Some(edns);
    }

    // Remove any existing Padding option (idempotency: re-padding must replace
    // the old padding, not stack on top of it, which would miscalculate the
    // base length).
    {
        let edns = msg.edns.as_mut().ok_or_else(|| {
            PaddingError::Build("EDNS section disappeared after init".to_string())
        })?;
        edns.options_mut()
            .options
            .retain(|(code, _)| u16::from(*code) != PADDING_CODE);
    }

    // First serialization: measure the length WITHOUT any padding option so we
    // know the exact number of zero bytes to add.
    let base_wire = msg
        .to_vec()
        .map_err(|e| PaddingError::Build(format!("serialize (base): {e}")))?;
    let base_len = base_wire.len();

    // Compute how many zero bytes of option DATA are needed.
    //
    // Each padding option adds:
    //   4 bytes of option header (2-byte code + 2-byte data-length)
    //   + padding_data_len bytes of zeros
    //
    // We need:  (base_len + 4 + padding_data_len) % 128 == 0
    // => padding_data_len = (128 - ((base_len + 4) % 128)) % 128
    let header_cost = 4usize; // option-code (2) + option-length (2)
    let after_header = base_len + header_cost;
    let padding_data_len = (PADDING_BLOCK - (after_header % PADDING_BLOCK)) % PADDING_BLOCK;

    // Insert the Padding option into the OPT record.
    // Safety: we ensured edns.is_some() above and only removed the padding
    // option from it — the EDNS section itself is still present.
    let edns = msg.edns.as_mut().ok_or_else(|| {
        PaddingError::Build("EDNS section disappeared after base serialize".to_string())
    })?;
    edns.options_mut().insert(EdnsOption::Unknown(
        PADDING_CODE,
        vec![0u8; padding_data_len],
    ));

    // Final serialization.
    let padded = msg
        .to_vec()
        .map_err(|e| PaddingError::Build(format!("serialize (padded): {e}")))?;

    // Invariant check.
    if padded.len() % PADDING_BLOCK != 0 {
        return Err(PaddingError::Invariant {
            len: padded.len(),
            block: PADDING_BLOCK,
        });
    }

    Ok(padded)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    /// Build a minimal DNS query wire message for the given domain name string.
    fn make_query(name: &str) -> Vec<u8> {
        let qname = Name::from_ascii(name).unwrap();
        let mut q = Query::new();
        q.set_name(qname);
        q.set_query_type(RecordType::A);

        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    // ── Padding alignment invariant ───────────────────────────────────────────

    /// Padded query length must be a multiple of 128 for every qname in
    /// the 1..=253 ASCII label-length range.
    ///
    /// Table-driven per `specs/wp8-transport-privacy.md` §7 (unit rows).
    #[test]
    fn padded_length_is_multiple_of_128_across_qname_lengths() {
        // Sample every qname length from 1 to 253 characters.
        for qlen in 1usize..=253 {
            // Build a query name with exactly `qlen` ASCII characters.
            // Use "a" repeated, split into ≤63-char labels to stay valid.
            let name = make_valid_qname(qlen);
            let wire = make_query(&name);
            let padded = pad_dns_query(&wire)
                .unwrap_or_else(|e| panic!("pad_dns_query failed for qlen={qlen}: {e}"));
            assert_eq!(
                padded.len() % PADDING_BLOCK,
                0,
                "padded length {len} is not a multiple of {PADDING_BLOCK} for qlen={qlen}",
                len = padded.len()
            );
        }
    }

    /// Padding is idempotent: calling pad_dns_query twice keeps alignment.
    #[test]
    fn padding_idempotent() {
        let wire = make_query("example.com");
        let once = pad_dns_query(&wire).unwrap();
        let twice = pad_dns_query(&once).unwrap();
        assert_eq!(once.len() % PADDING_BLOCK, 0);
        assert_eq!(twice.len() % PADDING_BLOCK, 0);
    }

    /// A message that already has an OPT record gets padding appended correctly.
    #[test]
    fn padding_with_existing_opt_record() {
        let qname = Name::from_ascii("test.example.com").unwrap();
        let mut q = Query::new();
        q.set_name(qname);
        q.set_query_type(RecordType::A);

        let mut msg = Message::new(0xABCD, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(q);
        // Explicitly add an EDNS record.
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        msg.edns = Some(edns);

        let wire = msg.to_vec().unwrap();
        let padded = pad_dns_query(&wire).unwrap();
        assert_eq!(padded.len() % PADDING_BLOCK, 0);
    }

    /// Re-applying padding to an already-padded message replaces the old
    /// Padding option and still produces a multiple-of-128 length.
    #[test]
    fn padding_replaces_existing_padding_option() {
        let wire = make_query("example.org");
        let once = pad_dns_query(&wire).unwrap();
        // Verify the already-padded message is valid DNS.
        let twice = pad_dns_query(&once).unwrap();
        assert_eq!(twice.len() % PADDING_BLOCK, 0);
    }

    // ── Correctness of parsed message ─────────────────────────────────────────

    /// The padded message round-trips through hickory-proto without error.
    #[test]
    fn padded_message_parses_correctly() {
        let wire = make_query("cloudflare.com");
        let padded = pad_dns_query(&wire).unwrap();
        let msg = Message::from_vec(&padded).expect("padded message must parse");
        assert!(
            !msg.queries.is_empty(),
            "query section must survive padding"
        );
        assert!(
            msg.edns.is_some(),
            "OPT record must be present after padding"
        );
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Build a well-formed domain name with approximately `target_len` ASCII
    /// characters in the presentation form.  Labels are at most 63 chars.
    fn make_valid_qname(target_len: usize) -> String {
        // Build labels of up to 63 chars each, total presentation length ≈
        // target_len.  Use letters only to stay within allowed label syntax.
        let char_set = b"abcdefghijklmnopqrstuvwxyz";
        let mut name = String::new();
        let mut remaining = target_len;
        let mut idx: usize = 0;

        while remaining > 0 {
            if !name.is_empty() {
                // Check we can fit at least "a." (2 chars)
                if remaining < 2 {
                    break;
                }
                name.push('.');
                remaining -= 1;
            }
            let label_len = remaining.min(63);
            for _ in 0..label_len {
                name.push(char_set[idx % char_set.len()] as char);
                idx += 1;
            }
            remaining = remaining.saturating_sub(label_len);
        }

        // Ensure we have at least one label.
        if name.is_empty() {
            name.push('a');
        }

        name
    }
}
