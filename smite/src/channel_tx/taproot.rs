//! Simple taproot channel output scripts.
//!
//! Every commitment output of a simple taproot channel is a P2TR output whose
//! key commits to a tapscript tree. This module builds those `script_pubkey`s.
//! The forms here are the ones negotiated by the `option_simple_taproot`
//! channel type (BOLT 9 bit 80), which is what lnd calls its "final" taproot
//! commitment and what the spec's test vectors encode.

use bitcoin::ScriptBuf;
use bitcoin::secp256k1::XOnlyPublicKey;

/// Builds the funding output `script_pubkey` for a simple taproot channel.
///
/// `aggregate_funding_key` is the `MuSig2` aggregate of both `funding_pubkey`s
/// with the BIP 86 tweak already applied, so the output commits to no script
/// path and is spent with a single aggregated Schnorr signature.
#[must_use]
pub fn funding_scriptpubkey(aggregate_funding_key: XOnlyPublicKey) -> ScriptBuf {
    // `dangerous_assume_tweaked` is correct here: the `MuSig2` key aggregation
    // already applied the BIP 86 taptweak, so tweaking again would produce a
    // key neither peer can sign for.
    ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
        aggregate_funding_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_scriptpubkey_matches_spec_vector() {
        let aggregate = XOnlyPublicKey::from_slice(
            &hex::decode("d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e")
                .expect("valid hex"),
        )
        .expect("valid x-only pubkey");

        assert_eq!(
            hex::encode(funding_scriptpubkey(aggregate).as_bytes()),
            "5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e"
        );
    }
}
