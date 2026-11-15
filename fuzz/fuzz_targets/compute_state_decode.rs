#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the compute marketplace state decoders (envelope v15 sections) and
// the Smart Gate revocation accumulator.
//
// `PayoutInstruction::decode`, `EscrowBook::decode`, `ChallengeBook::decode`
// and `BondBook::decode` parse bytes from `state.bin`, and
// `GuardRevokeBook::record` parses bytes from a peer — both are untrusted
// input that must never panic or grow memory without bound. Properties:
// every decoder is total (Ok or Err, never a panic), and a value that
// decodes must re-encode to bytes the same decoder accepts (encode stability,
// the property the state file actually depends on).
fuzz_target!(|data: &[u8]| {
    let net = "srct/mini";

    if let Ok(payout) = srct_compute::PayoutInstruction::decode(data) {
        let again = srct_compute::PayoutInstruction::decode(&payout.encode())
            .expect("a payout must decode from its own encoding");
        assert_eq!(again.encode(), payout.encode());
    }
    if let Ok(book) = srct_compute::EscrowBook::decode(data, net) {
        let again = srct_compute::EscrowBook::decode(&book.encode(), net)
            .expect("an escrow book must decode from its own encoding");
        assert_eq!(again.encode(), book.encode());
    }
    if let Ok(book) = srct_compute::ChallengeBook::decode(data, net) {
        let again = srct_compute::ChallengeBook::decode(&book.encode(), net)
            .expect("a challenge book must decode from its own encoding");
        assert_eq!(again.encode(), book.encode());
    }
    if let Ok(book) = srct_compute::BondBook::decode(data, net) {
        let again = srct_compute::BondBook::decode(&book.encode(), net)
            .expect("a bond book must decode from its own encoding");
        assert_eq!(again.encode(), book.encode());
    }

    // Revocation accumulator: three slices of the input as (policy, sigs,
    // keys). Verified or refused — never a panic, and a duplicate filing
    // must not grow the book.
    let third = data.len() / 3;
    let (policy, rest) = data.split_at(third);
    let (sigs, keys) = rest.split_at(rest.len() / 2);
    let mut book = srct_core::guard::GuardRevokeBook::new();
    if book.record(policy, sigs, keys, net).is_ok() {
        let before = book.len();
        let _ = book.record(policy, sigs, keys, net);
        assert_eq!(book.len(), before, "re-filing must not grow the book");
    }
});
