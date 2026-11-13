//! Compile-time crate feature flags for this build.
//!
//! These constants match the `[features]` table in `Cargo.toml`. Use them
//! when a caller needs to branch on whether serde, BLAKE3, or Poseidon was
//! compiled in, without duplicating `cfg` attributes at every call site.

/// Default `std` feature: CLI, [`crate::chunk_reader`], and `std::error::Error`.
pub const STD: bool = cfg!(feature = "std");

/// Serde derives on proof, root, and metadata types.
pub const SERDE: bool = cfg!(feature = "serde");

/// Domain-separated BLAKE3 hashing.
pub const BLAKE3: bool = cfg!(feature = "blake3");

/// Circom-compatible Poseidon over BN254.
pub const POSEIDON: bool = cfg!(feature = "poseidon");

/// Rescue placeholder API (`HashNotImplemented`).
pub const RESCUE: bool = cfg!(feature = "rescue");

/// Names of features compiled into this build, in a stable order.
///
/// The default `std` feature is listed when it is on. Optional hashes appear
/// only when their flags are enabled.
pub fn enabled() -> &'static [&'static str] {
    &[
        #[cfg(feature = "std")]
        "std",
        #[cfg(feature = "serde")]
        "serde",
        #[cfg(feature = "blake3")]
        "blake3",
        #[cfg(feature = "poseidon")]
        "poseidon",
        #[cfg(feature = "rescue")]
        "rescue",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_matches_constants() {
        assert_eq!(enabled().contains(&"std"), STD);
        assert_eq!(enabled().contains(&"serde"), SERDE);
        assert_eq!(enabled().contains(&"blake3"), BLAKE3);
        assert_eq!(enabled().contains(&"poseidon"), POSEIDON);
        assert_eq!(enabled().contains(&"rescue"), RESCUE);
        assert_eq!(STD, cfg!(feature = "std"));
        assert_eq!(BLAKE3, cfg!(feature = "blake3"));
        assert_eq!(POSEIDON, cfg!(feature = "poseidon"));
        assert_eq!(SERDE, cfg!(feature = "serde"));
        assert_eq!(RESCUE, cfg!(feature = "rescue"));
    }

    #[test]
    fn enabled_has_no_duplicates() {
        let names = enabled();
        for (i, name) in names.iter().enumerate() {
            assert!(!names[i + 1..].contains(name), "{names:?}");
        }
    }
}
