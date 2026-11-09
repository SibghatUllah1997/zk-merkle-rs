//! Recoverable errors for length checks, hex decoding, proof-step parsing,
//! and placeholder hash algorithms.
//!
//! These types are `no_std` friendly. When the `std` feature is on they also
//! implement [`std::error::Error`] so they plug into ordinary `?` chains.

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Error returned when converting variable-length byte slices into fixed-size arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthError {
    pub expected: usize,
    pub found: usize,
}

impl LengthError {
    /// Build a length mismatch for `found` bytes versus `expected`.
    pub const fn new(expected: usize, found: usize) -> Self {
        Self { expected, found }
    }
}

impl core::fmt::Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "length {} does not match expected {}",
            self.found, self.expected
        )
    }
}

/// Fallible conversion of a byte slice into a 32-byte array.
#[inline]
pub fn try_array32(bytes: &[u8]) -> Result<[u8; 32], LengthError> {
    if bytes.len() != 32 {
        return Err(LengthError::new(32, bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Error returned when decoding a hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// Input had an odd number of hex characters.
    OddLength { chars: usize },
    /// Character at `index` is not a hex digit.
    InvalidDigit { index: usize, digit: char },
    /// Decoded byte length did not match the expected size.
    UnexpectedLen { expected: usize, found: usize },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HexError::OddLength { chars } => {
                write!(f, "odd-length hex string ({chars} chars)")
            }
            HexError::InvalidDigit { index, digit } => {
                write!(f, "invalid hex digit {digit:?} at index {index}")
            }
            HexError::UnexpectedLen { expected, found } => {
                write!(
                    f,
                    "decoded length {found} does not match expected {expected}"
                )
            }
        }
    }
}

/// Error returned when parsing a proof-step token list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStepsError {
    /// A comma-separated token was empty (for example a trailing comma).
    EmptyToken,
    /// Token did not contain a `:` separator.
    MissingColon { token: String },
    /// Side marker was not `L`/`l` or `R`/`r`.
    BadSide { found: String },
    /// Hex payload of a token could not be decoded as 32 bytes.
    Hex(HexError),
}

impl core::fmt::Display for ParseStepsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseStepsError::EmptyToken => write!(f, "empty proof step token"),
            ParseStepsError::MissingColon { token } => {
                write!(f, "proof step {token:?} is missing a ':' separator")
            }
            ParseStepsError::BadSide { found } => {
                write!(f, "proof step side {found:?} is not L or R")
            }
            ParseStepsError::Hex(err) => write!(f, "proof step hex: {err}"),
        }
    }
}

impl From<HexError> for ParseStepsError {
    fn from(err: HexError) -> Self {
        ParseStepsError::Hex(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

#[cfg(feature = "std")]
impl std::error::Error for HexError {}

#[cfg(feature = "std")]
impl std::error::Error for ParseStepsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseStepsError::Hex(err) => Some(err),
            _ => None,
        }
    }
}

/// Returned when a named hash is selected but has no implementation yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashNotImplemented {
    /// Stable algorithm name, e.g. `"poseidon"` or `"rescue"`.
    pub algorithm: &'static str,
}

impl HashNotImplemented {
    /// Build an error for the given algorithm name.
    pub const fn new(algorithm: &'static str) -> Self {
        Self { algorithm }
    }
}

impl core::fmt::Display for HashNotImplemented {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} hashing is not implemented yet", self.algorithm)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HashNotImplemented {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::string::{String, ToString};

    #[test]
    fn try_array32_accepts_exact_len_and_rejects_others() {
        let ok = [42u8; 32];
        assert_eq!(try_array32(&ok).unwrap(), ok);
        let short = [0u8; 31];
        assert_eq!(try_array32(&short), Err(LengthError::new(32, 31)));
        let mut long = [0u8; 33];
        long[0] = 7;
        assert_eq!(try_array32(&long), Err(LengthError::new(32, 33)));
    }

    #[test]
    fn length_and_hex_errors_display_clearly() {
        assert_eq!(
            LengthError::new(32, 8).to_string(),
            "length 8 does not match expected 32"
        );
        assert_eq!(
            HexError::OddLength { chars: 3 }.to_string(),
            "odd-length hex string (3 chars)"
        );
        assert_eq!(
            HexError::InvalidDigit {
                index: 1,
                digit: 'g'
            }
            .to_string(),
            "invalid hex digit 'g' at index 1"
        );
        assert_eq!(
            HexError::UnexpectedLen {
                expected: 32,
                found: 2
            }
            .to_string(),
            "decoded length 2 does not match expected 32"
        );
    }

    #[test]
    fn parse_steps_error_wraps_hex_and_displays() {
        let hex = HexError::UnexpectedLen {
            expected: 32,
            found: 2,
        };
        let wrapped: ParseStepsError = hex.into();
        assert_eq!(wrapped, ParseStepsError::Hex(hex));
        assert!(wrapped.to_string().contains("decoded length 2"));
        assert_eq!(
            ParseStepsError::EmptyToken.to_string(),
            "empty proof step token"
        );
        assert!(ParseStepsError::MissingColon {
            token: String::from("no-colon")
        }
        .to_string()
        .contains("no-colon"));
        assert!(ParseStepsError::BadSide {
            found: String::from("X")
        }
        .to_string()
        .contains('X'));
    }

    #[cfg(feature = "std")]
    #[test]
    fn parse_steps_error_source_is_hex_when_wrapped() {
        use std::error::Error;
        let hex = HexError::OddLength { chars: 1 };
        let wrapped = ParseStepsError::Hex(hex);
        assert!(wrapped.source().is_some());
        assert!(ParseStepsError::EmptyToken.source().is_none());
        assert!(HashNotImplemented::new("poseidon").source().is_none());
    }

    #[test]
    fn hash_not_implemented_displays_algorithm_name() {
        let err = HashNotImplemented::new("poseidon");
        assert_eq!(err.algorithm, "poseidon");
        assert_eq!(err.to_string(), "poseidon hashing is not implemented yet");
        assert_eq!(HashNotImplemented::new("poseidon"), err);
        let rescue = HashNotImplemented::new("rescue");
        assert_eq!(rescue.to_string(), "rescue hashing is not implemented yet");
        assert_ne!(rescue, err);
    }
}
