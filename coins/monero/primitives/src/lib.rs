#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::vec::Vec;
#[cfg(feature = "std")]
use std_shims::sync::OnceLock;

use zeroize::{Zeroize, ZeroizeOnDrop};

use sha3::{Digest, Keccak256};
use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  traits::VartimePrecomputedMultiscalarMul,
  scalar::Scalar,
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation},
};

use monero_generators::H;

mod unreduced_scalar;
pub use unreduced_scalar::UnreducedScalar;

#[cfg(test)]
mod tests;

// On std, we cache some variables in statics.
#[cfg(feature = "std")]
static INV_EIGHT_CELL: OnceLock<Scalar> = OnceLock::new();
/// The inverse of 8 over l.
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
  *INV_EIGHT_CELL.get_or_init(|| Scalar::from(8u8).invert())
}
// In no-std environments, we prefer the reduced memory use and calculate it ad-hoc.
/// The inverse of 8 over l.
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn INV_EIGHT() -> Scalar {
  Scalar::from(8u8).invert()
}

#[cfg(feature = "std")]
static G_PRECOMP_CELL: OnceLock<VartimeEdwardsPrecomputation> = OnceLock::new();
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(feature = "std")]
#[allow(non_snake_case)]
pub fn G_PRECOMP() -> &'static VartimeEdwardsPrecomputation {
  G_PRECOMP_CELL.get_or_init(|| VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT]))
}
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
pub fn G_PRECOMP() -> VartimeEdwardsPrecomputation {
  VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT])
}

/// The Keccak-256 hash function.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
  Keccak256::digest(data.as_ref()).into()
}

/// Hash the provided data to a scalar via keccak256(data) % l.
///
/// This function panics if it finds the Keccak-256 preimage for [0; 32].
pub fn keccak256_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
  let scalar = Scalar::from_bytes_mod_order(keccak256(data.as_ref()));
  // Monero will explicitly error in this case
  // This library acknowledges its practical impossibility of it occurring, and doesn't bother to
  // code in logic to handle it. That said, if it ever occurs, something must happen in order to
  // not generate/verify a proof we believe to be valid when it isn't
  assert!(scalar != Scalar::ZERO, "ZERO HASH: {:?}", data.as_ref());
  scalar
}

/// Transparent structure representing a Pedersen commitment's contents.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
  /// The mask for this commitment.
  pub mask: Scalar,
  /// The amount committed to by this commitment.
  pub amount: u64,
}

impl core::fmt::Debug for Commitment {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("Commitment").field("amount", &self.amount).finish_non_exhaustive()
  }
}

impl Commitment {
  /// A commitment to zero, defined with a mask of 1 (as to not be the identity).
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::ONE, amount: 0 }
  }

  /// Create a new Commitment.
  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  /// Calculate the Pedersen commitment, as a point, from this transparent structure.
  pub fn calculate(&self) -> EdwardsPoint {
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&Scalar::from(self.amount), &H(), &self.mask)
  }
}

/// Decoy data, as used for producing Monero's ring signatures.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Decoys {
  offsets: Vec<u64>,
  signer_index: u8,
  ring: Vec<[EdwardsPoint; 2]>,
}

#[allow(clippy::len_without_is_empty)]
impl Decoys {
  /// Create a new instance of decoy data.
  ///
  /// `offsets` are the positions of each ring member within the Monero blockchain, offset from the
  /// prior member's position (with the initial ring member offset from 0).
  pub fn new(offsets: Vec<u64>, signer_index: u8, ring: Vec<[EdwardsPoint; 2]>) -> Option<Self> {
    if (offsets.len() != ring.len()) || (usize::from(signer_index) >= ring.len()) {
      None?;
    }
    Some(Decoys { offsets, signer_index, ring })
  }

  /// The length of the ring.
  pub fn len(&self) -> usize {
    self.offsets.len()
  }

  /// The positions of the ring members within the Monero blockchain, as their offsets.
  ///
  /// The list is formatted as the position of the first ring member, then the offset from each
  /// ring member to its prior.
  pub fn offsets(&self) -> &[u64] {
    &self.offsets
  }

  /// The positions of the ring members within the Monero blockchain.
  pub fn positions(&self) -> Vec<u64> {
    let mut res = Vec::with_capacity(self.len());
    res.push(self.offsets[0]);
    for m in 1 .. res.len() {
      res.push(res[m - 1] + self.offsets[m]);
    }
    res
  }

  /// The index of the signer within the ring.
  pub fn signer_index(&self) -> u8 {
    self.signer_index
  }

  /// The ring.
  pub fn ring(&self) -> &[[EdwardsPoint; 2]] {
    &self.ring
  }

  /// The [key, commitment] pair of the signer.
  pub fn signer_ring_members(&self) -> [EdwardsPoint; 2] {
    self.ring[usize::from(self.signer_index)]
  }
}