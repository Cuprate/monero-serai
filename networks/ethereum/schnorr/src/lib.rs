#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

/// The initialization bytecode of the Schnorr library.
pub const BYTECODE: &[u8] = {
  const BYTECODE_HEX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ethereum-schnorr-contract/Schnorr.bin"));
  const BYTECODE: [u8; BYTECODE_HEX.len() / 2] =
    match const_hex::const_decode_to_array::<{ BYTECODE_HEX.len() / 2 }>(BYTECODE_HEX) {
      Ok(bytecode) => bytecode,
      Err(_) => panic!("Schnorr.bin did not contain valid hex"),
    };
  &BYTECODE
};

mod public_key;
pub use public_key::PublicKey;
mod signature;
pub use signature::Signature;

#[cfg(test)]
mod tests;
