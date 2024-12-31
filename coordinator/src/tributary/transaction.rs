use core::{ops::Deref, fmt::Debug};
use std::io;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use blake2::{digest::typenum::U32, Digest, Blake2b};
use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::primitives::PublicKey;

use processor_messages::sign::VariantSignId;

use tributary::{
  ReadWrite,
  transaction::{
    Signed as TributarySigned, TransactionError, TransactionKind, Transaction as TransactionTrait,
  },
};

/// The label for data from a signing protocol.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, BorshSerialize, BorshDeserialize)]
pub enum Label {
  /// A preprocess.
  Preprocess,
  /// A signature share.
  Share,
}

impl Label {
  fn nonce(&self) -> u32 {
    match self {
      Label::Preprocess => 0,
      Label::Share => 1,
    }
  }
}

fn borsh_serialize_public<W: io::Write>(
  public: &PublicKey,
  writer: &mut W,
) -> Result<(), io::Error> {
  // This doesn't use `encode_to` as `encode_to` panics if the writer returns an error
  writer.write_all(&public.encode())
}
fn borsh_deserialize_public<R: io::Read>(reader: &mut R) -> Result<PublicKey, io::Error> {
  Decode::decode(&mut scale::IoReader(reader)).map_err(io::Error::other)
}

/// `tributary::Signed` without the nonce.
///
/// All of our nonces are deterministic to the type of transaction and fields within.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signed {
  pub signer: <Ristretto as Ciphersuite>::G,
  pub signature: SchnorrSignature<Ristretto>,
}

impl BorshSerialize for Signed {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> Result<(), io::Error> {
    writer.write_all(self.signer.to_bytes().as_ref())?;
    self.signature.write(writer)
  }
}
impl BorshDeserialize for Signed {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> Result<Self, io::Error> {
    let signer = Ristretto::read_G(reader)?;
    let signature = SchnorrSignature::read(reader)?;
    Ok(Self { signer, signature })
  }
}

impl Signed {
  /// Provide a nonce to convert a `Signed` into a `tributary::Signed`.
  fn nonce(&self, nonce: u32) -> TributarySigned {
    TributarySigned { signer: self.signer, nonce, signature: self.signature }
  }
}

/// The Tributary transaction definition used by Serai
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Transaction {
  /// A vote to remove a participant for invalid behavior
  RemoveParticipant {
    /// The participant to remove
    #[borsh(
      serialize_with = "borsh_serialize_public",
      deserialize_with = "borsh_deserialize_public"
    )]
    participant: PublicKey,
    /// The transaction's signer and signature
    signed: Signed,
  },

  /// A participation in the DKG
  DkgParticipation {
    participation: Vec<u8>,
    /// The transaction's signer and signature
    signed: Signed,
  },
  /// The preprocess to confirm the DKG results on-chain
  DkgConfirmationPreprocess {
    /// The attempt number of this signing protocol
    attempt: u32,
    // The preprocess
    preprocess: [u8; 64],
    /// The transaction's signer and signature
    signed: Signed,
  },
  /// The signature share to confirm the DKG results on-chain
  DkgConfirmationShare {
    /// The attempt number of this signing protocol
    attempt: u32,
    // The signature share
    confirmation_share: [u8; 32],
    /// The transaction's signer and signature
    signed: Signed,
  },

  /// Intend to co-sign a finalized Substrate block
  ///
  /// When the time comes to start a new co-signing protocol, the most recent Substrate block will
  /// be the one selected to be cosigned.
  CosignSubstrateBlock {
    /// THe hash of the Substrate block to sign
    hash: [u8; 32],
  },

  /// Acknowledge a Substrate block
  ///
  /// This is provided after the block has been cosigned.
  ///
  /// With the acknowledgement of a Substrate block, we can whitelist all the `VariantSignId`s
  /// resulting from its handling.
  SubstrateBlock {
    /// The hash of the Substrate block
    hash: [u8; 32],
  },

  /// Acknowledge a Batch
  ///
  /// Once everyone has acknowledged the Batch, we can begin signing it.
  Batch {
    /// The hash of the Batch's serialization.
    ///
    /// Generally, we refer to a Batch by its ID/the hash of its instructions. Here, we want to
    /// ensure consensus on the Batch, and achieving consensus on its hash is the most effective
    /// way to do that.
    hash: [u8; 32],
  },

  /// The local view of slashes observed by the transaction's sender
  SlashReport {
    /// The slash points accrued by each validator
    slash_points: Vec<u32>,
    /// The transaction's signer and signature
    signed: Signed,
  },

  Sign {
    /// The ID of the object being signed
    id: VariantSignId,
    /// The attempt number of this signing protocol
    attempt: u32,
    /// The label for this data within the signing protocol
    label: Label,
    /// The data itself
    ///
    /// There will be `n` blobs of data where `n` is the amount of key shares the validator sending
    /// this transaction has.
    data: Vec<Vec<u8>>,
    /// The transaction's signer and signature
    signed: Signed,
  },
}

impl ReadWrite for Transaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    borsh::from_reader(reader)
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    borsh::to_writer(writer, self)
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind {
    match self {
      Transaction::RemoveParticipant { participant, signed } => {
        TransactionKind::Signed((b"RemoveParticipant", participant).encode(), signed.nonce(0))
      }

      Transaction::DkgParticipation { signed, .. } => {
        TransactionKind::Signed(b"DkgParticipation".encode(), signed.nonce(0))
      }
      Transaction::DkgConfirmationPreprocess { attempt, signed, .. } => {
        TransactionKind::Signed((b"DkgConfirmation", attempt).encode(), signed.nonce(0))
      }
      Transaction::DkgConfirmationShare { attempt, signed, .. } => {
        TransactionKind::Signed((b"DkgConfirmation", attempt).encode(), signed.nonce(1))
      }

      Transaction::CosignSubstrateBlock { .. } => TransactionKind::Provided("CosignSubstrateBlock"),
      Transaction::SubstrateBlock { .. } => TransactionKind::Provided("SubstrateBlock"),
      Transaction::Batch { .. } => TransactionKind::Provided("Batch"),

      Transaction::Sign { id, attempt, label, signed, .. } => {
        TransactionKind::Signed((b"Sign", id, attempt).encode(), signed.nonce(label.nonce()))
      }

      Transaction::SlashReport { signed, .. } => {
        TransactionKind::Signed(b"SlashReport".encode(), signed.nonce(0))
      }
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = ReadWrite::serialize(self);
    if let TransactionKind::Signed(_, signed) = self.kind() {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), signed.signature.serialize());
    }
    Blake2b::<U32>::digest(&tx).into()
  }

  // We don't have any verification logic embedded into the transaction. We just slash anyone who
  // publishes an invalid transaction.
  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

impl Transaction {
  // Sign a transaction
  pub fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    genesis: [u8; 32],
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) {
    fn signed(tx: &mut Transaction) -> &mut Signed {
      #[allow(clippy::match_same_arms)] // This doesn't make semantic sense here
      match tx {
        Transaction::RemoveParticipant { ref mut signed, .. } |
        Transaction::DkgParticipation { ref mut signed, .. } |
        Transaction::DkgConfirmationPreprocess { ref mut signed, .. } => signed,
        Transaction::DkgConfirmationShare { ref mut signed, .. } => signed,

        Transaction::CosignSubstrateBlock { .. } => panic!("signing CosignSubstrateBlock"),
        Transaction::SubstrateBlock { .. } => panic!("signing SubstrateBlock"),
        Transaction::Batch { .. } => panic!("signing Batch"),

        Transaction::Sign { ref mut signed, .. } => signed,

        Transaction::SlashReport { ref mut signed, .. } => signed,
      }
    }

    // Decide the nonce to sign with
    let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));

    {
      // Set the signer and the nonce
      let signed = signed(self);
      signed.signer = Ristretto::generator() * key.deref();
      signed.signature.R = <Ristretto as Ciphersuite>::generator() * sig_nonce.deref();
    }

    // Get the signature hash (which now includes `R || A` making it valid as the challenge)
    let sig_hash = self.sig_hash(genesis);

    // Sign the signature
    signed(self).signature = SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
  }
}
