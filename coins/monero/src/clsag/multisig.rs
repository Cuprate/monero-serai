use core::fmt::Debug;
use std::{rc::Rc, cell::RefCell};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::Identity,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use monero::util::ringct::{Key, Clsag};

use group::Group;

use transcript::Transcript as TranscriptTrait;
use frost::{Curve, FrostError, algorithm::Algorithm, MultisigView};
use dalek_ff_group as dfg;

use crate::{
  hash_to_point,
  frost::{Transcript, MultisigError, Ed25519, DLEqProof},
  key_image,
  clsag::{Input, sign_core, verify}
};

impl Input {
  fn transcript<T: TranscriptTrait>(&self, transcript: &mut T) {
    // Doesn't domain separate as this is considered part of the larger CLSAG proof

    // Ring index
    transcript.append_message(b"ring_index", &[self.decoys.i]);

    // Ring
    let mut ring = vec![];
    for pair in &self.decoys.ring {
      // Doesn't include global output indexes as CLSAG doesn't care and won't be affected by it
      // They're just a unreliable reference to this data which will be included in the message
      // if in use
      ring.extend(&pair[0].compress().to_bytes());
      ring.extend(&pair[1].compress().to_bytes());
    }
    transcript.append_message(b"ring", &ring);

    // Doesn't include the commitment's parts as the above ring + index includes the commitment
    // The only potential malleability would be if the G/H relationship is known breaking the
    // discrete log problem, which breaks everything already
  }
}

// pub to enable testing
// While we could move the CLSAG test inside this crate, that'd require duplicating the FROST test
// helper, and isn't worth doing right now when this is harmless enough (semver? TODO)
#[derive(Clone, Debug)]
pub struct Details {
  input: Input,
  mask: Scalar
}

impl Details {
  pub fn new(input: Input, mask: Scalar) -> Details {
    Details { input, mask }
  }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
struct Interim {
  p: Scalar,
  c: Scalar,

  clsag: Clsag,
  pseudo_out: EdwardsPoint
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Multisig {
  transcript: Transcript,

  image: EdwardsPoint,
  commitments_H: Vec<u8>,
  AH: (dfg::EdwardsPoint, dfg::EdwardsPoint),

  details: Rc<RefCell<Option<Details>>>,
  msg: Rc<RefCell<Option<[u8; 32]>>>,

  interim: Option<Interim>
}

impl Multisig {
  pub fn new(
    transcript: Transcript,
    details: Rc<RefCell<Option<Details>>>,
    msg: Rc<RefCell<Option<[u8; 32]>>>,
  ) -> Result<Multisig, MultisigError> {
    Ok(
      Multisig {
        transcript,

        image: EdwardsPoint::identity(),
        commitments_H: vec![],
        AH: (dfg::EdwardsPoint::identity(), dfg::EdwardsPoint::identity()),

        details,
        msg,

        interim: None
      }
    )
  }

  pub fn serialized_len() -> usize {
    3 * (32 + 64)
  }

  fn input(&self) -> Input {
    self.details.borrow().as_ref().unwrap().input.clone()
  }

  fn mask(&self) -> Scalar {
    self.details.borrow().as_ref().unwrap().mask
  }

  fn msg(&self) -> [u8; 32] {
    *self.msg.borrow().as_ref().unwrap()
  }
}

impl Algorithm<Ed25519> for Multisig {
  type Transcript = Transcript;
  type Signature = (Clsag, EdwardsPoint);

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &MultisigView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    let (share, proof) = key_image::generate_share(rng, view);

    #[allow(non_snake_case)]
    let H = hash_to_point(&view.group_key().0);
    #[allow(non_snake_case)]
    let nH = (nonces[0].0 * H, nonces[1].0 * H);

    let mut serialized = Vec::with_capacity(Multisig::serialized_len());
    serialized.extend(share.compress().to_bytes());
    serialized.extend(nH.0.compress().to_bytes());
    serialized.extend(nH.1.compress().to_bytes());
    serialized.extend(&DLEqProof::prove(rng, &nonces[0].0, &H, &nH.0).serialize());
    serialized.extend(&DLEqProof::prove(rng, &nonces[1].0, &H, &nH.1).serialize());
    serialized.extend(proof);
    serialized
  }

  fn process_addendum(
    &mut self,
    view: &MultisigView<Ed25519>,
    l: usize,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    if serialized.len() != Multisig::serialized_len() {
      // Not an optimal error but...
      Err(FrostError::InvalidCommitmentQuantity(l, 9, serialized.len() / 32))?;
    }

    if self.commitments_H.len() == 0 {
      self.transcript.domain_separate(b"CLSAG");
      self.input().transcript(&mut self.transcript);
      self.transcript.append_message(b"mask", &self.mask().to_bytes());
      self.transcript.append_message(b"message", &self.msg());
    }

    let (share, serialized) = key_image::verify_share(view, l, serialized).map_err(|_| FrostError::InvalidShare(l))?;
    // Given the fact there's only ever one possible value for this, this may technically not need
    // to be committed to. If signing a TX, it'll be double committed to thanks to the message
    // It doesn't hurt to have though and ensures security boundaries are well formed
    self.transcript.append_message(b"image_share", &share.compress().to_bytes());
    self.image += share;

    let alt = &hash_to_point(&view.group_key().0);

    // Uses the same format FROST does for the expected commitments (nonce * G where this is nonce * H)
    // Given this is guaranteed to match commitments, which FROST commits to, this also technically
    // doesn't need to be committed to if a canonical serialization is guaranteed
    // It, again, doesn't hurt to include and ensures security boundaries are well formed
    self.transcript.append_message(b"participant", &u16::try_from(l).unwrap().to_be_bytes());
    self.transcript.append_message(b"commitments_H", &serialized[0 .. 64]);

    #[allow(non_snake_case)]
    let H = (
      <Ed25519 as Curve>::G_from_slice(&serialized[0 .. 32]).map_err(|_| FrostError::InvalidCommitment(l))?,
      <Ed25519 as Curve>::G_from_slice(&serialized[32 .. 64]).map_err(|_| FrostError::InvalidCommitment(l))?
    );

    DLEqProof::deserialize(&serialized[64 .. 128]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[0],
      &H.0
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    DLEqProof::deserialize(&serialized[128 .. 192]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[1],
      &H.1
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    self.AH.0 += H.0;
    self.AH.1 += H.1;

    Ok(())
  }

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn sign_share(
    &mut self,
    view: &MultisigView<Ed25519>,
    nonce_sum: dfg::EdwardsPoint,
    b: dfg::Scalar,
    nonce: dfg::Scalar,
    _: &[u8]
  ) -> dfg::Scalar {
    // Apply the binding factor to the H variant of the nonce
    self.AH.0 += self.AH.1 * b;

    // Use the transcript to get a seeded random number generator
    // The transcript contains private data, preventing passive adversaries from recreating this
    // process even if they have access to commitments (specifically, the ring index being signed
    // for, along with the mask which should not only require knowing the shared keys yet also the
    // input commitment masks)
    let mut rng = ChaCha12Rng::from_seed(self.transcript.rng_seed(b"decoy_responses", None));

    #[allow(non_snake_case)]
    let (clsag, pseudo_out, p, c) = sign_core(
      &mut rng,
      &self.image,
      &self.input(),
      self.mask(),
      &self.msg(),
      nonce_sum.0,
      self.AH.0.0
    );
    self.interim = Some(Interim { p, c, clsag, pseudo_out });

    let share = dfg::Scalar(nonce.0 - (p * view.secret_share().0));

    share
  }

  fn verify(
    &self,
    _: dfg::EdwardsPoint,
    _: dfg::EdwardsPoint,
    sum: dfg::Scalar
  ) -> Option<Self::Signature> {
    let interim = self.interim.as_ref().unwrap();
    let mut clsag = interim.clsag.clone();
    clsag.s[usize::from(self.input().decoys.i)] = Key { key: (sum.0 - interim.c).to_bytes() };
    if verify(&clsag, &self.input().decoys.ring, &self.image, &interim.pseudo_out, &self.msg()).is_ok() {
      return Some((clsag, interim.pseudo_out));
    }
    return None;
  }

  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonce: dfg::EdwardsPoint,
    share: dfg::Scalar,
  ) -> bool {
    let interim = self.interim.as_ref().unwrap();
    return (&share.0 * &ED25519_BASEPOINT_TABLE) == (
      nonce.0 - (interim.p * verification_share.0)
    );
  }
}