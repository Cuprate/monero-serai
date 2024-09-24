use core::{marker::PhantomData, ops::Deref, fmt};

use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use blake2::{Digest, Blake2s256};
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

use generalized_bulletproofs::{
  *,
  transcript::{Transcript as ProverTranscript, VerifierTranscript},
  arithmetic_circuit_proof::*,
};
use generalized_bulletproofs_circuit_abstraction::*;

use ec_divisors::{DivisorCurve, ScalarDecomposition};
use generalized_bulletproofs_ec_gadgets::*;

/// A pair of curves to perform the eVRF with.
pub trait EvrfCurve: Ciphersuite {
  type EmbeddedCurve: Ciphersuite<G: DivisorCurve<FieldElement = <Self as Ciphersuite>::F>>;
  type EmbeddedCurveParameters: DiscreteLogParameters;
}

#[cfg(feature = "evrf-secp256k1")]
impl EvrfCurve for ciphersuite::Secp256k1 {
  type EmbeddedCurve = secq256k1::Secq256k1;
  type EmbeddedCurveParameters = secq256k1::Secq256k1;
}

#[cfg(feature = "evrf-ed25519")]
impl EvrfCurve for ciphersuite::Ed25519 {
  type EmbeddedCurve = embedwards25519::Embedwards25519;
  type EmbeddedCurveParameters = embedwards25519::Embedwards25519;
}

#[cfg(feature = "evrf-ristretto")]
impl EvrfCurve for ciphersuite::Ristretto {
  type EmbeddedCurve = embedwards25519::Embedwards25519;
  type EmbeddedCurveParameters = embedwards25519::Embedwards25519;
}

fn sample_point<C: Ciphersuite>(rng: &mut (impl RngCore + CryptoRng)) -> C::G {
  let mut repr = <C::G as GroupEncoding>::Repr::default();
  loop {
    rng.fill_bytes(repr.as_mut());
    if let Ok(point) = C::read_G(&mut repr.as_ref()) {
      if bool::from(!point.is_identity()) {
        return point;
      }
    }
  }
}

/// Generators for eVRF proof.
#[derive(Clone, Debug)]
pub struct EvrfGenerators<C: EvrfCurve>(pub(crate) Generators<C>);

impl<C: EvrfCurve> EvrfGenerators<C> {
  /// Create a new set of generators.
  pub fn new(max_threshold: u16, max_participants: u16) -> EvrfGenerators<C> {
    let g = C::generator();
    let mut rng = ChaCha20Rng::from_seed(Blake2s256::digest(g.to_bytes()).into());
    let h = sample_point::<C>(&mut rng);
    let (_, generators) =
      Evrf::<C>::muls_and_generators_to_use(max_threshold.into(), max_participants.into());
    let mut g_bold = vec![];
    let mut h_bold = vec![];
    for _ in 0 .. generators {
      g_bold.push(sample_point::<C>(&mut rng));
      h_bold.push(sample_point::<C>(&mut rng));
    }
    Self(Generators::new(g, h, g_bold, h_bold).unwrap())
  }
}

/// The result of proving for an eVRF.
pub(crate) struct EvrfProveResult<C: Ciphersuite> {
  /// The coefficients for use in the DKG.
  pub(crate) coefficients: Vec<Zeroizing<C::F>>,
  /// The masks to encrypt secret shares with.
  pub(crate) encryption_masks: Vec<Zeroizing<C::F>>,
  /// The proof itself.
  pub(crate) proof: Vec<u8>,
}

/// The result of verifying an eVRF.
pub(crate) struct EvrfVerifyResult<C: EvrfCurve> {
  /// The commitments to the coefficients for use in the DKG.
  pub(crate) coefficients: Vec<C::G>,
  /// The ephemeral public keys to perform ECDHs with
  pub(crate) ecdh_keys: Vec<[<C::EmbeddedCurve as Ciphersuite>::G; 2]>,
  /// The commitments to the masks used to encrypt secret shares with.
  pub(crate) encryption_commitments: Vec<C::G>,
}

impl<C: EvrfCurve> fmt::Debug for EvrfVerifyResult<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("EvrfVerifyResult").finish_non_exhaustive()
  }
}

/// A struct to prove/verify eVRFs with.
pub(crate) struct Evrf<C: EvrfCurve>(PhantomData<C>);
impl<C: EvrfCurve> Evrf<C> {
  // Sample uniform points (via rejection-sampling) on the embedded elliptic curve
  fn transcript_to_points(
    seed: [u8; 32],
    coefficients: usize,
  ) -> Vec<<C::EmbeddedCurve as Ciphersuite>::G> {
    // We need to do two Diffie-Hellman's per coefficient in order to achieve an unbiased result
    let quantity = 2 * coefficients;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut res = Vec::with_capacity(quantity);
    for _ in 0 .. quantity {
      res.push(sample_point::<C::EmbeddedCurve>(&mut rng));
    }
    res
  }

  /// Read a Variable from a theoretical vector commitment tape
  fn read_one_from_tape(generators_to_use: usize, start: &mut usize) -> Variable {
    // Each commitment has twice as many variables as generators in use
    let commitment = *start / (2 * generators_to_use);
    // The index will be less than the amount of generators in use, as half are left and half are
    // right
    let index = *start % generators_to_use;
    let res = if (*start / generators_to_use) % 2 == 0 {
      Variable::CG { commitment, index }
    } else {
      Variable::CH { commitment, index }
    };
    *start += 1;
    res
  }

  /// Read a set of variables from a theoretical vector commitment tape
  fn read_from_tape<N: ArrayLength>(
    generators_to_use: usize,
    start: &mut usize,
  ) -> GenericArray<Variable, N> {
    let mut buf = Vec::with_capacity(N::USIZE);
    for _ in 0 .. N::USIZE {
      buf.push(Self::read_one_from_tape(generators_to_use, start));
    }
    GenericArray::from_slice(&buf).clone()
  }

  /// Read `PointWithDlog`s, which share a discrete logarithm, from the theoretical vector
  /// commitment tape.
  fn point_with_dlogs(
    start: &mut usize,
    quantity: usize,
    generators_to_use: usize,
  ) -> Vec<PointWithDlog<C::EmbeddedCurveParameters>> {
    // We define a serialized tape of the discrete logarithm, then for each divisor/point, we push:
    //   zero, x**i, y x**i, y, x_coord, y_coord
    // We then chunk that into vector commitments
    // Here, we take the assumed layout and generate the expected `Variable`s for this layout

    let dlog = Self::read_from_tape(generators_to_use, start);

    let mut res = Vec::with_capacity(quantity);
    let mut read_point_with_dlog = || {
      let zero = Self::read_one_from_tape(generators_to_use, start);
      let x_from_power_of_2 = Self::read_from_tape(generators_to_use, start);
      let yx = Self::read_from_tape(generators_to_use, start);
      let y = Self::read_one_from_tape(generators_to_use, start);
      let divisor = Divisor { zero, x_from_power_of_2, yx, y };

      let point = (
        Self::read_one_from_tape(generators_to_use, start),
        Self::read_one_from_tape(generators_to_use, start),
      );

      res.push(PointWithDlog { dlog: dlog.clone(), divisor, point });
    };

    for _ in 0 .. quantity {
      read_point_with_dlog();
    }
    res
  }

  fn muls_and_generators_to_use(coefficients: usize, ecdhs: usize) -> (usize, usize) {
    const MULS_PER_DH: usize = 7;
    // 1 DH to prove the discrete logarithm corresponds to the eVRF public key
    // 2 DHs per generated coefficient
    // 2 DHs per generated ECDH
    let expected_muls = MULS_PER_DH * (1 + (2 * coefficients) + (2 * 2 * ecdhs));
    let generators_to_use = {
      let mut padded_pow_of_2 = 1;
      while padded_pow_of_2 < expected_muls {
        padded_pow_of_2 <<= 1;
      }
      // This may as small as 16, which would create an excessive amount of vector commitments
      // We set a floor of 1024 rows for bandwidth reasons
      padded_pow_of_2.max(1024)
    };
    (expected_muls, generators_to_use)
  }

  fn circuit(
    curve_spec: &CurveSpec<C::F>,
    evrf_public_key: (C::F, C::F),
    coefficients: usize,
    ecdh_commitments: &[[(C::F, C::F); 2]],
    generator_tables: &[GeneratorTable<C::F, C::EmbeddedCurveParameters>],
    circuit: &mut Circuit<C>,
    transcript: &mut impl Transcript,
  ) {
    let (expected_muls, generators_to_use) =
      Self::muls_and_generators_to_use(coefficients, ecdh_commitments.len());
    let (challenge, challenged_generators) =
      circuit.discrete_log_challenge(transcript, curve_spec, generator_tables);
    debug_assert_eq!(challenged_generators.len(), 1 + (2 * coefficients) + ecdh_commitments.len());

    // The generators tables/challenged generators are expected to have the following layouts
    // G, coefficients * [A, B], ecdhs * [P]
    #[allow(non_snake_case)]
    let challenged_G = &challenged_generators[0];

    // Execute the circuit for the coefficients
    let mut tape_pos = 0;
    {
      let mut point_with_dlogs =
        Self::point_with_dlogs(&mut tape_pos, 1 + (2 * coefficients), generators_to_use)
          .into_iter();

      // Verify the discrete logarithm is in the fact the discrete logarithm of the eVRF public key
      let point = circuit.discrete_log(
        curve_spec,
        point_with_dlogs.next().unwrap(),
        &challenge,
        challenged_G,
      );
      circuit.equality(LinComb::from(point.x()), &LinComb::empty().constant(evrf_public_key.0));
      circuit.equality(LinComb::from(point.y()), &LinComb::empty().constant(evrf_public_key.1));

      // Verify the DLog claims against the sampled points
      for (i, pair) in challenged_generators[1 ..].chunks(2).take(coefficients).enumerate() {
        let mut lincomb = LinComb::empty();
        debug_assert_eq!(pair.len(), 2);
        for challenged_generator in pair {
          let point = circuit.discrete_log(
            curve_spec,
            point_with_dlogs.next().unwrap(),
            &challenge,
            challenged_generator,
          );
          // For each point in this pair, add its x coordinate to a lincomb
          lincomb = lincomb.term(C::F::ONE, point.x());
        }
        // Constrain the sum of the two x coordinates to be equal to the value in the Pedersen
        // commitment
        circuit.equality(lincomb, &LinComb::from(Variable::V(i)));
      }
      debug_assert!(point_with_dlogs.next().is_none());
    }

    // Now execute the circuit for the ECDHs
    let mut challenged_generators = challenged_generators.iter().skip(1 + (2 * coefficients));
    for (i, ecdh) in ecdh_commitments.iter().enumerate() {
      let challenged_generator = challenged_generators.next().unwrap();
      let mut lincomb = LinComb::empty();
      for ecdh in ecdh {
        let mut point_with_dlogs =
          Self::point_with_dlogs(&mut tape_pos, 2, generators_to_use).into_iter();

        // One proof of the ECDH secret * G for the commitment published
        let point = circuit.discrete_log(
          curve_spec,
          point_with_dlogs.next().unwrap(),
          &challenge,
          challenged_G,
        );
        circuit.equality(LinComb::from(point.x()), &LinComb::empty().constant(ecdh.0));
        circuit.equality(LinComb::from(point.y()), &LinComb::empty().constant(ecdh.1));

        // One proof of the ECDH secret * P for the ECDH
        let point = circuit.discrete_log(
          curve_spec,
          point_with_dlogs.next().unwrap(),
          &challenge,
          challenged_generator,
        );
        // For each point in this pair, add its x coordinate to a lincomb
        lincomb = lincomb.term(C::F::ONE, point.x());
      }

      // Constrain the sum of the two x coordinates to be equal to the value in the Pedersen
      // commitment
      circuit.equality(lincomb, &LinComb::from(Variable::V(coefficients + i)));
    }

    debug_assert_eq!(expected_muls, circuit.muls());
    debug_assert!(challenged_generators.next().is_none());
  }

  /// Prove a point on an elliptic curve had its discrete logarithm generated via an eVRF.
  pub(crate) fn prove(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    transcript: [u8; 32],
    coefficients: usize,
    ecdh_public_keys: &[<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G],
    evrf_private_key: &Zeroizing<<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Result<EvrfProveResult<C>, AcError> {
    let curve_spec = CurveSpec {
      a: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::a(),
      b: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::b(),
    };

    // A tape of the discrete logarithm, then [zero, x**i, y x**i, y, x_coord, y_coord]
    let mut vector_commitment_tape = vec![];

    let mut generator_tables = Vec::with_capacity(1 + (2 * coefficients) + ecdh_public_keys.len());

    // A function to calculate a divisor and push it onto the tape
    // This defines a vec, divisor_points, outside of the fn to reuse its allocation
    let mut divisor =
      |vector_commitment_tape: &mut Vec<_>,
       dlog: &ScalarDecomposition<<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::F>,
       push_generator: bool,
       generator: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G,
       dh: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G| {
        if push_generator {
          let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(generator).unwrap();
          generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
        }

        let mut divisor = dlog.scalar_mul_divisor(generator).normalize_x_coefficient();

        vector_commitment_tape.push(divisor.zero_coefficient);

        for coefficient in divisor.x_coefficients.iter().skip(1) {
          vector_commitment_tape.push(*coefficient);
        }
        for _ in divisor.x_coefficients.len() ..
          <C::EmbeddedCurveParameters as DiscreteLogParameters>::XCoefficientsMinusOne::USIZE
        {
          vector_commitment_tape.push(<C as Ciphersuite>::F::ZERO);
        }

        for coefficient in divisor.yx_coefficients.first().unwrap_or(&vec![]) {
          vector_commitment_tape.push(*coefficient);
        }
        for _ in divisor.yx_coefficients.first().unwrap_or(&vec![]).len() ..
          <C::EmbeddedCurveParameters as DiscreteLogParameters>::YxCoefficients::USIZE
        {
          vector_commitment_tape.push(<C as Ciphersuite>::F::ZERO);
        }

        vector_commitment_tape
          .push(divisor.y_coefficients.first().copied().unwrap_or(<C as Ciphersuite>::F::ZERO));

        divisor.zeroize();
        drop(divisor);

        let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(dh).unwrap();
        vector_commitment_tape.push(x);
        vector_commitment_tape.push(y);

        (x, y)
      };

    // Start with the coefficients
    let evrf_public_key;
    let mut actual_coefficients = Vec::with_capacity(coefficients);
    {
      let dlog =
        ScalarDecomposition::<<C::EmbeddedCurve as Ciphersuite>::F>::new(**evrf_private_key);
      let points = Self::transcript_to_points(transcript, coefficients);

      // Start by pushing the discrete logarithm onto the tape
      for coefficient in dlog.decomposition() {
        vector_commitment_tape.push(<_>::from(*coefficient));
      }

      // Push a divisor for proving that we're using the correct scalar
      evrf_public_key = divisor(
        &mut vector_commitment_tape,
        &dlog,
        true,
        <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator(),
        <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * evrf_private_key.deref(),
      );

      // Push a divisor for each point we use in the eVRF
      for pair in points.chunks(2) {
        let mut res = Zeroizing::new(C::F::ZERO);
        for point in pair {
          let (dh_x, _) = divisor(
            &mut vector_commitment_tape,
            &dlog,
            true,
            *point,
            *point * evrf_private_key.deref(),
          );
          *res += dh_x;
        }
        actual_coefficients.push(res);
      }
      debug_assert_eq!(actual_coefficients.len(), coefficients);
    }

    // Now do the ECDHs for the encryption
    let mut encryption_masks = Vec::with_capacity(ecdh_public_keys.len());
    let mut ecdh_commitments = Vec::with_capacity(2 * ecdh_public_keys.len());
    let mut ecdh_commitments_xy = Vec::with_capacity(ecdh_public_keys.len());
    for ecdh_public_key in ecdh_public_keys {
      ecdh_commitments_xy.push([(C::F::ZERO, C::F::ZERO); 2]);

      let mut res = Zeroizing::new(C::F::ZERO);
      for j in 0 .. 2 {
        let mut ecdh_private_key;
        loop {
          ecdh_private_key = <C::EmbeddedCurve as Ciphersuite>::F::random(&mut *rng);
          // Generate a non-0 ECDH private key, as necessary to not produce an identity output
          // Identity isn't representable with the divisors, hence the explicit effort
          if bool::from(!ecdh_private_key.is_zero()) {
            break;
          }
        }
        let dlog =
          ScalarDecomposition::<<C::EmbeddedCurve as Ciphersuite>::F>::new(ecdh_private_key);
        let ecdh_commitment = <C::EmbeddedCurve as Ciphersuite>::generator() * ecdh_private_key;
        ecdh_commitments.push(ecdh_commitment);
        ecdh_commitments_xy.last_mut().unwrap()[j] =
          <<C::EmbeddedCurve as Ciphersuite>::G as DivisorCurve>::to_xy(ecdh_commitment).unwrap();

        // Start by pushing the discrete logarithm onto the tape
        for coefficient in dlog.decomposition() {
          vector_commitment_tape.push(<_>::from(*coefficient));
        }

        // Push a divisor for proving that we're using the correct scalar for the commitment
        divisor(
          &mut vector_commitment_tape,
          &dlog,
          false,
          <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator(),
          <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::generator() * ecdh_private_key,
        );
        // Push a divisor for the key we're performing the ECDH with
        let (dh_x, _) = divisor(
          &mut vector_commitment_tape,
          &dlog,
          j == 0,
          *ecdh_public_key,
          *ecdh_public_key * ecdh_private_key,
        );
        *res += dh_x;

        ecdh_private_key.zeroize();
      }
      encryption_masks.push(res);
    }
    debug_assert_eq!(encryption_masks.len(), ecdh_public_keys.len());

    // Now that we have the vector commitment tape, chunk it
    let (_, generators_to_use) =
      Self::muls_and_generators_to_use(coefficients, ecdh_public_keys.len());

    let mut vector_commitments =
      Vec::with_capacity(vector_commitment_tape.len().div_ceil(2 * generators_to_use));
    for chunk in vector_commitment_tape.chunks(2 * generators_to_use) {
      let g_values = chunk[.. generators_to_use.min(chunk.len())].to_vec().into();
      let h_values = chunk[generators_to_use.min(chunk.len()) ..].to_vec().into();
      vector_commitments.push(PedersenVectorCommitment {
        g_values,
        h_values,
        mask: C::F::random(&mut *rng),
      });
    }

    vector_commitment_tape.zeroize();
    drop(vector_commitment_tape);

    let mut commitments = Vec::with_capacity(coefficients + ecdh_public_keys.len());
    for coefficient in &actual_coefficients {
      commitments.push(PedersenCommitment { value: **coefficient, mask: C::F::random(&mut *rng) });
    }
    for enc_mask in &encryption_masks {
      commitments.push(PedersenCommitment { value: **enc_mask, mask: C::F::random(&mut *rng) });
    }

    let mut transcript = ProverTranscript::new(transcript);
    let commited_commitments = transcript.write_commitments(
      vector_commitments
        .iter()
        .map(|commitment| {
          commitment
            .commit(generators.g_bold_slice(), generators.h_bold_slice(), generators.h())
            .ok_or(AcError::NotEnoughGenerators)
        })
        .collect::<Result<_, _>>()?,
      commitments
        .iter()
        .map(|commitment| commitment.commit(generators.g(), generators.h()))
        .collect(),
    );
    for ecdh_commitment in ecdh_commitments {
      transcript.push_point(ecdh_commitment);
    }

    let mut circuit = Circuit::prove(vector_commitments, commitments.clone());
    Self::circuit(
      &curve_spec,
      evrf_public_key,
      coefficients,
      &ecdh_commitments_xy,
      &generator_tables,
      &mut circuit,
      &mut transcript,
    );

    let (statement, Some(witness)) = circuit
      .statement(
        generators.reduce(generators_to_use).ok_or(AcError::NotEnoughGenerators)?,
        commited_commitments,
      )
      .unwrap()
    else {
      panic!("proving yet wasn't yielded the witness");
    };
    statement.prove(&mut *rng, &mut transcript, witness).unwrap();

    // Push the reveal onto the transcript
    for commitment in &commitments {
      transcript.push_point(generators.g() * commitment.value);
    }

    // Define a weight to aggregate the commitments with
    let mut agg_weights = Vec::with_capacity(commitments.len());
    agg_weights.push(C::F::ONE);
    while agg_weights.len() < commitments.len() {
      agg_weights.push(transcript.challenge::<C::F>());
    }
    let mut x = commitments
      .iter()
      .zip(&agg_weights)
      .map(|(commitment, weight)| commitment.mask * *weight)
      .sum::<C::F>();

    // Do a Schnorr PoK for the randomness of the aggregated Pedersen commitment
    let mut r = C::F::random(&mut *rng);
    transcript.push_point(generators.h() * r);
    let c = transcript.challenge::<C::F>();
    transcript.push_scalar(r + (c * x));
    r.zeroize();
    x.zeroize();

    Ok(EvrfProveResult {
      coefficients: actual_coefficients,
      encryption_masks,
      proof: transcript.complete(),
    })
  }

  /// Verify an eVRF proof, returning the commitments output.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn verify(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    verifier: &mut BatchVerifier<C>,
    transcript: [u8; 32],
    coefficients: usize,
    ecdh_public_keys: &[<<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G],
    evrf_public_key: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G,
    proof: &[u8],
  ) -> Result<EvrfVerifyResult<C>, ()> {
    let curve_spec = CurveSpec {
      a: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::a(),
      b: <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G::b(),
    };

    let mut generator_tables = Vec::with_capacity(1 + (2 * coefficients) + ecdh_public_keys.len());
    {
      let (x, y) =
        <C::EmbeddedCurve as Ciphersuite>::G::to_xy(<C::EmbeddedCurve as Ciphersuite>::generator())
          .unwrap();
      generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
    }
    let points = Self::transcript_to_points(transcript, coefficients);
    for generator in points {
      let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(generator).unwrap();
      generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
    }
    for generator in ecdh_public_keys {
      let (x, y) = <C::EmbeddedCurve as Ciphersuite>::G::to_xy(*generator).unwrap();
      generator_tables.push(GeneratorTable::new(&curve_spec, x, y));
    }

    let (_, generators_to_use) =
      Self::muls_and_generators_to_use(coefficients, ecdh_public_keys.len());

    let mut transcript = VerifierTranscript::new(transcript, proof);

    let dlog_len = <C::EmbeddedCurveParameters as DiscreteLogParameters>::ScalarBits::USIZE;
    let divisor_len = 1 +
      <C::EmbeddedCurveParameters as DiscreteLogParameters>::XCoefficientsMinusOne::USIZE +
      <C::EmbeddedCurveParameters as DiscreteLogParameters>::YxCoefficients::USIZE +
      1;
    let dlog_proof_len = divisor_len + 2;

    let coeffs_vc_variables = dlog_len + ((1 + (2 * coefficients)) * dlog_proof_len);
    let ecdhs_vc_variables = ((2 * ecdh_public_keys.len()) * dlog_len) +
      ((2 * 2 * ecdh_public_keys.len()) * dlog_proof_len);
    let vcs = (coeffs_vc_variables + ecdhs_vc_variables).div_ceil(2 * generators_to_use);

    let all_commitments =
      transcript.read_commitments(vcs, coefficients + ecdh_public_keys.len()).map_err(|_| ())?;
    let commitments = all_commitments.V().to_vec();

    let mut ecdh_keys = Vec::with_capacity(ecdh_public_keys.len());
    let mut ecdh_keys_xy = Vec::with_capacity(ecdh_public_keys.len());
    for _ in 0 .. ecdh_public_keys.len() {
      let ecdh_keys_i = [
        transcript.read_point::<C::EmbeddedCurve>().map_err(|_| ())?,
        transcript.read_point::<C::EmbeddedCurve>().map_err(|_| ())?,
      ];
      ecdh_keys.push(ecdh_keys_i);
      // This bans zero ECDH keys
      ecdh_keys_xy.push([
        <<C::EmbeddedCurve as Ciphersuite>::G as DivisorCurve>::to_xy(ecdh_keys_i[0]).ok_or(())?,
        <<C::EmbeddedCurve as Ciphersuite>::G as DivisorCurve>::to_xy(ecdh_keys_i[1]).ok_or(())?,
      ]);
    }

    let mut circuit = Circuit::verify();
    Self::circuit(
      &curve_spec,
      <C::EmbeddedCurve as Ciphersuite>::G::to_xy(evrf_public_key).ok_or(())?,
      coefficients,
      &ecdh_keys_xy,
      &generator_tables,
      &mut circuit,
      &mut transcript,
    );

    let (statement, None) =
      circuit.statement(generators.reduce(generators_to_use).ok_or(())?, all_commitments).unwrap()
    else {
      panic!("verifying yet was yielded a witness");
    };

    statement.verify(rng, verifier, &mut transcript).map_err(|_| ())?;

    // Read the openings for the commitments
    let mut openings = Vec::with_capacity(commitments.len());
    for _ in 0 .. commitments.len() {
      openings.push(transcript.read_point::<C>().map_err(|_| ())?);
    }

    // Verify the openings of the commitments
    let mut agg_weights = Vec::with_capacity(commitments.len());
    agg_weights.push(C::F::ONE);
    while agg_weights.len() < commitments.len() {
      agg_weights.push(transcript.challenge::<C::F>());
    }

    let sum_points =
      openings.iter().zip(&agg_weights).map(|(point, weight)| *point * *weight).sum::<C::G>();
    let sum_commitments =
      commitments.into_iter().zip(agg_weights).map(|(point, weight)| point * weight).sum::<C::G>();
    #[allow(non_snake_case)]
    let A = sum_commitments - sum_points;

    #[allow(non_snake_case)]
    let R = transcript.read_point::<C>().map_err(|_| ())?;
    let c = transcript.challenge::<C::F>();
    let s = transcript.read_scalar::<C>().map_err(|_| ())?;

    // Doesn't batch verify this as we can't access the internals of the GBP batch verifier
    if (R + (A * c)) != (generators.h() * s) {
      Err(())?;
    }

    if !transcript.complete().is_empty() {
      Err(())?
    };

    let encryption_commitments = openings[coefficients ..].to_vec();
    let coefficients = openings[.. coefficients].to_vec();
    Ok(EvrfVerifyResult { coefficients, ecdh_keys, encryption_commitments })
  }
}
