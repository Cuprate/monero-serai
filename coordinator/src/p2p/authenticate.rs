use core::{pin::Pin, future::Future};
use std::{sync::Arc, io};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use blake2::{Digest, Blake2s256};
use schnorrkel::{Keypair, PublicKey, Signature};

use serai_client::primitives::PublicKey as Public;

use tokio::sync::RwLock;

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{core::UpgradeInfo, InboundUpgrade, OutboundUpgrade, identity::PeerId, noise};

use crate::p2p::{validators::Validators, peer_id_from_public};

const PROTOCOL: &str = "/serai/coordinator/validators";

struct OnlyValidators {
  validators: Arc<RwLock<Validators>>,
  serai_key: Zeroizing<Keypair>,
  our_peer_id: PeerId,
}

impl OnlyValidators {
  /// The ephemeral challenge protocol for authentication.
  ///
  /// We use ephemeral challenges to prevent replaying signatures from historic sessions.
  ///
  /// We don't immediately send the challenge. We only send a commitment to it. This prevents our
  /// remote peer from choosing their challenge in response to our challenge, in case there was any
  /// benefit to doing so.
  async fn challenges<S: 'static + Send + Unpin + AsyncRead + AsyncWrite>(
    socket: &mut noise::Output<S>,
  ) -> io::Result<([u8; 32], [u8; 32])> {
    let mut our_challenge = [0; 32];
    OsRng.fill_bytes(&mut our_challenge);

    // Write the hash of our challenge
    socket.write_all(&Blake2s256::digest(our_challenge)).await?;

    // Read the hash of their challenge
    let mut their_challenge_commitment = [0; 32];
    socket.read_exact(&mut their_challenge_commitment).await?;

    // Reveal our challenge
    socket.write_all(&our_challenge).await?;

    // Read their challenge
    let mut their_challenge = [0; 32];
    socket.read_exact(&mut their_challenge).await?;

    // Verify their challenge
    if <[u8; 32]>::from(Blake2s256::digest(their_challenge)) != their_challenge_commitment {
      Err(io::Error::other("challenge didn't match challenge commitment"))?;
    }

    Ok((our_challenge, their_challenge))
  }

  // We sign the two noise peer IDs and the ephemeral challenges.
  //
  // Signing the noise peer IDs ensures we're authenticating this noise connection. The only
  // expectations placed on noise are for it to prevent a MITM from impersonating the other end or
  // modifying any messages sent.
  //
  // Signing the ephemeral challenges prevents any replays. While that should be unnecessary, as
  // noise MAY prevent replays across sessions (even when the same key is used), and noise IDs
  // shouldn't be reused (so it should be fine to reuse an existing signature for these noise IDs),
  // it doesn't hurt.
  async fn authenticate<S: 'static + Send + Unpin + AsyncRead + AsyncWrite>(
    &self,
    socket: &mut noise::Output<S>,
    dialer_peer_id: PeerId,
    dialer_challenge: [u8; 32],
    listener_peer_id: PeerId,
    listener_challenge: [u8; 32],
  ) -> io::Result<PeerId> {
    // Write our public key
    socket.write_all(&self.serai_key.public.to_bytes()).await?;

    let msg = borsh::to_vec(&(
      dialer_peer_id.to_bytes(),
      dialer_challenge,
      listener_peer_id.to_bytes(),
      listener_challenge,
    ))
    .unwrap();
    let signature = self.serai_key.sign_simple(PROTOCOL.as_bytes(), &msg);
    socket.write_all(&signature.to_bytes()).await?;

    let mut public_key_and_sig = [0; 96];
    socket.read_exact(&mut public_key_and_sig).await?;
    let public_key = PublicKey::from_bytes(&public_key_and_sig[.. 32])
      .map_err(|_| io::Error::other("invalid public key"))?;
    let sig = Signature::from_bytes(&public_key_and_sig[32 ..])
      .map_err(|_| io::Error::other("invalid signature serialization"))?;

    public_key
      .verify_simple(PROTOCOL.as_bytes(), &msg, &sig)
      .map_err(|_| io::Error::other("invalid signature"))?;

    let peer_id = peer_id_from_public(Public::from_raw(public_key.to_bytes()));
    if !self.validators.read().await.contains(&peer_id) {
      Err(io::Error::other("peer which tried to connect isn't a known active validator"))?;
    }

    Ok(peer_id)
  }
}

impl UpgradeInfo for OnlyValidators {
  type Info = &'static str;
  type InfoIter = [&'static str; 1];
  fn protocol_info(&self) -> [&'static str; 1] {
    [PROTOCOL]
  }
}

impl<S: 'static + Send + Unpin + AsyncRead + AsyncWrite> InboundUpgrade<(PeerId, noise::Output<S>)>
  for OnlyValidators
{
  type Output = (PeerId, noise::Output<S>);
  type Error = io::Error;
  type Future = Pin<Box<dyn Send + Future<Output = Result<Self::Output, Self::Error>>>>;

  fn upgrade_inbound(
    self,
    (dialer_noise_peer_id, mut socket): (PeerId, noise::Output<S>),
    _: Self::Info,
  ) -> Self::Future {
    Box::pin(async move {
      let (our_challenge, dialer_challenge) = OnlyValidators::challenges(&mut socket).await?;
      let dialer_serai_validator = self
        .authenticate(
          &mut socket,
          dialer_noise_peer_id,
          dialer_challenge,
          self.our_peer_id,
          our_challenge,
        )
        .await?;
      Ok((dialer_serai_validator, socket))
    })
  }
}

impl<S: 'static + Send + Unpin + AsyncRead + AsyncWrite> OutboundUpgrade<(PeerId, noise::Output<S>)>
  for OnlyValidators
{
  type Output = (PeerId, noise::Output<S>);
  type Error = io::Error;
  type Future = Pin<Box<dyn Send + Future<Output = Result<Self::Output, Self::Error>>>>;

  fn upgrade_outbound(
    self,
    (listener_noise_peer_id, mut socket): (PeerId, noise::Output<S>),
    _: Self::Info,
  ) -> Self::Future {
    Box::pin(async move {
      let (our_challenge, listener_challenge) = OnlyValidators::challenges(&mut socket).await?;
      let listener_serai_validator = self
        .authenticate(
          &mut socket,
          self.our_peer_id,
          our_challenge,
          listener_noise_peer_id,
          listener_challenge,
        )
        .await?;
      Ok((listener_serai_validator, socket))
    })
  }
}
