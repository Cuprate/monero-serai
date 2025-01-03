use core::time::Duration;
use std::io::{self, Read};

use async_trait::async_trait;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_client::validator_sets::primitives::ValidatorSet;

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use libp2p::request_response::{Codec as CodecTrait, Config, Behaviour, ProtocolSupport};

use serai_cosign::SignedCosign;

/// The maximum message size for the request-response protocol
// This is derived from the heartbeat message size as it's our largest message
const MAX_LIBP2P_REQRES_MESSAGE_SIZE: usize =
  (tributary::BLOCK_SIZE_LIMIT * crate::p2p::heartbeat::BLOCKS_PER_BATCH) + 1024;

const PROTOCOL: &str = "/serai/coordinator";

/// Requests which can be made via the request-response protocol.
#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) enum Request {
  /// A keep-alive to prevent our connections from being dropped.
  KeepAlive,
  /// A heartbeat informing our peers of our latest block, for the specified blockchain, on regular
  /// intervals.
  ///
  /// If our peers have more blocks than us, they're expected to respond with those blocks.
  Heartbeat { set: ValidatorSet, latest_block_hash: [u8; 32] },
  /// A request for the notable cosigns for a global session.
  NotableCosigns { global_session: [u8; 32] },
}

/// A tributary block and its commit.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct TributaryBlockWithCommit {
  pub(crate) block: Vec<u8>,
  pub(crate) commit: Vec<u8>,
}

/// Responses which can be received via the request-response protocol.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) enum Response {
  Blocks(Vec<TributaryBlockWithCommit>),
  NotableCosigns(Vec<SignedCosign>),
}

/// The codec used for the request-response protocol.
///
/// We don't use CBOR or JSON, but use borsh to create `Vec<u8>`s we then length-prefix. While
/// ideally, we'd use borsh directly with the `io` traits defined here, they're async and there
/// isn't an amenable API within borsh for incremental deserialization.
#[derive(Default, Clone, Copy, Debug)]
struct Codec;
impl Codec {
  async fn read<M: BorshDeserialize>(io: &mut (impl Unpin + AsyncRead)) -> io::Result<M> {
    let mut len = [0; 4];
    io.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("not at least a 32-bit platform?");
    if len > MAX_LIBP2P_REQRES_MESSAGE_SIZE {
      Err(io::Error::other("request length exceeded MAX_LIBP2P_REQRES_MESSAGE_SIZE"))?;
    }
    // This may be a non-trivial allocation easily causable
    // While we could chunk the read, meaning we only perform the allocation as bandwidth is used,
    // the max message size should be sufficiently sane
    let mut buf = vec![0; len];
    io.read_exact(&mut buf).await?;
    let mut buf = buf.as_slice();
    let res = M::deserialize(&mut buf)?;
    if !buf.is_empty() {
      Err(io::Error::other("p2p message had extra data appended to it"))?;
    }
    Ok(res)
  }
  async fn write(io: &mut (impl Unpin + AsyncWrite), msg: &impl BorshSerialize) -> io::Result<()> {
    let msg = borsh::to_vec(msg).unwrap();
    io.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await?;
    io.write_all(&msg).await
  }
}
#[async_trait]
impl CodecTrait for Codec {
  type Protocol = &'static str;
  type Request = Request;
  type Response = Response;

  async fn read_request<R: Send + Unpin + AsyncRead>(
    &mut self,
    _: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Request> {
    Self::read(io).await
  }
  async fn read_response<R: Send + Unpin + AsyncRead>(
    &mut self,
    proto: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Response> {
    Self::read(io).await
  }
  async fn write_request<W: Send + Unpin + AsyncWrite>(
    &mut self,
    _: &Self::Protocol,
    io: &mut W,
    req: Request,
  ) -> io::Result<()> {
    Self::write(io, &req).await
  }
  async fn write_response<W: Send + Unpin + AsyncWrite>(
    &mut self,
    proto: &Self::Protocol,
    io: &mut W,
    res: Response,
  ) -> io::Result<()> {
    Self::write(io, &res).await
  }
}

pub(crate) type Behavior = Behaviour<Codec>;
pub(crate) fn new_behavior() -> Behavior {
  let mut config = Config::default();
  config.set_request_timeout(Duration::from_secs(5));
  Behavior::new([(PROTOCOL, ProtocolSupport::Full)], config)
}
