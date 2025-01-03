use serai_client::primitives::NetworkId;

mod reqres;
use reqres::{Request, Response};

mod gossip;

mod heartbeat;

struct Peer;
impl Peer {
  async fn send(&self, request: Request) -> Result<Response, tokio::time::error::Elapsed> {
    (async move { todo!("TODO") }).await
  }
}

#[derive(Clone, Debug)]
struct P2p;
impl P2p {
  async fn peers(&self, set: NetworkId) -> Vec<Peer> {
    (async move { todo!("TODO") }).await
  }
}

#[async_trait::async_trait]
impl tributary::P2p for P2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    todo!("TODO")
  }
}
