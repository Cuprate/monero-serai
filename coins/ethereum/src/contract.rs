use crate::crypto::ProcessedSignature;
use ethers::{contract::ContractFactory, prelude::*, solc::artifacts::contract::ContractBytecode};
use eyre::{eyre, Result};
use std::fs::File;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
  #[error("failed to verify Schnorr signature")]
  VerificationError,
}

abigen!(
  Schnorr,
  "./artifacts/Schnorr.sol/Schnorr.json",
  event_derives(serde::Deserialize, serde::Serialize),
);

abigen!(
  Router,
  "./artifacts/Router.sol/Router.json",
  event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
  client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
  let path = "./artifacts/Schnorr.sol/Schnorr.json";
  let artifact: ContractBytecode = serde_json::from_reader(File::open(path).unwrap()).unwrap();
  let abi = artifact.abi.unwrap();
  let bin = artifact.bytecode.unwrap().object;
  let factory = ContractFactory::new(abi, bin.into_bytes().unwrap(), client.clone());
  let contract = factory.deploy(())?.send().await?;
  let contract = Schnorr::new(contract.address(), client);
  Ok(contract)
}

pub async fn deploy_router_contract(
  client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>> {
  let path = "./artifacts/Router.sol/Router.json";
  let artifact: ContractBytecode = serde_json::from_reader(File::open(path).unwrap()).unwrap();
  let abi = artifact.abi.unwrap();
  let bin = artifact.bytecode.unwrap().object;
  let factory = ContractFactory::new(abi, bin.into_bytes().unwrap(), client.clone());
  let contract = factory.deploy(())?.send().await?;
  let contract = Router::new(contract.address(), client);
  Ok(contract)
}

pub async fn call_verify(
  contract: &schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>,
  params: &ProcessedSignature,
) -> Result<()> {
  if contract
    .verify(
      params.parity + 27,
      params.px.to_bytes().into(),
      params.message,
      params.s.to_bytes().into(),
      params.e.to_bytes().into(),
    )
    .call()
    .await?
  {
    Ok(())
  } else {
    Err(eyre!(EthereumError::VerificationError))
  }
}

pub async fn call_router_execute(
  contract: &router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>,
  txs: Vec<router_mod::Transaction>,
  signature: &ProcessedSignature,
) -> Result<()> {
  if contract
    .execute(
      txs,
      signature.parity + 27,
      signature.px.to_bytes().into(),
      signature.s.to_bytes().into(),
      signature.e.to_bytes().into(),
    )
    .call()
    .await?
  {
    Ok(())
  } else {
    Err(eyre!(EthereumError::VerificationError))
  }
}
