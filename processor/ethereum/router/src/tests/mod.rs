use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore, OsRng};

use group::ff::Field;
use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::{Address, U256, TxKind};
use alloy_sol_types::SolCall;

use alloy_consensus::TxLegacy;

use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionReceipt};
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::RootProvider;

use alloy_node_bindings::{Anvil, AnvilInstance};

use ethereum_primitives::LogIndex;
use ethereum_schnorr::{PublicKey, Signature};
use ethereum_deployer::Deployer;

use crate::{Coin, OutInstructions, Router};

#[test]
fn execute_reentrancy_guard() {
  let hash = alloy_core::primitives::keccak256(b"ReentrancyGuard Router.execute");
  assert_eq!(
    alloy_core::primitives::hex::encode(
      (U256::from_be_slice(hash.as_ref()) - U256::from(1u8)).to_be_bytes::<32>()
    ),
    // Constant from the Router contract
    "cf124a063de1614fedbd6b47187f98bf8873a1ae83da5c179a5881162f5b2401",
  );
}

#[test]
fn selector_collisions() {
  assert_eq!(
    crate::_irouter_abi::IRouter::confirmNextSeraiKeyCall::SELECTOR,
    crate::_router_abi::Router::confirmNextSeraiKey34AC53ACCall::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::updateSeraiKeyCall::SELECTOR,
    crate::_router_abi::Router::updateSeraiKey5A8542A2Call::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::executeCall::SELECTOR,
    crate::_router_abi::Router::execute4DE42904Call::SELECTOR
  );
  assert_eq!(
    crate::_irouter_abi::IRouter::escapeHatchCall::SELECTOR,
    crate::_router_abi::Router::escapeHatchDCDD91CCCall::SELECTOR
  );
}

pub(crate) fn test_key() -> (Scalar, PublicKey) {
  loop {
    let key = Scalar::random(&mut OsRng);
    let point = ProjectivePoint::GENERATOR * key;
    if let Some(public_key) = PublicKey::new(point) {
      return (key, public_key);
    }
  }
}

async fn setup_test(
) -> (AnvilInstance, Arc<RootProvider<SimpleRequest>>, Router, (Scalar, PublicKey)) {
  let anvil = Anvil::new().spawn();

  let provider = Arc::new(RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()), true),
  ));

  let (private_key, public_key) = test_key();
  assert!(Router::new(provider.clone(), &public_key).await.unwrap().is_none());

  // Deploy the Deployer
  let receipt = ethereum_test_primitives::publish_tx(&provider, Deployer::deployment_tx()).await;
  assert!(receipt.status());

  // Get the TX to deploy the Router
  let mut tx = Router::deployment_tx(&public_key);
  // Set a gas price (100 gwei)
  tx.gas_price = 100_000_000_000;
  // Sign it
  let tx = ethereum_primitives::deterministically_sign(tx);
  // Publish it
  let receipt = ethereum_test_primitives::publish_tx(&provider, tx).await;
  assert!(receipt.status());
  assert_eq!(Router::DEPLOYMENT_GAS, ((receipt.gas_used + 1000) / 1000) * 1000);

  let router = Router::new(provider.clone(), &public_key).await.unwrap().unwrap();

  (anvil, provider, router, (private_key, public_key))
}

#[tokio::test]
async fn test_constructor() {
  let (_anvil, _provider, router, key) = setup_test().await;
  assert_eq!(router.next_key(BlockNumberOrTag::Latest.into()).await.unwrap(), Some(key.1));
  assert_eq!(router.key(BlockNumberOrTag::Latest.into()).await.unwrap(), None);
  assert_eq!(router.next_nonce(BlockNumberOrTag::Latest.into()).await.unwrap(), 1);
  assert_eq!(
    router.escaped_to(BlockNumberOrTag::Latest.into()).await.unwrap(),
    Address::from([0; 20])
  );
}

async fn confirm_next_serai_key(
  provider: &Arc<RootProvider<SimpleRequest>>,
  router: &Router,
  nonce: u64,
  key: (Scalar, PublicKey),
) -> TransactionReceipt {
  let msg = Router::confirm_next_serai_key_message(nonce);

  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, &msg);
  let s = nonce + (c * key.0);

  let sig = Signature::new(c, s).unwrap();

  let mut tx = router.confirm_next_serai_key(&sig);
  tx.gas_price = 100_000_000_000;
  let tx = ethereum_primitives::deterministically_sign(tx);
  let receipt = ethereum_test_primitives::publish_tx(provider, tx).await;
  assert!(receipt.status());
  assert_eq!(Router::CONFIRM_NEXT_SERAI_KEY_GAS, ((receipt.gas_used + 1000) / 1000) * 1000);
  receipt
}

#[tokio::test]
async fn test_confirm_next_serai_key() {
  let (_anvil, provider, router, key) = setup_test().await;

  assert_eq!(router.next_key(BlockNumberOrTag::Latest.into()).await.unwrap(), Some(key.1));
  assert_eq!(router.key(BlockNumberOrTag::Latest.into()).await.unwrap(), None);
  assert_eq!(router.next_nonce(BlockNumberOrTag::Latest.into()).await.unwrap(), 1);

  let receipt = confirm_next_serai_key(&provider, &router, 1, key).await;

  assert_eq!(router.next_key(receipt.block_hash.unwrap().into()).await.unwrap(), None);
  assert_eq!(router.key(receipt.block_hash.unwrap().into()).await.unwrap(), Some(key.1));
  assert_eq!(router.next_nonce(receipt.block_hash.unwrap().into()).await.unwrap(), 2);
}

#[tokio::test]
async fn test_update_serai_key() {
  let (_anvil, provider, router, key) = setup_test().await;
  confirm_next_serai_key(&provider, &router, 1, key).await;

  let update_to = test_key().1;
  let msg = Router::update_serai_key_message(2, &update_to);

  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, &msg);
  let s = nonce + (c * key.0);

  let sig = Signature::new(c, s).unwrap();

  let mut tx = router.update_serai_key(&update_to, &sig);
  tx.gas_price = 100_000_000_000;
  let tx = ethereum_primitives::deterministically_sign(tx);
  let receipt = ethereum_test_primitives::publish_tx(&provider, tx).await;
  assert!(receipt.status());
  assert_eq!(Router::UPDATE_SERAI_KEY_GAS, ((receipt.gas_used + 1000) / 1000) * 1000);

  assert_eq!(router.key(receipt.block_hash.unwrap().into()).await.unwrap(), Some(key.1));
  assert_eq!(router.next_key(receipt.block_hash.unwrap().into()).await.unwrap(), Some(update_to));
  assert_eq!(router.next_nonce(receipt.block_hash.unwrap().into()).await.unwrap(), 3);
}

#[tokio::test]
async fn test_eth_in_instruction() {
  let (_anvil, provider, router, key) = setup_test().await;
  confirm_next_serai_key(&provider, &router, 1, key).await;

  let amount = U256::try_from(OsRng.next_u64()).unwrap();
  let mut in_instruction = vec![0; usize::try_from(OsRng.next_u64() % 256).unwrap()];
  OsRng.fill_bytes(&mut in_instruction);

  let tx = TxLegacy {
    chain_id: None,
    nonce: 0,
    // 100 gwei
    gas_price: 100_000_000_000,
    gas_limit: 1_000_000,
    to: TxKind::Call(router.address()),
    value: amount,
    input: crate::abi::inInstructionCall::new((
      [0; 20].into(),
      amount,
      in_instruction.clone().into(),
    ))
    .abi_encode()
    .into(),
  };
  let tx = ethereum_primitives::deterministically_sign(tx);
  let signer = tx.recover_signer().unwrap();

  let receipt = ethereum_test_primitives::publish_tx(&provider, tx).await;
  assert!(receipt.status());

  assert_eq!(receipt.inner.logs().len(), 1);
  let parsed_log =
    receipt.inner.logs()[0].log_decode::<crate::InInstructionEvent>().unwrap().inner.data;
  assert_eq!(parsed_log.from, signer);
  assert_eq!(parsed_log.coin, Address::from([0; 20]));
  assert_eq!(parsed_log.amount, amount);
  assert_eq!(parsed_log.instruction.as_ref(), &in_instruction);

  let parsed_in_instructions =
    router.in_instructions(receipt.block_number.unwrap(), &HashSet::new()).await.unwrap();
  assert_eq!(parsed_in_instructions.len(), 1);
  assert_eq!(
    parsed_in_instructions[0].id,
    LogIndex {
      block_hash: *receipt.block_hash.unwrap(),
      index_within_block: receipt.inner.logs()[0].log_index.unwrap(),
    },
  );
  assert_eq!(parsed_in_instructions[0].from, signer);
  assert_eq!(parsed_in_instructions[0].coin, Coin::Ether);
  assert_eq!(parsed_in_instructions[0].amount, amount);
  assert_eq!(parsed_in_instructions[0].data, in_instruction);
}

#[tokio::test]
async fn test_erc20_in_instruction() {
  todo!("TODO")
}

async fn publish_outs(
  provider: &RootProvider<SimpleRequest>,
  router: &Router,
  key: (Scalar, PublicKey),
  nonce: u64,
  coin: Coin,
  fee: U256,
  outs: OutInstructions,
) -> TransactionReceipt {
  let msg = Router::execute_message(nonce, coin, fee, outs.clone());

  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, &msg);
  let s = nonce + (c * key.0);

  let sig = Signature::new(c, s).unwrap();

  let mut tx = router.execute(coin, fee, outs, &sig);
  tx.gas_price = 100_000_000_000;
  let tx = ethereum_primitives::deterministically_sign(tx);
  ethereum_test_primitives::publish_tx(provider, tx).await
}

#[tokio::test]
async fn test_eth_address_out_instruction() {
  let (_anvil, provider, router, key) = setup_test().await;
  confirm_next_serai_key(&provider, &router, 1, key).await;

  let mut amount = U256::try_from(OsRng.next_u64()).unwrap();
  let mut fee = U256::try_from(OsRng.next_u64()).unwrap();
  if fee > amount {
    core::mem::swap(&mut amount, &mut fee);
  }
  assert!(amount >= fee);
  ethereum_test_primitives::fund_account(&provider, router.address(), amount).await;

  let instructions = OutInstructions::from([].as_slice());
  let receipt = publish_outs(&provider, &router, key, 2, Coin::Ether, fee, instructions).await;
  assert!(receipt.status());
  assert_eq!(Router::EXECUTE_BASE_GAS, ((receipt.gas_used + 1000) / 1000) * 1000);

  assert_eq!(router.next_nonce(receipt.block_hash.unwrap().into()).await.unwrap(), 3);
}

#[tokio::test]
async fn test_erc20_address_out_instruction() {
  todo!("TODO")
}

#[tokio::test]
async fn test_eth_code_out_instruction() {
  todo!("TODO")
}

#[tokio::test]
async fn test_erc20_code_out_instruction() {
  todo!("TODO")
}

async fn escape_hatch(
  provider: &Arc<RootProvider<SimpleRequest>>,
  router: &Router,
  nonce: u64,
  key: (Scalar, PublicKey),
  escape_to: Address,
) -> TransactionReceipt {
  let msg = Router::escape_hatch_message(nonce, escape_to);

  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, &msg);
  let s = nonce + (c * key.0);

  let sig = Signature::new(c, s).unwrap();

  let mut tx = router.escape_hatch(escape_to, &sig);
  tx.gas_price = 100_000_000_000;
  let tx = ethereum_primitives::deterministically_sign(tx);
  let receipt = ethereum_test_primitives::publish_tx(provider, tx).await;
  assert!(receipt.status());
  assert_eq!(Router::ESCAPE_HATCH_GAS, ((receipt.gas_used + 1000) / 1000) * 1000);
  receipt
}

async fn escape(
  provider: &Arc<RootProvider<SimpleRequest>>,
  router: &Router,
  coin: Coin,
) -> TransactionReceipt {
  let mut tx = router.escape(coin.address());
  tx.gas_price = 100_000_000_000;
  let tx = ethereum_primitives::deterministically_sign(tx);
  let receipt = ethereum_test_primitives::publish_tx(provider, tx).await;
  assert!(receipt.status());
  receipt
}

#[tokio::test]
async fn test_escape_hatch() {
  let (_anvil, provider, router, key) = setup_test().await;
  confirm_next_serai_key(&provider, &router, 1, key).await;
  let escape_to: Address = {
    let mut escape_to = [0; 20];
    OsRng.fill_bytes(&mut escape_to);
    escape_to.into()
  };
  escape_hatch(&provider, &router, 2, key, escape_to).await;
  escape(&provider, &router, Coin::Ether).await;
}
