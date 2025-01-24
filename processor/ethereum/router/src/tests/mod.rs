use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore, OsRng};

use group::ff::Field;
use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::{Address, U256, TxKind};
use alloy_sol_types::SolCall;

use alloy_consensus::TxLegacy;

#[rustfmt::skip]
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionInput, TransactionRequest, TransactionReceipt};
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use alloy_node_bindings::{Anvil, AnvilInstance};

use scale::Encode;
use serai_client::{
  primitives::SeraiAddress,
  in_instructions::primitives::{
    InInstruction as SeraiInInstruction, RefundableInInstruction, Shorthand,
  },
};

use ethereum_primitives::LogIndex;
use ethereum_schnorr::{PublicKey, Signature};
use ethereum_deployer::Deployer;

use crate::{
  _irouter_abi::IRouterWithoutCollisions::{
    self as IRouter, IRouterWithoutCollisionsErrors as IRouterErrors,
  },
  Coin, InInstruction, OutInstructions, Router, Executed, Escape,
};

mod constants;
mod erc20;
use erc20::Erc20;

pub(crate) fn test_key() -> (Scalar, PublicKey) {
  loop {
    let key = Scalar::random(&mut OsRng);
    let point = ProjectivePoint::GENERATOR * key;
    if let Some(public_key) = PublicKey::new(point) {
      return (key, public_key);
    }
  }
}

fn sign(key: (Scalar, PublicKey), msg: &[u8]) -> Signature {
  let nonce = Scalar::random(&mut OsRng);
  let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &key.1, msg);
  let s = nonce + (c * key.0);
  Signature::new(c, s).unwrap()
}

/// Calculate the gas used by a transaction if none of its calldata's bytes were zero
struct CalldataAgnosticGas;
impl CalldataAgnosticGas {
  fn calculate(tx: &TxLegacy, mut gas_used: u64) -> u64 {
    const ZERO_BYTE_GAS_COST: u64 = 4;
    const NON_ZERO_BYTE_GAS_COST: u64 = 16;
    for b in &tx.input {
      if *b == 0 {
        gas_used += NON_ZERO_BYTE_GAS_COST - ZERO_BYTE_GAS_COST;
      }
    }
    gas_used
  }
}

struct RouterState {
  next_key: Option<(Scalar, PublicKey)>,
  key: Option<(Scalar, PublicKey)>,
  next_nonce: u64,
  escaped_to: Option<Address>,
}

struct Test {
  #[allow(unused)]
  anvil: AnvilInstance,
  provider: Arc<RootProvider<SimpleRequest>>,
  chain_id: U256,
  router: Router,
  state: RouterState,
}

impl Test {
  async fn verify_state(&self) {
    assert_eq!(
      self.router.next_key(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.next_key.map(|key| key.1)
    );
    assert_eq!(
      self.router.key(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.key.map(|key| key.1)
    );
    assert_eq!(
      self.router.next_nonce(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.next_nonce
    );
    assert_eq!(
      self.router.escaped_to(BlockNumberOrTag::Latest.into()).await.unwrap(),
      self.state.escaped_to,
    );
  }

  async fn new() -> Self {
    // The following is explicitly only evaluated against the cancun network upgrade at this time
    let anvil = Anvil::new().arg("--hardfork").arg("cancun").spawn();

    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()), true),
    ));
    let chain_id = U256::from(provider.get_chain_id().await.unwrap());

    let (private_key, public_key) = test_key();
    assert!(Router::new(provider.clone(), &public_key).await.unwrap().is_none());

    // Deploy the Deployer
    let receipt = ethereum_test_primitives::publish_tx(&provider, Deployer::deployment_tx()).await;
    assert!(receipt.status());

    let mut tx = Router::deployment_tx(&public_key);
    tx.gas_limit = 1_100_000;
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&provider, tx).await;
    assert!(receipt.status());

    let router = Router::new(provider.clone(), &public_key).await.unwrap().unwrap();
    let state = RouterState {
      next_key: Some((private_key, public_key)),
      key: None,
      // Nonce 0 should've been consumed by setting the next key to the key initialized with
      next_nonce: 1,
      escaped_to: None,
    };

    // Confirm nonce 0 was used as such
    {
      let block = receipt.block_number.unwrap();
      let executed = router.executed(block, block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(executed[0], Executed::NextSeraiKeySet { nonce: 0, key: public_key.eth_repr() });
    }

    let res = Test { anvil, provider, chain_id, router, state };
    res.verify_state().await;
    res
  }

  async fn call_and_decode_err(&self, tx: TxLegacy) -> IRouterErrors {
    let call = TransactionRequest::default()
      .to(self.router.address())
      .input(TransactionInput::new(tx.input));
    let call_err = self.provider.call(&call).await.unwrap_err();
    call_err.as_error_resp().unwrap().as_decoded_error::<IRouterErrors>(true).unwrap()
  }

  fn confirm_next_serai_key_tx(&self) -> TxLegacy {
    let msg = Router::confirm_next_serai_key_message(self.chain_id, self.state.next_nonce);
    let sig = sign(self.state.next_key.unwrap(), &msg);

    self.router.confirm_next_serai_key(&sig)
  }

  async fn confirm_next_serai_key(&mut self) {
    let mut tx = self.confirm_next_serai_key_tx();
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    // Only check the gas is equal when writing to a previously unallocated storage slot, as this
    // is the highest possible gas cost and what the constant is derived from
    if self.state.key.is_none() {
      assert_eq!(
        CalldataAgnosticGas::calculate(tx.tx(), receipt.gas_used),
        Router::CONFIRM_NEXT_SERAI_KEY_GAS,
      );
    } else {
      assert!(
        CalldataAgnosticGas::calculate(tx.tx(), receipt.gas_used) <
          Router::CONFIRM_NEXT_SERAI_KEY_GAS
      );
    }

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block, block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(
        executed[0],
        Executed::SeraiKeyUpdated {
          nonce: self.state.next_nonce,
          key: self.state.next_key.unwrap().1.eth_repr()
        }
      );
    }

    self.state.next_nonce += 1;
    self.state.key = self.state.next_key;
    self.state.next_key = None;
    self.verify_state().await;
  }

  fn update_serai_key_tx(&self) -> ((Scalar, PublicKey), TxLegacy) {
    let next_key = test_key();

    let msg = Router::update_serai_key_message(self.chain_id, self.state.next_nonce, &next_key.1);
    let sig = sign(self.state.key.unwrap(), &msg);

    (next_key, self.router.update_serai_key(&next_key.1, &sig))
  }

  async fn update_serai_key(&mut self) {
    let (next_key, mut tx) = self.update_serai_key_tx();
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    assert_eq!(
      CalldataAgnosticGas::calculate(tx.tx(), receipt.gas_used),
      Router::UPDATE_SERAI_KEY_GAS,
    );

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block, block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(
        executed[0],
        Executed::NextSeraiKeySet { nonce: self.state.next_nonce, key: next_key.1.eth_repr() }
      );
    }

    self.state.next_nonce += 1;
    self.state.next_key = Some(next_key);
    self.verify_state().await;
  }

  fn in_instruction() -> Shorthand {
    Shorthand::Raw(RefundableInInstruction {
      origin: None,
      instruction: SeraiInInstruction::Transfer(SeraiAddress([0xff; 32])),
    })
  }

  fn eth_in_instruction_tx(&self) -> (Coin, U256, Shorthand, TxLegacy) {
    let coin = Coin::Ether;
    let amount = U256::from(1);
    let shorthand = Self::in_instruction();

    let mut tx = self.router.in_instruction(coin, amount, &shorthand);
    tx.gas_limit = 1_000_000;
    tx.gas_price = 100_000_000_000;

    (coin, amount, shorthand, tx)
  }

  fn escape_hatch_tx(&self, escape_to: Address) -> TxLegacy {
    let msg = Router::escape_hatch_message(self.chain_id, self.state.next_nonce, escape_to);
    let sig = sign(self.state.key.unwrap(), &msg);
    self.router.escape_hatch(escape_to, &sig)
  }

  async fn escape_hatch(&mut self) {
    let mut escape_to = [0; 20];
    OsRng.fill_bytes(&mut escape_to);
    let escape_to = Address(escape_to.into());

    // Set the code of the address to escape to so it isn't flagged as a non-contract
    let () = self.provider.raw_request("anvil_setCode".into(), (escape_to, [0])).await.unwrap();

    let mut tx = self.escape_hatch_tx(escape_to);
    tx.gas_price = 100_000_000_000;
    let tx = ethereum_primitives::deterministically_sign(tx);
    let receipt = ethereum_test_primitives::publish_tx(&self.provider, tx.clone()).await;
    assert!(receipt.status());
    assert_eq!(CalldataAgnosticGas::calculate(tx.tx(), receipt.gas_used), Router::ESCAPE_HATCH_GAS);

    {
      let block = receipt.block_number.unwrap();
      let executed = self.router.executed(block, block).await.unwrap();
      assert_eq!(executed.len(), 1);
      assert_eq!(executed[0], Executed::EscapeHatch { nonce: self.state.next_nonce, escape_to });
    }

    self.state.next_nonce += 1;
    self.state.escaped_to = Some(escape_to);
    self.verify_state().await;
  }

  fn escape_tx(&self, coin: Coin) -> TxLegacy {
    let mut tx = self.router.escape(coin);
    tx.gas_limit = 100_000;
    tx.gas_price = 100_000_000_000;
    tx
  }
}

#[tokio::test]
async fn test_constructor() {
  // `Test::new` internalizes all checks on initial state
  Test::new().await;
}

#[tokio::test]
async fn test_confirm_next_serai_key() {
  let mut test = Test::new().await;
  // TODO: Check all calls fail at this time, including inInstruction
  test.confirm_next_serai_key().await;
}

#[tokio::test]
async fn test_update_serai_key() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;
  test.update_serai_key().await;

  // Once we update to a new key, we should, of course, be able to continue to rotate keys
  test.confirm_next_serai_key().await;
}

#[tokio::test]
async fn test_eth_in_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let (coin, amount, shorthand, tx) = test.eth_in_instruction_tx();

  // This should fail if the value mismatches the amount
  {
    let mut tx = tx.clone();
    tx.value = U256::ZERO;
    assert!(matches!(
      test.call_and_decode_err(tx).await,
      IRouterErrors::AmountMismatchesMsgValue(IRouter::AmountMismatchesMsgValue {})
    ));
  }

  let tx = ethereum_primitives::deterministically_sign(tx);
  let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
  assert!(receipt.status());

  let block = receipt.block_number.unwrap();
  let in_instructions =
    test.router.in_instructions_unordered(block, block, &HashSet::new()).await.unwrap();
  assert_eq!(in_instructions.len(), 1);
  assert_eq!(
    in_instructions[0],
    InInstruction {
      id: LogIndex {
        block_hash: *receipt.block_hash.unwrap(),
        index_within_block: receipt.inner.logs()[0].log_index.unwrap(),
      },
      transaction_hash: **tx.hash(),
      from: tx.recover_signer().unwrap(),
      coin,
      amount,
      data: shorthand.encode(),
    }
  );
}

#[tokio::test]
async fn test_erc20_in_instruction() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  let erc20 = Erc20::deploy(&test).await;

  let coin = Coin::Erc20(erc20.address());
  let amount = U256::from(1);
  let shorthand = Test::in_instruction();

  // The provided `in_instruction` function will use a top-level transfer for ERC20 InInstructions,
  // so we have to manually write this call
  let tx = TxLegacy {
    chain_id: None,
    nonce: 0,
    gas_price: 100_000_000_000u128,
    gas_limit: 1_000_000,
    to: test.router.address().into(),
    value: U256::ZERO,
    input: crate::abi::inInstructionCall::new((coin.into(), amount, shorthand.encode().into()))
      .abi_encode()
      .into(),
  };

  // If no `approve` was granted, this should fail
  assert!(matches!(
    test.call_and_decode_err(tx.clone()).await,
    IRouterErrors::TransferFromFailed(IRouter::TransferFromFailed {})
  ));

  let tx = ethereum_primitives::deterministically_sign(tx);
  {
    let signer = tx.recover_signer().unwrap();
    erc20.mint(&test, signer, amount).await;
    erc20.approve(&test, signer, test.router.address(), amount).await;
  }
  let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
  assert!(receipt.status());

  let block = receipt.block_number.unwrap();

  // If we don't whitelist this token, we shouldn't be yielded an InInstruction
  {
    let in_instructions =
      test.router.in_instructions_unordered(block, block, &HashSet::new()).await.unwrap();
    assert!(in_instructions.is_empty());
  }

  let in_instructions = test
    .router
    .in_instructions_unordered(block, block, &HashSet::from([coin.into()]))
    .await
    .unwrap();
  assert_eq!(in_instructions.len(), 1);
  assert_eq!(
    in_instructions[0],
    InInstruction {
      id: LogIndex {
        block_hash: *receipt.block_hash.unwrap(),
        // First is the Transfer log, then the InInstruction log
        index_within_block: receipt.inner.logs()[1].log_index.unwrap(),
      },
      transaction_hash: **tx.hash(),
      from: tx.recover_signer().unwrap(),
      coin,
      amount,
      data: shorthand.encode(),
    }
  );
}

#[tokio::test]
async fn test_eth_address_out_instruction() {
  todo!("TODO")
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

#[tokio::test]
async fn test_escape_hatch() {
  let mut test = Test::new().await;
  test.confirm_next_serai_key().await;

  // Queue another key so the below test cases can run
  test.update_serai_key().await;

  {
    // The zero address should be invalid to escape to
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([0; 20].into())).await,
      IRouterErrors::InvalidEscapeAddress(IRouter::InvalidEscapeAddress {})
    ));
    // Empty addresses should be invalid to escape to
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([1; 20].into())).await,
      IRouterErrors::EscapeAddressWasNotAContract(IRouter::EscapeAddressWasNotAContract {})
    ));
    // Non-empty addresses without code should be invalid to escape to
    let tx = ethereum_primitives::deterministically_sign(TxLegacy {
      to: Address([1; 20].into()).into(),
      gas_limit: 21_000,
      gas_price: 100_000_000_000u128,
      value: U256::from(1),
      ..Default::default()
    });
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
    assert!(receipt.status());
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx([1; 20].into())).await,
      IRouterErrors::EscapeAddressWasNotAContract(IRouter::EscapeAddressWasNotAContract {})
    ));

    // Escaping at this point in time should fail
    assert!(matches!(
      test.call_and_decode_err(test.router.escape(Coin::Ether)).await,
      IRouterErrors::EscapeHatchNotInvoked(IRouter::EscapeHatchNotInvoked {})
    ));
  }

  // Invoke the escape hatch
  test.escape_hatch().await;

  // Now that the escape hatch has been invoked, all of the following calls should fail
  {
    assert!(matches!(
      test.call_and_decode_err(test.update_serai_key_tx().1).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    assert!(matches!(
      test.call_and_decode_err(test.confirm_next_serai_key_tx()).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    assert!(matches!(
      test.call_and_decode_err(test.eth_in_instruction_tx().3).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
    // TODO execute
    // We reject further attempts to update the escape hatch to prevent the last key from being
    // able to switch from the honest escape hatch to siphoning via a malicious escape hatch (such
    // as after the validators represented unstake)
    assert!(matches!(
      test.call_and_decode_err(test.escape_hatch_tx(test.state.escaped_to.unwrap())).await,
      IRouterErrors::EscapeHatchInvoked(IRouter::EscapeHatchInvoked {})
    ));
  }

  // Check the escape fn itself

  // ETH
  {
    let () = test
      .provider
      .raw_request("anvil_setBalance".into(), (test.router.address(), 1))
      .await
      .unwrap();
    let tx = ethereum_primitives::deterministically_sign(test.escape_tx(Coin::Ether));
    let receipt = ethereum_test_primitives::publish_tx(&test.provider, tx.clone()).await;
    assert!(receipt.status());

    let block = receipt.block_number.unwrap();
    assert_eq!(
      test.router.escapes(block, block).await.unwrap(),
      vec![Escape { coin: Coin::Ether, amount: U256::from(1) }],
    );

    assert!(test.provider.get_balance(test.router.address()).await.unwrap() == U256::from(0));
    assert!(
      test.provider.get_balance(test.state.escaped_to.unwrap()).await.unwrap() == U256::from(1)
    );
  }

  // TODO ERC20 escape
}

/*
  event InInstruction(
    address indexed from, address indexed coin, uint256 amount, bytes instruction
  );
  event Batch(uint256 indexed nonce, bytes32 indexed messageHash, bytes results);
  error InvalidSeraiKey();
  error InvalidSignature();
  error AmountMismatchesMsgValue();
  error TransferFromFailed();
  error Reentered();
  error EscapeFailed();
  function executeArbitraryCode(bytes memory code) external payable;
  struct Signature {
    bytes32 c;
    bytes32 s;
  }
  enum DestinationType {
    Address,
    Code
  }
  struct CodeDestination {
    uint32 gasLimit;
    bytes code;
  }
  struct OutInstruction {
    DestinationType destinationType;
    bytes destination;
    uint256 amount;
  }
  function execute(
    Signature calldata signature,
    address coin,
    uint256 fee,
    OutInstruction[] calldata outs
  ) external;
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
    input: crate::_irouter_abi::inInstructionCall::new((
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
*/
