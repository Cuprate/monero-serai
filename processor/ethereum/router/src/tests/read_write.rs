use rand_core::{RngCore, OsRng};

use alloy_core::primitives::U256;

use crate::{Coin, InInstruction, Executed};

fn coins() -> [Coin; 2] {
  [Coin::Ether, {
    let mut erc20 = [0; 20];
    OsRng.fill_bytes(&mut erc20);
    Coin::Erc20(erc20.into())
  }]
}

#[test]
fn test_coin_read_write() {
  for coin in coins() {
    let mut res = vec![];
    coin.write(&mut res).unwrap();
    assert_eq!(coin, Coin::read(&mut res.as_slice()).unwrap());
  }
}

#[test]
fn test_in_instruction_read_write() {
  for coin in coins() {
    let instruction = InInstruction {
      id: (
        {
          let mut tx_id = [0; 32];
          OsRng.fill_bytes(&mut tx_id);
          tx_id
        },
        OsRng.next_u64(),
      ),
      from: {
        let mut from = [0; 20];
        OsRng.fill_bytes(&mut from);
        from
      },
      coin,
      amount: U256::from_le_bytes({
        let mut amount = [0; 32];
        OsRng.fill_bytes(&mut amount);
        amount
      }),
      data: {
        let len = usize::try_from(OsRng.next_u64() % 65536).unwrap();
        let mut data = vec![0; len];
        OsRng.fill_bytes(&mut data);
        data
      },
    };

    let mut buf = vec![];
    instruction.write(&mut buf).unwrap();
    assert_eq!(InInstruction::read(&mut buf.as_slice()).unwrap(), instruction);
  }
}

#[test]
fn test_executed_read_write() {
  for executed in [
    Executed::SetKey {
      nonce: OsRng.next_u64(),
      key: {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        key
      },
    },
    Executed::Batch {
      nonce: OsRng.next_u64(),
      message_hash: {
        let mut message_hash = [0; 32];
        OsRng.fill_bytes(&mut message_hash);
        message_hash
      },
    },
  ] {
    let mut res = vec![];
    executed.write(&mut res).unwrap();
    assert_eq!(executed, Executed::read(&mut res.as_slice()).unwrap());
  }
}
