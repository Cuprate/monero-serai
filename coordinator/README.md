# Coordinator

- [`tendermint`](/tributary/tendermint) is an implementation of the Tendermint BFT algorithm.

- [`tributary`](./tributary) is a micro-blockchain framework. Instead of a producing a blockchain
  daemon like the Polkadot SDK or Cosmos SDK intend to, `tributary` is solely intended to be an
  embedded asynchronous task within an application.

  The Serai coordinator spawns a tributary for each validator set it's coordinating. This allows
  the participating validators to communicate in a byzantine-fault-tolerant manner (relying on
  Tendermint for consensus).

- [`cosign`](./cosign) contains a library to decide which Substrate blocks should be cosigned and
  to evaluate cosigns.

- [`substrate`](./substrate) contains a library to index the Substrate blockchain and handle its
  events.

- [`src`](./src) contains the source code for the Coordinator binary itself.
