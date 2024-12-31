# Serai Coordinate Substrate Scanner

This is the scanner of the Serai blockchain for the purposes of Serai's coordinator.

Two event streams are defined:

- Canonical events, which must be handled by every validator, regardless of the sets they're present
  in. These are represented by `serai_processor_messages::substrate::CoordinatorMessage`.
- Ephemeral events, which only need to be handled by the validators present within the sets they
  relate to. These are represented by two channels, `NewSet` and `SignSlashReport`.

The canonical event stream is available without provision of a validator's public key. The ephemeral
event stream requires provision of a validator's public key. Both are ordered within themselves, yet
there are no ordering guarantees across the two.
