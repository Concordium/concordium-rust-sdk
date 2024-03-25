## Unreleased changes

- Bump MSRV to 1.73
- Update dependencies. In particular `concordium-base` and `concordium-smart-contract-engine` are bumped to version 5.

## 4.2.0

- Add a `ProcessorConfig` struct dual to the `TraverseConfig` to help in writing
  indexers.
- Bump MSRV to 1.72

## 4.1.1

- Fix incorrect calculation of the micro_ccd_per_eur helper.

## 4.1.0

- Add `ContractInitBuilder` for more ergonomic initialization of new smart
  contract instances with automatic NRG cost estimation.
- Add `ModuleDeployBuilder` for more ergonomic deployment of contract modules
  with automatic dry run and validation.

## 4.0.0

- Add a `From<&AccountInfo>` instance for `AccountAccessStructure` to ease verification of signatures using `GetAccountInfo` response.
- Add a `get_finalized_block_item` method to the `Client` to retrieve a finalized block item from the node.
- Remove the V1 API.
- Add `Display` implementation to `BlockIdentifier`.
- Add `Display` and `FromStr` implementations for `AccountIdentifier`.
- Rename `find_first_finalized_block_no_later_than` into
  `find_first_finalized_block_no_earlier_than` since that correctly reflects its
  semantics with respect to time and is much clearer.
- Make the `Client::new` method slightly more general by accepting a
  `TryInto<Endpoint>`. This allows passing URLs as strings directly.
- Add a new `indexer` module that provides boilerplate for robustly traversing
  the chain.
- Support protocol version 7.
- Support for smart contract debugging when running locally.
- Remove JSON serialization support of BlockSummary.
- Add an additional `indexer` to index all transaction outcomes and special events.
- Make the `energy` field of `ContractContext` optional since it is no longer
  required by the node.
- Add `dry_run_update` and `dry_run_update_raw` methods to the `ContractClient`
  to simulate smart contract updates. The return values of these can be used to
  immediately sign and send a transaction.
- Update `rand` dependency to `0.8`.
- Update `tonic` to 0.10.

## 3.2.0

- The sdk now requires a `rustc` version at least 1.67 (Before it required version 1.66).
- Add a `contract_update` helper analogous to `contract_init` to extract an
  execution tree from a smart contract update transaction.
- Add a `ccd_cost` helper to `ChainParameters` to convert NRG cost to CCD.
- Add support for `DryRun`. Requires a node version at least 6.2.

## 3.1.0

- Add a `commission_rates` field to `CurrentPaydayBakerPoolStatus` which yields the commission rates
  of the baker for the reward period. Requires a node version at least 6.1.
- Add support for `GetWinningBakersEpoch`. Requires a node version at least 6.1.
- Add Support for `GetFirstBlockEpoch`. Requires a node version at least 6.1.
- Add support for `GetBakersRewardPeriod` endpoint. Requires a node version at least 6.1.
- Add Support for `GetBakerEarliestWinTime` endpoint. Requires a node version at least 6.1.
- Add support for `GetBlockCertificates`. Requires a node version at least 6.1.
- Add `make_update` and `make_update_raw` methods to the `ContractClient`. They
  are like `update` and `update_raw` but instead of sending a transaction they
  only construct it and return it.
- Add `make_register_credential`, `make_revoke_credential_as_issuer` and
  `make_revoke_credential_other` to the CIS4 client. These are like the methods
  without the `make_` prefix, except that they only construct the transaction,
  they do not send it.
- Add `make_transfer` and `make_update_operator` functions to the CIS2 client.
  These are like the methods without the `make_`, except that they only
  construct the transaction.
- Update minimum supported rust version to `1.66`.


## 3.0.1

- Update `concordium_base` dependency to 3.0.1.

## 3.0.0

- The SDK requires node version 6 or later.
- Support relative and absolute block height as the block identifier in block queries.
- Add field `protocol_version` to `BlockInfo` which is the protocol version of the queried block.
- Extend enum `PendingUpdateEffect` with variants for protocol version 6.
- Introduce `ChainParametersV2` struct for protocol version 6.
- Introduce generic `gas_reward` in `RewardParametersSkeleton` for supporting different versions of GASRewards.
- Add `find_account_creation` helper to find a block where the account was
  created.
- Deprecate `find_earliest_finalized` and replace it with
  `find_at_lowest_height` that avoids an extra call to the node. This is making
  use of the new API.
- Re-export `http::Scheme` from `http` crate since it is often needed when
  configuring endpoints.
- Add a new `ContractClient` that supports operations on smart contract
  instances such as queries and updates.
- Add a `Cis4Contract` for interacting with Cis4 contracts.
- Add a new `web3id` module that contains types and functionality for
  construcing Web3ID credentials and verifying Web3ID proofs.
- Deprecate the client for V1 of the node's API.

### Breaking changes in types
- `ConsensusInfo`
  - `slot_duration` is now an optional field, only present in protocols 1-5.
  - a new field `concordium_bft_status` is added, that is present if protocol
    version is 6 or higher
- `BlockInfo`
  - `slot_number` is optional, and only present in protocols 1-5
  - new fields `round` and `epoch` that are present in protocol 6 or higher.
- `BirkParameters`
  - `election_difficulty` is optional, and only present in protocols 1-5.
- `NextUpdateSequenceNumbers`
  - Add `timeout_parameters`, `min_block_time`, `block_energy_limit`, and
    `finalization_committee_parameters` sequence numbers.

## 2.4.0

- Re-export `concordium_base` to enable use of `concordium_base_derive`
  serialization macros.
- Bump minimum supported rust version to 1.64.
- When using derive(Serial,Deserial) macros from the smart_contracts modules
  `concordium_std` must be made available, for example as 
  `use concordium_rust_sdk::smart_contracts::common as concordium_std`

## 2.3.0

- Add `find_earliest_finalized`, `find_instance_creation`,
  `find_first_finalized_block_no_later_than` methods to the `v2` client.
- Bump MSRV to 1.62
- Add deprecation notices to `ModuleRef` and `Parameter`. Use `ModuleReference`
  and `OwnedParameter`, respectively, instead.
  - Replace `AsRef<Vec<u8>>` with `AsRef<[u8]>` for `OwnedParameter` (and
    thereby also for the now deprecated `Parameter`).
    - Migrate from `parameter.as_ref()`: Use `&parameter.as_ref().to_vec()` instead.
  - `OwnedParameter` also has a number of additional methods and trait
    implementations, namely:
  - A `from_serial` method which constructs a new parameter by serializing the
    input and checking that the length is valid.
  - An `empty` method which constructs an empty parameter.
  - An `Into<Vec<u8>>` implementation for getting the inner `bytes`.
  - An `as_parameter` method for converting it to the borrowed version
    `Parameter(&[u8])` type (not to be confused with the now deprecated
    `Parameter(Vec<u8>)`).

## 2.2.0

- Add helpers to `WalletAccount` so that it can be constructed from genesis
  account format produced by the genesis creator tool, as well as from browser
  key export format.
- Fix contract schema's `to_json` to output contract addresses in the correct format.
- Add a `Display` implementation for `ContractEvent`.
- Add `_single` family of functions to `Cis2Contract` to make it easier to do
  queries and updates for a single token or operator.
- Generalize the signature of `Cis2Contract` methods that take a block
  identifier. They now take `impl IntoBlockIdentifier`. All existing uses should
  remain working since `&BlockIdentifier` implements this trait.
- Add `is_rejected_account_transaction` helper to `BlockItemSummary` to help
  extract reject reason for an account transaction.
- Add `update_operator_dry_run` and `transfer_dry_run` methods to
  `Cis2Contract`. These dry-run `update_operator` and `transfer` transactions
  using `invoke_instance`. They can be used to estimate transaction costs, and
  check whether the call will succeed.
- Add `is_payday_block` helper function to `v2::Client` to identify whether a specific block is one that includes payday events.
- Add `new_from_payload` helper to `ContractContext` for convenience when
  dry-running smart contract update transactions.
- Add a notion of `TokenAddress` and its string representation based on base58 encoding.

## 2.1.0

- Add `WalletAccount` type that can be parsed from the browser extension wallet
  export. This supports the signer interface and so can be used to send transactions.

## 2.0.0

- Expose macros for deriving `Serial` and `Deserial` from `concordium-contracts-common`.
- Address method `is_alias_of` is now `is_alias`.
- Replaced `ReceiveName` and `InitName` with `OwnedReceiveName` and `OwnedContractName` from `concordium-contracts-common`.
- Remove `ContractAddress` and `Address` in favor of their equivalents in `concordium-contracts-common`.
- `AccountAddress::new` is replaced by a function called `account_address_from_registration_id`.
- `Amount` now has a field `micro_ccd` instead of `microgtu`.
- The default arithmetic (operator syntax, such as `+`, `-`, `*`) with `Amount` is now unchecked.
- There are no longer implementations of `From<u64> for Amount` and `From<Amount> for u64` as the behavior of these is not obvious.
  Instead, the functions `Amount::from_micro_ccd` or `Amount::from_ccd` and the getter `micro_ccd` should be used instead.
- Implement `Display` and `FromStr` for `ContractAddress` formatted as `<index, subindex>`, E.g `<145,0>`.
- Implement `Display` and `FromStr` for `Address`. The latter attempts to parse a contract address. If this fails it will attempt to parse an `AccountAddress`.
- Implement `FromStr` for `OwnedReceiveName`.
- Remove the `From<Vec<u8>>` implementation for `Parameter`. Instead a `TryFrom` is
  provided that checks the length.
- Add support for the node's GRPC V2 interface.
- Bump minimum supported Rust version to 1.57.
- Add support for CIS0 standard.
- The CIS2 support now uses the V2 node API. This has led so small changes in
  the API.
- Add support for protocol version 5 events and limitations.
- Deprecate `add_baker`, `update_baker_keys`, `remove_baker`,
  `update_baker_stake`, `update_baker_restake_earnings` functions. They only
  apply to protocol versions 1-3 and are replaced by `configure_baker`.

## 1.1.0

Bump minimum supported Rust version to 1.56.

## 1.0.3

- Add V1 variant of root and level 1 key updates.
- Expose helper methods to wait for new blocks or finalization.
- Add some helper methods to `InstanceInfo`, `ElectionDifficulty` and
  `DelegationTarget` types.
- Expose types and functions for interacting with CIS2 smart contracts.

## 1.0.2

- Let AmountFraction derive Display.
- Fix JSON parsing bug.

## 1.0.0

- Replace `send_transaction` with `send_block_item`.
- Support protocol version 4 data formats.
- Support node version 4 API.
