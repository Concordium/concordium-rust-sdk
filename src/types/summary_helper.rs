//! This private module contains an auxiliary definition of `BlockItemSummary`
//! that matches the one in Haskell code of the node. We only use this
//! definition to derive JSON serialization of [super::BlockItemSummary] via
//! the [BlockItemSummary] in this module and the `TryFrom`/`Into` instances.
//!
//! The reason for modelling things in this way is that the [BlockItemSummary]
//! has too much freedom which makes it harder for consumers of the API to use
//! the values. The [super::BlockItemSummary] definition is more precise and
//! thus easier to consume.
use super::{
    hashes, smart_contracts, AccountThreshold, AmountFraction, BakerAddedEvent, BakerId,
    BakerKeysEvent, ContractInitializedEvent, CredentialRegistrationID, CredentialType,
    DelegationTarget, DelegatorId, EncryptedAmountRemovedEvent, EncryptedSelfAmountAddedEvent,
    Energy, InstanceUpdatedEvent, Memo, NewEncryptedAmountEvent, OpenStatus, RegisteredData,
    RejectReason, TransactionIndex, TransactionType, UpdatePayload, UrlText,
};

use crate::types::Address;
use concordium_base::{
    common::{
        types::{Amount, Timestamp, TransactionTime},
        SerdeDeserialize, SerdeSerialize,
    },
    id::types::AccountAddress,
    protocol_level_tokens::{
        TokenEvent, TokenEventDetails, TokenId, TokenModuleEvent, TokenSupplyUpdateEvent,
        TokenTransferEvent,
    },
    updates::{CreatePlt, UpdateType},
};
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Summary of the outcome of a block item.
pub(crate) struct BlockItemSummary {
    #[serde(default)]
    /// Sender, if available. The sender is always available for account
    /// transactions.
    sender:       Option<AccountAddress>,
    /// Hash of the transaction.
    hash:         hashes::TransactionHash,
    /// The amount of CCD the transaction was charged to the sender.
    cost:         Amount,
    /// The amount of NRG the transaction cost.
    energy_cost:  Energy,
    #[serde(rename = "type")]
    /// Which type of block item this is.
    summary_type: BlockItemType,
    /// What is the outcome of this particular block item.
    result:       BlockItemResult,
    /// Index of the transaction in the block where it is included.
    index:        TransactionIndex,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "type", content = "contents", rename_all = "camelCase")]
/// The type of the block item.
enum BlockItemType {
    #[serde(rename = "accountTransaction")]
    /// Account transactions are transactions that are signed by an account.
    /// Most transactions are account transactions.
    Account(#[serde(default)] Option<TransactionType>),
    #[serde(rename = "credentialDeploymentTransaction")]
    /// Credential deployments that create accounts are special kinds of
    /// transactions. They are not signed by the account in the usual way,
    /// and they are not paid for directly by the sender.
    CredentialDeployment(CredentialType),
    #[serde(rename = "updateTransaction")]
    /// Chain updates are signed by the governance keys. They affect the core
    /// parameters of the chain.
    Update(super::UpdateType),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "outcome", rename_all = "camelCase")]
/// Outcome of a block item execution.
enum BlockItemResult {
    /// The intended action was completed. The sender was charged, if
    /// applicable. Some events were generated describing the changes that
    /// happened on the chain.
    Success { events: Vec<Event> },
    #[serde(rename_all = "camelCase")]
    /// The intended action was not completed due to an error. The sender was
    /// charged, but no other effect is seen on the chain.
    Reject { reject_reason: Box<RejectReason> },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "tag")]
/// An event describing the changes that occurred to the state of the chain.
pub(crate) enum Event {
    /// A smart contract module was successfully deployed.
    ModuleDeployed {
        #[serde(rename = "contents")]
        module_ref: smart_contracts::ModuleReference,
    },
    /// A new smart contract instance was created.
    #[serde(rename_all = "camelCase")]
    ContractInitialized {
        #[serde(flatten)]
        data: ContractInitializedEvent,
    },
    /// A smart contract instance was updated.
    Updated {
        #[serde(flatten)]
        data: InstanceUpdatedEvent,
    },
    #[serde(rename_all = "camelCase")]
    /// An amount of CCD was transferred.
    Transferred {
        /// Sender, either smart contract instance or account.
        from:   Address,
        /// Amount that was transferred.
        amount: Amount,
        /// Receiver. This will currently always be an account. Transferring to
        /// a smart contract is always an update.
        to:     Address,
    },
    /// An account with the given address was created.
    AccountCreated { contents: AccountAddress },
    #[serde(rename_all = "camelCase")]
    /// A new credential with the given ID was deployed onto an account.
    /// This is used only when a new account is created. See
    /// [Event::CredentialsUpdated] for when an existing account's
    /// credentials are updated.
    CredentialDeployed {
        reg_id:  CredentialRegistrationID,
        account: AccountAddress,
    },
    /// A new baker was registered, with the given ID and keys.
    BakerAdded {
        #[serde(flatten)]
        data: Box<BakerAddedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker was scheduled to be removed.
    BakerRemoved {
        baker_id: BakerId,
        account:  AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker's stake was increased. This has effect immediately.
    BakerStakeIncreased {
        baker_id:  BakerId,
        account:   AccountAddress,
        new_stake: Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker's stake was scheduled to be decreased. This will have an effect
    /// on the stake after a number of epochs, controlled by the baker
    /// cooldown period.
    BakerStakeDecreased {
        baker_id:  BakerId,
        account:   AccountAddress,
        new_stake: Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// The setting for whether rewards are added to stake immediately or not
    /// was changed to the given value.
    BakerSetRestakeEarnings {
        baker_id:         BakerId,
        account:          AccountAddress,
        /// The new value of the flag.
        restake_earnings: bool,
    },
    /// The baker keys were updated. The new keys are listed.
    BakerKeysUpdated {
        #[serde(flatten)]
        data: Box<BakerKeysEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// Keys of the given credential were updated.
    CredentialKeysUpdated { cred_id: CredentialRegistrationID },
    #[serde(rename_all = "camelCase")]
    /// A new encrypted amount was added to the account.
    NewEncryptedAmount {
        #[serde(flatten)]
        data: Box<NewEncryptedAmountEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// One or more encrypted amounts were removed from an account as part of a
    /// transfer or decryption.
    EncryptedAmountsRemoved {
        #[serde(flatten)]
        data: Box<EncryptedAmountRemovedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// The public balance of the account was increased via a transfer from
    /// encrypted to public balance.
    AmountAddedByDecryption {
        account: AccountAddress,
        amount:  Amount,
    },
    /// The encrypted balance of the account was updated due to transfer from
    /// public to encrypted balance of the account.
    EncryptedSelfAmountAdded {
        #[serde(flatten)]
        data: Box<EncryptedSelfAmountAddedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// An update was enqueued for the given time.
    UpdateEnqueued {
        effective_time: TransactionTime,
        payload:        UpdatePayload,
    },
    #[serde(rename_all = "camelCase")]
    /// A transfer with schedule was enqueued.
    TransferredWithSchedule {
        /// Sender account.
        from:   AccountAddress,
        /// Receiver account.
        to:     AccountAddress,
        /// The list of releases. Ordered by increasing timestamp.
        amount: Vec<(Timestamp, Amount)>,
    },
    #[serde(rename_all = "camelCase")]
    /// The credentials of the account were updated. Either added, removed, or
    /// both.
    CredentialsUpdated {
        /// The affected account.
        account:          AccountAddress,
        /// The credential ids that were added.
        new_cred_ids:     Vec<CredentialRegistrationID>,
        /// The credentials that were removed.
        removed_cred_ids: Vec<CredentialRegistrationID>,
        /// The (possibly) updated account threshold.
        new_threshold:    AccountThreshold,
    },
    #[serde(rename_all = "camelCase")]
    /// Data was registered.
    DataRegistered { data: RegisteredData },
    #[serde(rename_all = "camelCase")]
    /// Memo
    TransferMemo { memo: Memo },
    /// A V1 contract was interrupted.
    #[serde(rename_all = "camelCase")]
    Interrupted {
        /// Address of the contract that was interrupted.
        address: super::ContractAddress,
        /// Events generated up to the interrupt.
        events:  Vec<smart_contracts::ContractEvent>,
    },
    /// A V1 contract resumed execution.
    #[serde(rename_all = "camelCase")]
    Resumed {
        /// Address of the contract that is resuming.
        address: super::ContractAddress,
        /// Whether the interrupt succeeded or not.
        success: bool,
    },
    /// Updated open status for a baker pool
    #[serde(rename_all = "camelCase")]
    BakerSetOpenStatus {
        /// Baker's id
        baker_id:    BakerId,
        /// Baker account
        account:     AccountAddress,
        /// The open status.
        open_status: OpenStatus,
    },
    /// Updated metadata url for baker pool
    #[serde(rename_all = "camelCase")]
    BakerSetMetadataURL {
        /// Baker's id
        baker_id:     BakerId,
        /// Baker account
        account:      AccountAddress,
        /// The URL.
        #[serde(rename = "metadataURL")]
        metadata_url: UrlText,
    },
    /// Updated transaction fee commission for baker pool
    #[serde(rename_all = "camelCase")]
    BakerSetTransactionFeeCommission {
        /// Baker's id
        baker_id:                   BakerId,
        /// Baker account
        account:                    AccountAddress,
        /// The transaction fee commission.
        transaction_fee_commission: AmountFraction,
    },
    /// Updated baking reward commission for baker pool
    #[serde(rename_all = "camelCase")]
    BakerSetBakingRewardCommission {
        /// Baker's id
        baker_id:                 BakerId,
        /// Baker account
        account:                  AccountAddress,
        /// The baking reward commission
        baking_reward_commission: AmountFraction,
    },
    /// Updated finalization reward commission for baker pool
    #[serde(rename_all = "camelCase")]
    BakerSetFinalizationRewardCommission {
        /// Baker's id
        baker_id: BakerId,
        /// Baker account
        account: AccountAddress,
        /// The finalization reward commission
        finalization_reward_commission: AmountFraction,
    },
    #[serde(rename_all = "camelCase")]
    DelegationStakeIncreased {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// Delegator account
        account:      AccountAddress,
        /// New stake
        new_stake:    Amount,
    },
    #[serde(rename_all = "camelCase")]
    DelegationStakeDecreased {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// Delegator account
        account:      AccountAddress,
        /// New stake
        new_stake:    Amount,
    },
    #[serde(rename_all = "camelCase")]
    DelegationSetRestakeEarnings {
        /// Delegator's id
        delegator_id:     DelegatorId,
        /// Delegator account
        account:          AccountAddress,
        /// Whether earnings will be restaked
        restake_earnings: bool,
    },
    #[serde(rename_all = "camelCase")]
    DelegationSetDelegationTarget {
        /// Delegator's id
        delegator_id:      DelegatorId,
        /// Delegator account
        account:           AccountAddress,
        /// New delegation target
        delegation_target: DelegationTarget,
    },
    #[serde(rename_all = "camelCase")]
    DelegationAdded {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// Delegator account
        account:      AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    DelegationRemoved {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// Delegator account
        account:      AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    Upgraded {
        /// Address of the instance that was upgraded.
        address: super::ContractAddress,
        /// The existing module reference that is in effect before the upgrade.
        from:    smart_contracts::ModuleReference,
        /// The new module reference that is in effect after the upgrade.
        to:      smart_contracts::ModuleReference,
    },
    #[serde(rename_all = "camelCase")]
    BakerSuspended {
        /// Baker's id
        baker_id: BakerId,
        /// Baker account
        account:  AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    BakerResumed {
        /// Baker's id
        baker_id: BakerId,
        /// Baker account
        account:  AccountAddress,
    },
    /// An event emitted by a plt (protocol level token) module.
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::enum_variant_names)] // Note: The clippy warning is disabled to keep
    // the name `TokenModuleEvent` which has to align with the corresponding type in the haskell
    // code base in `concordium-base`. This is needed as the JSON representation of the event
    // is tagged with this name in the haskell code base.
    TokenModuleEvent {
        /// The token id of the token.
        token_id: TokenId,
        /// The event includes the `type` and cbor encoded `details` of the
        /// event.
        #[serde(flatten)]
        event:    TokenModuleEvent,
    },
    /// An event emitted when a transfer of plt (protocol level token) is
    /// performed.
    #[serde(rename_all = "camelCase")]
    TokenTransfer {
        /// The token id of the token.
        token_id: TokenId,
        /// The event includes the `from` and `to` addresses and the `amount` of
        /// tokens being transferred. An optional `memo` can be present.
        #[serde(flatten)]
        event:    TokenTransferEvent,
    },
    /// An event emitted when the plt (protocol level token) supply is updated
    /// by minting tokens to a token holder.
    #[serde(rename_all = "camelCase")]
    TokenMint {
        /// The token id of the token.
        token_id: TokenId,
        /// The event includes the `target` address and the `amount` of tokens
        /// minted.
        #[serde(flatten)]
        event:    TokenSupplyUpdateEvent,
    },
    /// An event emitted when the plt (protocol level token) supply is updated
    /// by burning tokens from the balance of a token holder.
    #[serde(rename_all = "camelCase")]
    TokenBurn {
        /// The token id of the token.
        token_id: TokenId,
        /// The event includes the `target` address and the `amount` of tokens
        /// burned.
        #[serde(flatten)]
        event:    TokenSupplyUpdateEvent,
    },
    /// An event emitted when the plt (protocol level token) is created.
    #[serde(rename_all = "camelCase")]
    TokenCreated {
        /// The transaction payload when the token was created.
        /// It includes the `token_id`, `token_module_reference`,
        /// `governance_account`, `decimal` and `initialization_parameters`.
        payload: CreatePlt,
    },
}

impl From<super::ContractTraceElement> for Event {
    fn from(e: super::ContractTraceElement) -> Self {
        match e {
            super::ContractTraceElement::Updated { data } => Event::Updated { data },
            super::ContractTraceElement::Transferred { from, amount, to } => Event::Transferred {
                from: Address::Contract(from),
                amount,
                to: Address::Account(to),
            },
            crate::types::ContractTraceElement::Interrupted { address, events } => {
                Event::Interrupted { address, events }
            }
            crate::types::ContractTraceElement::Resumed { address, success } => {
                Event::Resumed { address, success }
            }
            crate::types::ContractTraceElement::Upgraded { address, from, to } => {
                Event::Upgraded { address, from, to }
            }
        }
    }
}

impl TryFrom<Event> for super::ContractTraceElement {
    type Error = ConversionError;

    fn try_from(value: Event) -> Result<Self, Self::Error> {
        match value {
            Event::Updated { data } => Ok(super::ContractTraceElement::Updated { data }),
            Event::Transferred {
                from: Address::Contract(from),
                amount,
                to: Address::Account(to),
            } => Ok(Self::Transferred { from, amount, to }),
            Event::Interrupted { address, events } => Ok(Self::Interrupted { address, events }),
            Event::Resumed { address, success } => Ok(Self::Resumed { address, success }),
            Event::Upgraded { address, from, to } => Ok(Self::Upgraded { address, from, to }),
            other_event => Err(ConversionError::InvalidTransactionResult(format!(
                "Didn't expect event `{:?}` in contract trace element",
                other_event
            ))),
        }
    }
}

/// Helper function to convert a vector of `TokenEvent` into the a vector of
/// `Event` types.
fn token_events_to_events(events: Vec<TokenEvent>) -> Vec<Event> {
    events
        .into_iter()
        .map(|ev| match ev.event {
            TokenEventDetails::Module(token_module_event) => Event::TokenModuleEvent {
                token_id: ev.token_id,
                event:    token_module_event,
            },
            TokenEventDetails::Transfer(token_transfer_event) => Event::TokenTransfer {
                token_id: ev.token_id,
                event:    token_transfer_event,
            },
            TokenEventDetails::Mint(token_supply_update_event) => Event::TokenMint {
                token_id: ev.token_id,
                event:    token_supply_update_event,
            },
            TokenEventDetails::Burn(token_supply_update_event) => Event::TokenBurn {
                token_id: ev.token_id,
                event:    token_supply_update_event,
            },
        })
        .collect()
}

impl From<super::BlockItemSummary> for BlockItemSummary {
    fn from(bi: super::BlockItemSummary) -> Self {
        match bi.details {
            super::BlockItemSummaryDetails::AccountTransaction(
                super::AccountTransactionDetails {
                    cost,
                    sender,
                    effects,
                },
            ) => {
                let mk_success_1 =
                    |ty, ev| (Some(ty), BlockItemResult::Success { events: vec![ev] });
                let mk_success_2 = |ty, ev1, ev2| {
                    (Some(ty), BlockItemResult::Success {
                        events: vec![ev1, ev2],
                    })
                };
                let mk_success_3 = |ty, ev1, ev2, ev3| {
                    (Some(ty), BlockItemResult::Success {
                        events: vec![ev1, ev2, ev3],
                    })
                };
                let (transaction_type, result) = match effects {
                    super::AccountTransactionEffects::None {
                        transaction_type,
                        reject_reason,
                    } => (transaction_type, BlockItemResult::Reject {
                        reject_reason: Box::new(reject_reason),
                    }),
                    super::AccountTransactionEffects::ModuleDeployed { module_ref } => {
                        mk_success_1(TransactionType::DeployModule, Event::ModuleDeployed {
                            module_ref,
                        })
                    }
                    super::AccountTransactionEffects::ContractInitialized { data } => {
                        mk_success_1(TransactionType::InitContract, Event::ContractInitialized {
                            data,
                        })
                    }
                    super::AccountTransactionEffects::ContractUpdateIssued { effects } => {
                        let events = effects.into_iter().map(Event::from).collect::<Vec<_>>();
                        (Some(TransactionType::Update), BlockItemResult::Success {
                            events,
                        })
                    }
                    super::AccountTransactionEffects::AccountTransfer { amount, to } => {
                        mk_success_1(TransactionType::Transfer, Event::Transferred {
                            from: Address::Account(sender),
                            amount,
                            to: Address::Account(to),
                        })
                    }
                    super::AccountTransactionEffects::AccountTransferWithMemo {
                        amount,
                        to,
                        memo,
                    } => mk_success_2(
                        TransactionType::TransferWithMemo,
                        Event::Transferred {
                            from: Address::Account(sender),
                            amount,
                            to: Address::Account(to),
                        },
                        Event::TransferMemo { memo },
                    ),
                    super::AccountTransactionEffects::BakerAdded { data } =>
                    {
                        #[allow(deprecated)]
                        mk_success_1(TransactionType::AddBaker, Event::BakerAdded { data })
                    }
                    super::AccountTransactionEffects::BakerRemoved { baker_id } =>
                    {
                        #[allow(deprecated)]
                        mk_success_1(TransactionType::RemoveBaker, Event::BakerRemoved {
                            baker_id,
                            account: sender,
                        })
                    }
                    super::AccountTransactionEffects::BakerStakeUpdated { data } => {
                        if let Some(data) = data {
                            mk_success_1(
                                #[allow(deprecated)]
                                TransactionType::UpdateBakerStake,
                                if data.increased {
                                    Event::BakerStakeIncreased {
                                        baker_id:  data.baker_id,
                                        account:   sender,
                                        new_stake: data.new_stake,
                                    }
                                } else {
                                    Event::BakerStakeDecreased {
                                        baker_id:  data.baker_id,
                                        account:   sender,
                                        new_stake: data.new_stake,
                                    }
                                },
                            )
                        } else {
                            (
                                #[allow(deprecated)]
                                Some(TransactionType::UpdateBakerStake),
                                BlockItemResult::Success { events: Vec::new() },
                            )
                        }
                    }
                    super::AccountTransactionEffects::BakerRestakeEarningsUpdated {
                        baker_id,
                        restake_earnings,
                    } => mk_success_1(
                        #[allow(deprecated)]
                        TransactionType::UpdateBakerRestakeEarnings,
                        Event::BakerSetRestakeEarnings {
                            baker_id,
                            account: sender,
                            restake_earnings,
                        },
                    ),
                    super::AccountTransactionEffects::BakerKeysUpdated { data } =>
                    {
                        #[allow(deprecated)]
                        mk_success_1(TransactionType::UpdateBakerKeys, Event::BakerKeysUpdated {
                            data,
                        })
                    }
                    super::AccountTransactionEffects::EncryptedAmountTransferred {
                        removed,
                        added,
                    } => mk_success_2(
                        #[allow(deprecated)]
                        TransactionType::EncryptedAmountTransfer,
                        Event::EncryptedAmountsRemoved { data: removed },
                        Event::NewEncryptedAmount { data: added },
                    ),
                    super::AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                        removed,
                        added,
                        memo,
                    } => mk_success_3(
                        #[allow(deprecated)]
                        TransactionType::EncryptedAmountTransferWithMemo,
                        Event::EncryptedAmountsRemoved { data: removed },
                        Event::NewEncryptedAmount { data: added },
                        Event::TransferMemo { memo },
                    ),
                    super::AccountTransactionEffects::TransferredToEncrypted { data } =>
                    {
                        #[allow(deprecated)]
                        mk_success_1(
                            TransactionType::TransferToEncrypted,
                            Event::EncryptedSelfAmountAdded { data },
                        )
                    }
                    super::AccountTransactionEffects::TransferredToPublic { removed, amount } => {
                        mk_success_2(
                            TransactionType::TransferToPublic,
                            Event::EncryptedAmountsRemoved { data: removed },
                            Event::AmountAddedByDecryption {
                                account: sender,
                                amount,
                            },
                        )
                    }
                    super::AccountTransactionEffects::TransferredWithSchedule { to, amount } => {
                        mk_success_1(
                            TransactionType::TransferWithSchedule,
                            Event::TransferredWithSchedule {
                                from: sender,
                                to,
                                amount,
                            },
                        )
                    }
                    super::AccountTransactionEffects::TransferredWithScheduleAndMemo {
                        to,
                        amount,
                        memo,
                    } => mk_success_2(
                        TransactionType::TransferWithScheduleAndMemo,
                        Event::TransferredWithSchedule {
                            from: sender,
                            to,
                            amount,
                        },
                        Event::TransferMemo { memo },
                    ),
                    super::AccountTransactionEffects::CredentialKeysUpdated { cred_id } => {
                        mk_success_1(
                            TransactionType::UpdateCredentialKeys,
                            Event::CredentialKeysUpdated { cred_id },
                        )
                    }
                    super::AccountTransactionEffects::CredentialsUpdated {
                        new_cred_ids,
                        removed_cred_ids,
                        new_threshold,
                    } => mk_success_1(
                        TransactionType::UpdateCredentials,
                        Event::CredentialsUpdated {
                            account: sender,
                            new_cred_ids,
                            removed_cred_ids,
                            new_threshold,
                        },
                    ),
                    super::AccountTransactionEffects::DataRegistered { data } => {
                        mk_success_1(TransactionType::RegisterData, Event::DataRegistered {
                            data,
                        })
                    }
                    super::AccountTransactionEffects::BakerConfigured { data } => {
                        let ty = TransactionType::ConfigureBaker;
                        let events = data
                            .into_iter()
                            .map(|ev| match ev {
                                super::BakerEvent::BakerAdded { data } => {
                                    Event::BakerAdded { data }
                                }
                                super::BakerEvent::BakerRemoved { baker_id } => {
                                    Event::BakerRemoved {
                                        baker_id,
                                        account: sender,
                                    }
                                }
                                super::BakerEvent::BakerStakeIncreased {
                                    baker_id,
                                    new_stake,
                                } => Event::BakerStakeIncreased {
                                    baker_id,
                                    account: sender,
                                    new_stake,
                                },
                                super::BakerEvent::BakerStakeDecreased {
                                    baker_id,
                                    new_stake,
                                } => Event::BakerStakeDecreased {
                                    baker_id,
                                    account: sender,
                                    new_stake,
                                },
                                super::BakerEvent::BakerSetOpenStatus {
                                    baker_id,
                                    open_status,
                                } => Event::BakerSetOpenStatus {
                                    baker_id,
                                    account: sender,
                                    open_status,
                                },
                                super::BakerEvent::BakerSetMetadataURL {
                                    baker_id,
                                    metadata_url,
                                } => Event::BakerSetMetadataURL {
                                    baker_id,
                                    account: sender,
                                    metadata_url,
                                },
                                super::BakerEvent::BakerSetTransactionFeeCommission {
                                    baker_id,
                                    transaction_fee_commission,
                                } => Event::BakerSetTransactionFeeCommission {
                                    baker_id,
                                    account: sender,
                                    transaction_fee_commission,
                                },
                                super::BakerEvent::BakerSetBakingRewardCommission {
                                    baker_id,
                                    baking_reward_commission,
                                } => Event::BakerSetBakingRewardCommission {
                                    baker_id,
                                    account: sender,
                                    baking_reward_commission,
                                },
                                super::BakerEvent::BakerSetFinalizationRewardCommission {
                                    baker_id,
                                    finalization_reward_commission,
                                } => Event::BakerSetFinalizationRewardCommission {
                                    baker_id,
                                    account: sender,
                                    finalization_reward_commission,
                                },
                                super::BakerEvent::BakerRestakeEarningsUpdated {
                                    baker_id,
                                    restake_earnings,
                                } => Event::BakerSetRestakeEarnings {
                                    baker_id,
                                    account: sender,
                                    restake_earnings,
                                },
                                super::BakerEvent::BakerKeysUpdated { data } => {
                                    Event::BakerKeysUpdated { data }
                                }
                                super::BakerEvent::DelegationRemoved { delegator_id } => {
                                    Event::DelegationRemoved {
                                        delegator_id,
                                        account: sender,
                                    }
                                }
                                super::BakerEvent::BakerSuspended { baker_id } => {
                                    Event::BakerSuspended {
                                        baker_id,
                                        account: sender,
                                    }
                                }
                                super::BakerEvent::BakerResumed { baker_id } => {
                                    Event::BakerResumed {
                                        baker_id,
                                        account: sender,
                                    }
                                }
                            })
                            .collect();
                        (Some(ty), BlockItemResult::Success { events })
                    }
                    super::AccountTransactionEffects::DelegationConfigured { data } => {
                        let ty = TransactionType::ConfigureDelegation;
                        let events = data
                            .into_iter()
                            .map(|ev| match ev {
                                super::DelegationEvent::DelegationStakeIncreased {
                                    delegator_id,
                                    new_stake,
                                } => Event::DelegationStakeIncreased {
                                    delegator_id,
                                    account: sender,
                                    new_stake,
                                },
                                super::DelegationEvent::DelegationStakeDecreased {
                                    delegator_id,
                                    new_stake,
                                } => Event::DelegationStakeDecreased {
                                    delegator_id,
                                    account: sender,
                                    new_stake,
                                },
                                super::DelegationEvent::DelegationSetRestakeEarnings {
                                    delegator_id,
                                    restake_earnings,
                                } => Event::DelegationSetRestakeEarnings {
                                    delegator_id,
                                    account: sender,
                                    restake_earnings,
                                },
                                super::DelegationEvent::DelegationSetDelegationTarget {
                                    delegator_id,
                                    delegation_target,
                                } => Event::DelegationSetDelegationTarget {
                                    delegator_id,
                                    account: sender,
                                    delegation_target,
                                },
                                super::DelegationEvent::DelegationAdded { delegator_id } => {
                                    Event::DelegationAdded {
                                        delegator_id,
                                        account: sender,
                                    }
                                }
                                super::DelegationEvent::DelegationRemoved { delegator_id } => {
                                    Event::DelegationRemoved {
                                        delegator_id,
                                        account: sender,
                                    }
                                }
                                super::DelegationEvent::BakerRemoved { baker_id } => {
                                    Event::BakerRemoved {
                                        baker_id,
                                        account: sender,
                                    }
                                }
                            })
                            .collect();
                        (Some(ty), BlockItemResult::Success { events })
                    }
                    super::AccountTransactionEffects::TokenHolder { events } => {
                        let ty = TransactionType::TokenHolder;
                        let events = token_events_to_events(events);
                        (Some(ty), BlockItemResult::Success { events })
                    }
                    super::AccountTransactionEffects::TokenGovernance { events } => {
                        let ty = TransactionType::TokenGovernance;
                        let events = token_events_to_events(events);
                        (Some(ty), BlockItemResult::Success { events })
                    }
                };
                BlockItemSummary {
                    sender: Some(sender),
                    hash: bi.hash,
                    cost,
                    energy_cost: bi.energy_cost,
                    summary_type: BlockItemType::Account(transaction_type),
                    result,
                    index: bi.index,
                }
            }
            super::BlockItemSummaryDetails::AccountCreation(super::AccountCreationDetails {
                credential_type,
                address,
                reg_id,
            }) => BlockItemSummary {
                sender:       None,
                hash:         bi.hash,
                cost:         Amount::zero(),
                energy_cost:  bi.energy_cost,
                summary_type: BlockItemType::CredentialDeployment(credential_type),
                result:       BlockItemResult::Success {
                    events: vec![
                        Event::AccountCreated { contents: address },
                        Event::CredentialDeployed {
                            reg_id,
                            account: address,
                        },
                    ],
                },
                index:        bi.index,
            },
            super::BlockItemSummaryDetails::Update(super::UpdateDetails {
                effective_time,
                payload,
            }) => BlockItemSummary {
                sender:       None,
                hash:         bi.hash,
                cost:         Amount::zero(),
                energy_cost:  bi.energy_cost,
                summary_type: BlockItemType::Update(payload.update_type()),
                result:       BlockItemResult::Success {
                    events: vec![Event::UpdateEnqueued {
                        effective_time,
                        payload,
                    }],
                },
                index:        bi.index,
            },
            super::BlockItemSummaryDetails::TokenCreationDetails(token_creation_details) => {
                let mut events = vec![Event::TokenCreated {
                    payload: token_creation_details.create_plt,
                }];
                let additional_events = token_events_to_events(token_creation_details.events);
                events.extend(additional_events);

                BlockItemSummary {
                    sender:       None,
                    hash:         bi.hash,
                    cost:         Amount::zero(),
                    energy_cost:  bi.energy_cost,
                    summary_type: BlockItemType::Update(UpdateType::UpdateCreatePLT),
                    result:       BlockItemResult::Success { events },
                    index:        bi.index,
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Account creation failed.")]
    FailedAccountCreation,
    #[error("Unexpected response for an account creation transaction.")]
    InvalidAccountCreation,
    #[error("Failed update instruction.")]
    FailedUpdate,
    #[error("Unexpected response for an update instruction.")]
    InvalidUpdateResult,
    #[error("Unexpected response for an account transaction. Details: {0}")]
    InvalidTransactionResult(String),
}

#[inline(always)]
fn with_singleton(
    events: Vec<Event>,
    f: impl Fn(Event) -> Option<super::AccountTransactionEffects>,
) -> Result<super::AccountTransactionEffects, ConversionError> {
    let events_arr: [_; 1] = events.try_into().map_err(|_| {
        ConversionError::InvalidTransactionResult("Expect 1 event in singleton".to_string())
    })?;
    let [e] = events_arr;
    f(e).ok_or(ConversionError::InvalidTransactionResult(
        "Couldn't convert `Event` to `Option<AccountTransactionEffects>`".to_string(),
    ))
}

fn convert_account_transaction(
    ty: Option<TransactionType>,
    cost: Amount,
    sender: AccountAddress,
    value: BlockItemResult,
) -> Result<super::AccountTransactionDetails, ConversionError> {
    let mk_none = |reject_reason| {
        Ok(super::AccountTransactionDetails {
            cost,
            sender,
            effects: super::AccountTransactionEffects::None {
                transaction_type: ty,
                reject_reason,
            },
        })
    };

    let mk_success = |effects| {
        Ok(super::AccountTransactionDetails {
            cost,
            sender,
            effects,
        })
    };

    let ty = match ty {
        Some(ty) => ty,
        None => return mk_none(RejectReason::SerializationFailure),
    };
    let events = match value {
        BlockItemResult::Success { events } => events,
        BlockItemResult::Reject { reject_reason } => return mk_none(*reject_reason),
    };
    match ty {
        TransactionType::DeployModule => {
            let effects = with_singleton(events, |e| match e {
                Event::ModuleDeployed { module_ref } => {
                    Some(super::AccountTransactionEffects::ModuleDeployed { module_ref })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::InitContract => {
            let effects = with_singleton(events, |e| match e {
                Event::ContractInitialized { data } => {
                    Some(super::AccountTransactionEffects::ContractInitialized { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::Update => {
            let effects = events
                .into_iter()
                .map(super::ContractTraceElement::try_from)
                .collect::<Result<_, _>>()?;
            mk_success(super::AccountTransactionEffects::ContractUpdateIssued { effects })
        }
        TransactionType::Transfer => {
            let effects = with_singleton(events, |e| match e {
                Event::Transferred {
                    from: _,
                    amount,
                    to: Address::Account(to),
                } => Some(super::AccountTransactionEffects::AccountTransfer { amount, to }),
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::TransferWithMemo => {
            let events_arr: [_; 2] = events.try_into().map_err(|_| {
                ConversionError::InvalidTransactionResult(
                    "Expect 2 events in transaction type `TransferWithMemo`".to_string(),
                )
            })?;
            match events_arr {
                [Event::Transferred {
                    from: _,
                    amount,
                    to: Address::Account(to),
                }, Event::TransferMemo { memo }] => {
                    mk_success(super::AccountTransactionEffects::AccountTransferWithMemo {
                        amount,
                        to,
                        memo,
                    })
                }
                other_event => Err(ConversionError::InvalidTransactionResult(format!(
                    "Didn't expect event `{:?}` in transaction type `TransferWithMemo`",
                    other_event
                ))),
            }
        }
        #[allow(deprecated)]
        TransactionType::AddBaker => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerAdded { data } => {
                    Some(super::AccountTransactionEffects::BakerAdded { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        #[allow(deprecated)]
        TransactionType::RemoveBaker => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerRemoved {
                    baker_id,
                    account: _,
                } => Some(super::AccountTransactionEffects::BakerRemoved { baker_id }),
                _ => None,
            })?;
            mk_success(effects)
        }
        #[allow(deprecated)]
        TransactionType::UpdateBakerStake => {
            let effects = if events.is_empty() {
                super::AccountTransactionEffects::BakerStakeUpdated { data: None }
            } else {
                with_singleton(events, |e| match e {
                    Event::BakerStakeDecreased {
                        baker_id,
                        account: _,
                        new_stake,
                    } => Some(super::AccountTransactionEffects::BakerStakeUpdated {
                        data: Some(super::BakerStakeUpdatedData {
                            baker_id,
                            new_stake,
                            increased: false,
                        }),
                    }),
                    Event::BakerStakeIncreased {
                        baker_id,
                        account: _,
                        new_stake,
                    } => Some(super::AccountTransactionEffects::BakerStakeUpdated {
                        data: Some(super::BakerStakeUpdatedData {
                            baker_id,
                            new_stake,
                            increased: true,
                        }),
                    }),
                    _ => None,
                })?
            };
            mk_success(effects)
        }
        #[allow(deprecated)]
        TransactionType::UpdateBakerRestakeEarnings => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerSetRestakeEarnings {
                    baker_id,
                    account: _,
                    restake_earnings,
                } => Some(
                    super::AccountTransactionEffects::BakerRestakeEarningsUpdated {
                        baker_id,
                        restake_earnings,
                    },
                ),
                _ => None,
            })?;
            mk_success(effects)
        }
        #[allow(deprecated)]
        TransactionType::UpdateBakerKeys => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerKeysUpdated { data } => {
                    Some(super::AccountTransactionEffects::BakerKeysUpdated { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::UpdateCredentialKeys => {
            let effects = with_singleton(events, |e| match e {
                Event::CredentialKeysUpdated { cred_id } => {
                    Some(super::AccountTransactionEffects::CredentialKeysUpdated { cred_id })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        #[allow(deprecated)]
        TransactionType::EncryptedAmountTransfer => {
            let events_arr: [_; 2] = events.try_into().map_err(|_| {
                ConversionError::InvalidTransactionResult(
                    "Expect 2 events in transaction type `EncryptedAmountTransfer`".to_string(),
                )
            })?;
            match events_arr {
                [Event::EncryptedAmountsRemoved { data: removed }, Event::NewEncryptedAmount { data: added }] => {
                    mk_success(
                        super::AccountTransactionEffects::EncryptedAmountTransferred {
                            removed,
                            added,
                        },
                    )
                }
                other_events => Err(ConversionError::InvalidTransactionResult(format!(
                    "Didn't expect events `{:?}` in transaction type `EncryptedAmountTransfer`",
                    other_events
                ))),
            }
        }
        #[allow(deprecated)]
        TransactionType::EncryptedAmountTransferWithMemo => {
            let events_arr: [_; 3] = events.try_into().map_err(|_| {
                ConversionError::InvalidTransactionResult(
                    "Expect 3 events in transaction type `EncryptedAmountTransferWithMemo`"
                        .to_string(),
                )
            })?;
            match events_arr {
                [Event::EncryptedAmountsRemoved { data: removed }, Event::NewEncryptedAmount { data: added }, Event::TransferMemo { memo }] => {
                    mk_success(
                        super::AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                            removed,
                            added,
                            memo,
                        },
                    )
                }
                other_events => Err(ConversionError::InvalidTransactionResult(format!(
                    "Didn't expect events `{:?}` in transaction type \
                     `EncryptedAmountTransferWithMemo`",
                    other_events
                ))),
            }
        }
        #[allow(deprecated)]
        TransactionType::TransferToEncrypted => {
            let effects = with_singleton(events, |e| match e {
                Event::EncryptedSelfAmountAdded { data } => {
                    Some(super::AccountTransactionEffects::TransferredToEncrypted { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::TransferToPublic => {
            let events_arr: [_; 2] = events.try_into().map_err(|_| {
                ConversionError::InvalidTransactionResult(
                    "Expect 2 events in transaction type `TransferToPublic`".to_string(),
                )
            })?;
            match events_arr {
                [Event::EncryptedAmountsRemoved { data: removed }, Event::AmountAddedByDecryption { account: _, amount }] => {
                    mk_success(super::AccountTransactionEffects::TransferredToPublic {
                        removed,
                        amount,
                    })
                }
                other_events => Err(ConversionError::InvalidTransactionResult(format!(
                    "Didn't expect events `{:?}` in transaction type `TransferToPublic`",
                    other_events
                ))),
            }
        }
        TransactionType::TransferWithSchedule => {
            let effects = with_singleton(events, |e| match e {
                Event::TransferredWithSchedule { to, amount, .. } => {
                    Some(super::AccountTransactionEffects::TransferredWithSchedule { to, amount })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::TransferWithScheduleAndMemo => {
            let events_arr: [_; 2] = events.try_into().map_err(|_| {
                ConversionError::InvalidTransactionResult(
                    "Expect 2 events in transaction type `TransferWithScheduleAndMemo`".to_string(),
                )
            })?;
            match events_arr {
                [Event::TransferredWithSchedule { to, amount, .. }, Event::TransferMemo { memo }] => {
                    mk_success(
                        super::AccountTransactionEffects::TransferredWithScheduleAndMemo {
                            to,
                            amount,
                            memo,
                        },
                    )
                }
                other_events => Err(ConversionError::InvalidTransactionResult(format!(
                    "Didn't expect events `{:?}` in transaction type `TransferWithScheduleAndMemo`",
                    other_events
                ))),
            }
        }
        TransactionType::UpdateCredentials => {
            let effects = with_singleton(events, |e| match e {
                Event::CredentialsUpdated {
                    new_cred_ids,
                    removed_cred_ids,
                    new_threshold,
                    ..
                } => Some(super::AccountTransactionEffects::CredentialsUpdated {
                    new_cred_ids,
                    removed_cred_ids,
                    new_threshold,
                }),
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::RegisterData => {
            let effects = with_singleton(events, |e| match e {
                Event::DataRegistered { data } => {
                    Some(super::AccountTransactionEffects::DataRegistered { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
        TransactionType::ConfigureBaker => {
            let data = events
                .into_iter()
                .map(|ev| match ev {
                    Event::BakerAdded { data } => Ok(super::BakerEvent::BakerAdded { data }),
                    Event::BakerRemoved { baker_id, .. } => {
                        Ok(super::BakerEvent::BakerRemoved { baker_id })
                    }
                    Event::BakerSetOpenStatus {
                        baker_id,
                        account: _,
                        open_status,
                    } => Ok(super::BakerEvent::BakerSetOpenStatus {
                        baker_id,
                        open_status,
                    }),
                    Event::BakerStakeIncreased {
                        baker_id,
                        new_stake,
                        ..
                    } => Ok(super::BakerEvent::BakerStakeIncreased {
                        baker_id,
                        new_stake,
                    }),
                    Event::BakerStakeDecreased {
                        baker_id,
                        new_stake,
                        ..
                    } => Ok(super::BakerEvent::BakerStakeDecreased {
                        baker_id,
                        new_stake,
                    }),
                    Event::BakerSetRestakeEarnings {
                        baker_id,
                        restake_earnings,
                        ..
                    } => Ok(super::BakerEvent::BakerRestakeEarningsUpdated {
                        baker_id,
                        restake_earnings,
                    }),
                    Event::BakerKeysUpdated { data } => {
                        Ok(super::BakerEvent::BakerKeysUpdated { data })
                    }
                    Event::BakerSetMetadataURL {
                        baker_id,
                        account: _,
                        metadata_url,
                    } => Ok(super::BakerEvent::BakerSetMetadataURL {
                        baker_id,
                        metadata_url,
                    }),
                    Event::BakerSetTransactionFeeCommission {
                        baker_id,
                        account: _,
                        transaction_fee_commission,
                    } => Ok(super::BakerEvent::BakerSetTransactionFeeCommission {
                        baker_id,
                        transaction_fee_commission,
                    }),
                    Event::BakerSetBakingRewardCommission {
                        baker_id,
                        account: _,
                        baking_reward_commission,
                    } => Ok(super::BakerEvent::BakerSetBakingRewardCommission {
                        baker_id,
                        baking_reward_commission,
                    }),
                    Event::BakerSetFinalizationRewardCommission {
                        baker_id,
                        account: _,
                        finalization_reward_commission,
                    } => Ok(super::BakerEvent::BakerSetFinalizationRewardCommission {
                        baker_id,
                        finalization_reward_commission,
                    }),
                    Event::DelegationRemoved {
                        delegator_id,
                        account: _,
                    } => Ok(super::BakerEvent::DelegationRemoved { delegator_id }),
                    other_event => Err(ConversionError::InvalidTransactionResult(format!(
                        "Didn't expect event `{:?}` in transaction type `ConfigureBaker`",
                        other_event
                    ))),
                })
                .collect::<Result<_, ConversionError>>()?;
            mk_success(super::AccountTransactionEffects::BakerConfigured { data })
        }
        TransactionType::ConfigureDelegation => {
            let data = events
                .into_iter()
                .map(|ev| match ev {
                    Event::DelegationStakeIncreased {
                        delegator_id,
                        account: _,
                        new_stake,
                    } => Ok(super::DelegationEvent::DelegationStakeIncreased {
                        delegator_id,
                        new_stake,
                    }),
                    Event::DelegationStakeDecreased {
                        delegator_id,
                        account: _,
                        new_stake,
                    } => Ok(super::DelegationEvent::DelegationStakeDecreased {
                        delegator_id,
                        new_stake,
                    }),
                    Event::DelegationSetRestakeEarnings {
                        delegator_id,
                        account: _,
                        restake_earnings,
                    } => Ok(super::DelegationEvent::DelegationSetRestakeEarnings {
                        delegator_id,
                        restake_earnings,
                    }),
                    Event::DelegationSetDelegationTarget {
                        delegator_id,
                        account: _,
                        delegation_target,
                    } => Ok(super::DelegationEvent::DelegationSetDelegationTarget {
                        delegator_id,
                        delegation_target,
                    }),
                    Event::DelegationAdded {
                        delegator_id,
                        account: _,
                    } => Ok(super::DelegationEvent::DelegationAdded { delegator_id }),
                    Event::DelegationRemoved {
                        delegator_id,
                        account: _,
                    } => Ok(super::DelegationEvent::DelegationRemoved { delegator_id }),
                    Event::BakerRemoved {
                        baker_id,
                        account: _,
                    } => Ok(super::DelegationEvent::BakerRemoved { baker_id }),
                    other_event => Err(ConversionError::InvalidTransactionResult(format!(
                        "Didn't expect event `{:?}` in transaction type `ConfigureDelegation`",
                        other_event
                    ))),
                })
                .collect::<Result<_, ConversionError>>()?;
            mk_success(super::AccountTransactionEffects::DelegationConfigured { data })
        }
        TransactionType::TokenHolder => {
            let events = events
                .into_iter()
                .map(|ev| match ev {
                    Event::TokenModuleEvent { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Module(event),
                    }),
                    Event::TokenTransfer { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Transfer(event),
                    }),
                    Event::TokenMint { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Mint(event),
                    }),
                    Event::TokenBurn { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Burn(event),
                    }),
                    other_event => Err(ConversionError::InvalidTransactionResult(format!(
                        "Didn't expect event `{:?}` in transaction type `TokenHolder`",
                        other_event
                    ))),
                })
                .collect::<Result<_, ConversionError>>()?;
            mk_success(super::AccountTransactionEffects::TokenHolder { events })
        }
        TransactionType::TokenGovernance => {
            let events = events
                .into_iter()
                .map(|ev| match ev {
                    Event::TokenModuleEvent { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Module(event),
                    }),
                    Event::TokenTransfer { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Transfer(event),
                    }),
                    Event::TokenMint { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Mint(event),
                    }),
                    Event::TokenBurn { token_id, event } => Ok(TokenEvent {
                        token_id,
                        event: TokenEventDetails::Burn(event),
                    }),
                    other_event => Err(ConversionError::InvalidTransactionResult(format!(
                        "Didn't expect event `{:?}` in transaction type `TokenGovernance`",
                        other_event
                    ))),
                })
                .collect::<Result<_, ConversionError>>()?;
            mk_success(super::AccountTransactionEffects::TokenGovernance { events })
        }
    }
}

impl TryFrom<BlockItemSummary> for super::BlockItemSummary {
    type Error = ConversionError;

    fn try_from(value: BlockItemSummary) -> Result<Self, Self::Error> {
        match value.summary_type {
            BlockItemType::Account(ty) => {
                let index = value.index;
                let energy_cost = value.energy_cost;
                let hash = value.hash;
                let sender = value
                    .sender
                    .ok_or(ConversionError::InvalidTransactionResult(
                        "Expect `BlockItemType::Account` to have a sender".to_string(),
                    ))?;
                let details = convert_account_transaction(ty, value.cost, sender, value.result)?;
                Ok(super::BlockItemSummary {
                    index,
                    energy_cost,
                    hash,
                    details: super::BlockItemSummaryDetails::AccountTransaction(details),
                })
            }
            BlockItemType::CredentialDeployment(credential_type) => {
                use Event::*;
                let (address, reg_id) = match value.result {
                    BlockItemResult::Success { events } => {
                        let arr: [Event; 2] = events
                            .try_into()
                            .map_err(|_| ConversionError::InvalidAccountCreation)?;
                        match arr {
                            [AccountCreated { contents }, CredentialDeployed { reg_id, account }]
                                if contents == account =>
                            {
                                (contents, reg_id)
                            }
                            _ => return Err(ConversionError::InvalidAccountCreation),
                        }
                    }
                    BlockItemResult::Reject { .. } => {
                        return Err(ConversionError::FailedAccountCreation)
                    }
                };
                let acd = super::AccountCreationDetails {
                    credential_type,
                    address,
                    reg_id,
                };
                let details = super::BlockItemSummaryDetails::AccountCreation(acd);
                Ok(super::BlockItemSummary {
                    index: value.index,
                    energy_cost: value.energy_cost,
                    hash: value.hash,
                    details,
                })
            }
            BlockItemType::Update(_) => {
                let ud = match value.result {
                    BlockItemResult::Success { events } => {
                        let Some(first_event) = events.first() else {
                            return Err(ConversionError::InvalidUpdateResult);
                        };

                        match first_event {
                            Event::UpdateEnqueued {
                                effective_time,
                                payload,
                            } => {
                                if events.len() != 1 {
                                    return Err(ConversionError::InvalidUpdateResult);
                                }

                                Ok(super::UpdateDetails {
                                    effective_time: *effective_time,
                                    payload:        payload.clone(),
                                })
                            }
                            Event::TokenCreated { payload } => Ok(super::UpdateDetails {
                                // `Effective_time is always 0 for plt token creation transactions.
                                // Plt token creation transaction are not queued and instead take
                                // effect immediately.
                                effective_time: TransactionTime { seconds: 0 },
                                payload:        UpdatePayload::CreatePlt(payload.clone()),
                            }),
                            _ => Err(ConversionError::InvalidUpdateResult),
                        }
                    }
                    BlockItemResult::Reject { .. } => return Err(ConversionError::FailedUpdate),
                }?;
                let details = super::BlockItemSummaryDetails::Update(ud);
                Ok(super::BlockItemSummary {
                    index: value.index,
                    energy_cost: value.energy_cost,
                    hash: value.hash,
                    details,
                })
            }
        }
    }
}
