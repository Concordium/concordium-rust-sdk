//! This private module contains an auxiliary definition of `BlockItemSummary`
//! that matches the one in Haskell code of the node. We only use this
//! definition to derive JSON serialization of [super::BlockItemSummary] via
//! the [BlockItemSummary] in this module and the `TryFrom`/`Into` instances.
//!
//! The reason for modelling things in this way is that the [BlockItemSummary]
//! has too much freedom which makes it harder for consumers of the API to use
//! the values. The [super::BlockItemSummary] definition is more precise and
//! thus easier to consume.
use crypto_common::{SerdeDeserialize, SerdeSerialize};

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
    Update(UpdateType),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Enumeration of the types of updates that are possible.
pub enum UpdateType {
    /// Update the chain protocol
    UpdateProtocol,
    /// Update the election difficulty
    UpdateElectionDifficulty,
    /// Update the euro per energy exchange rate
    UpdateEuroPerEnergy,
    /// Update the microCCD per euro exchange rate
    UpdateMicroGTUPerEuro,
    /// Update the address of the foundation account
    UpdateFoundationAccount,
    /// Update the distribution of newly minted CCD
    UpdateMintDistribution,
    /// Update the distribution of transaction fees
    UpdateTransactionFeeDistribution,
    /// Update the GAS rewards
    UpdateGASRewards,
    /// Minimum amount to register as a baker
    UpdateBakerStakeThreshold,
    /// Add new anonymity revoker
    UpdateAddAnonymityRevoker,
    /// Add new identity provider
    UpdateAddIdentityProvider,
    /// Update the root keys
    UpdateRootKeys,
    /// Update the level 1 keys
    UpdateLevel1Keys,
    /// Update the level 2 keys
    UpdateLevel2Keys,
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
enum Event {
    /// A smart contract module was successfully deployed.
    ModuleDeployed {
        #[serde(rename = "contents")]
        module_ref: smart_contracts::ModuleRef,
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
}

use super::{
    hashes, smart_contracts, AccountThreshold, BakerAddedEvent, BakerId, BakerKeysEvent,
    ContractInitializedEvent, CredentialRegistrationID, CredentialType,
    EncryptedAmountRemovedEvent, EncryptedSelfAmountAddedEvent, Energy, InstanceUpdatedEvent, Memo,
    NewEncryptedAmountEvent, RegisteredData, RejectReason, TransactionIndex, TransactionType,
    UpdatePayload,
};
use crate::types::Address;
use crypto_common::types::{Amount, Timestamp, TransactionTime};
use id::types::AccountAddress;
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

impl super::UpdatePayload {
    fn update_type(&self) -> UpdateType {
        use UpdateType::*;
        match self {
            UpdatePayload::Protocol(_) => UpdateProtocol,
            UpdatePayload::ElectionDifficulty(_) => UpdateElectionDifficulty,
            UpdatePayload::EuroPerEnergy(_) => UpdateEuroPerEnergy,
            UpdatePayload::MicroGTUPerEuro(_) => UpdateMicroGTUPerEuro,
            UpdatePayload::FoundationAccount(_) => UpdateFoundationAccount,
            UpdatePayload::MintDistribution(_) => UpdateMintDistribution,
            UpdatePayload::TransactionFeeDistribution(_) => UpdateTransactionFeeDistribution,
            UpdatePayload::GASRewards(_) => UpdateGASRewards,
            UpdatePayload::BakerStakeThreshold(_) => UpdateBakerStakeThreshold,
            UpdatePayload::Root(_) => UpdateRootKeys,
            UpdatePayload::Level1(_) => UpdateLevel1Keys,
            UpdatePayload::AddAnonymityRevoker(_) => UpdateAddAnonymityRevoker,
            UpdatePayload::AddIdentityProvider(_) => UpdateAddIdentityProvider,
        }
    }
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
                        let events = effects
                            .into_iter()
                            .map(|e| match e {
                                super::ContractTraceElement::Updated { data } => {
                                    Event::Updated { data }
                                }
                                super::ContractTraceElement::Transferred { from, amount, to } => {
                                    Event::Transferred {
                                        from: Address::Contract(from),
                                        amount,
                                        to: Address::Account(to),
                                    }
                                }
                            })
                            .collect::<Vec<_>>();
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
                    super::AccountTransactionEffects::BakerAdded { data } => {
                        mk_success_1(TransactionType::AddBaker, Event::BakerAdded { data })
                    }
                    super::AccountTransactionEffects::BakerRemoved { baker_id } => {
                        mk_success_1(TransactionType::RemoveBaker, Event::BakerRemoved {
                            baker_id,
                            account: sender,
                        })
                    }
                    super::AccountTransactionEffects::BakerStakeUpdated {
                        baker_id,
                        new_stake,
                        increased,
                    } => mk_success_1(
                        TransactionType::UpdateBakerStake,
                        if increased {
                            Event::BakerStakeIncreased {
                                baker_id,
                                account: sender,
                                new_stake,
                            }
                        } else {
                            Event::BakerStakeDecreased {
                                baker_id,
                                account: sender,
                                new_stake,
                            }
                        },
                    ),
                    super::AccountTransactionEffects::BakerRestakeEarningsUpdated {
                        baker_id,
                        restake_earnings,
                    } => mk_success_1(
                        TransactionType::UpdateBakerRestakeEarnings,
                        Event::BakerSetRestakeEarnings {
                            baker_id,
                            account: sender,
                            restake_earnings,
                        },
                    ),
                    super::AccountTransactionEffects::BakerKeysUpdated { data } => {
                        mk_success_1(TransactionType::UpdateBakerKeys, Event::BakerKeysUpdated {
                            data,
                        })
                    }
                    super::AccountTransactionEffects::EncryptedAmountTransferred {
                        removed,
                        added,
                    } => mk_success_2(
                        TransactionType::EncryptedAmountTransfer,
                        Event::EncryptedAmountsRemoved { data: removed },
                        Event::NewEncryptedAmount { data: added },
                    ),
                    super::AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                        removed,
                        added,
                        memo,
                    } => mk_success_3(
                        TransactionType::EncryptedAmountTransferWithMemo,
                        Event::EncryptedAmountsRemoved { data: removed },
                        Event::NewEncryptedAmount { data: added },
                        Event::TransferMemo { memo },
                    ),
                    super::AccountTransactionEffects::TransferredToEncrypted { data } => {
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
                cost:         0.into(),
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
                cost:         0.into(),
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
    #[error("Unexpected response for an account transaction.")]
    InvalidTransactionResult,
}

#[inline(always)]
fn with_singleton(
    events: Vec<Event>,
    f: impl Fn(Event) -> Option<super::AccountTransactionEffects>,
) -> Result<super::AccountTransactionEffects, ConversionError> {
    let events_arr: [_; 1] = events
        .try_into()
        .map_err(|_| ConversionError::InvalidTransactionResult)?;
    let [e] = events_arr;
    f(e).ok_or(ConversionError::InvalidTransactionResult)
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
                .map(|e| match e {
                    Event::Updated { data } => Ok(super::ContractTraceElement::Updated { data }),
                    Event::Transferred {
                        from: Address::Contract(from),
                        amount,
                        to: Address::Account(to),
                    } => Ok(super::ContractTraceElement::Transferred { from, amount, to }),
                    _ => Err(ConversionError::InvalidTransactionResult),
                })
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
            let events_arr: [_; 2] = events
                .try_into()
                .map_err(|_| ConversionError::InvalidTransactionResult)?;
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
                _ => Err(ConversionError::InvalidTransactionResult),
            }
        }
        TransactionType::AddBaker => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerAdded { data } => {
                    Some(super::AccountTransactionEffects::BakerAdded { data })
                }
                _ => None,
            })?;
            mk_success(effects)
        }
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
        TransactionType::UpdateBakerStake => {
            let effects = with_singleton(events, |e| match e {
                Event::BakerStakeDecreased {
                    baker_id,
                    account: _,
                    new_stake,
                } => Some(super::AccountTransactionEffects::BakerStakeUpdated {
                    baker_id,
                    new_stake,
                    increased: false,
                }),
                Event::BakerStakeIncreased {
                    baker_id,
                    account: _,
                    new_stake,
                } => Some(super::AccountTransactionEffects::BakerStakeUpdated {
                    baker_id,
                    new_stake,
                    increased: true,
                }),
                _ => None,
            })?;
            mk_success(effects)
        }
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
        TransactionType::EncryptedAmountTransfer => {
            let events_arr: [_; 2] = events
                .try_into()
                .map_err(|_| ConversionError::InvalidTransactionResult)?;
            match events_arr {
                [Event::EncryptedAmountsRemoved { data: removed }, Event::NewEncryptedAmount { data: added }] => {
                    mk_success(
                        super::AccountTransactionEffects::EncryptedAmountTransferred {
                            removed,
                            added,
                        },
                    )
                }
                _ => Err(ConversionError::InvalidTransactionResult),
            }
        }
        TransactionType::EncryptedAmountTransferWithMemo => {
            let events_arr: [_; 3] = events
                .try_into()
                .map_err(|_| ConversionError::InvalidTransactionResult)?;
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
                _ => Err(ConversionError::InvalidTransactionResult),
            }
        }
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
            let events_arr: [_; 2] = events
                .try_into()
                .map_err(|_| ConversionError::InvalidTransactionResult)?;
            match events_arr {
                [Event::EncryptedAmountsRemoved { data: removed }, Event::AmountAddedByDecryption { account: _, amount }] => {
                    mk_success(super::AccountTransactionEffects::TransferredToPublic {
                        removed,
                        amount,
                    })
                }
                _ => Err(ConversionError::InvalidTransactionResult),
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
            let events_arr: [_; 2] = events
                .try_into()
                .map_err(|_| ConversionError::InvalidTransactionResult)?;
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
                _ => Err(ConversionError::InvalidTransactionResult),
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
                    .ok_or(ConversionError::InvalidTransactionResult)?;
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
                    BlockItemResult::Success { mut events } => {
                        if events.len() == 1 {
                            if let Event::UpdateEnqueued {
                                effective_time,
                                payload,
                            } = events.remove(0)
                            {
                                super::UpdateDetails {
                                    effective_time,
                                    payload,
                                }
                            } else {
                                return Err(ConversionError::InvalidUpdateResult);
                            }
                        } else {
                            return Err(ConversionError::InvalidUpdateResult);
                        }
                    }
                    BlockItemResult::Reject { .. } => return Err(ConversionError::FailedUpdate),
                };
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
