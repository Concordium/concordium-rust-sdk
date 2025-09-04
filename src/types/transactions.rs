//! Definition of transactions and other transaction-like messages, together
//! with their serialization, signing, and similar auxiliary methods.

use super::{AccountInfo, AccountThreshold, CredentialIndex};
use crate::v2::Upward;
use concordium_base::id::types::CredentialPublicKeys;
pub use concordium_base::{transactions::*, updates::*};

impl HasAccountAccessStructure for AccountInfo {
    fn threshold(&self) -> AccountThreshold {
        self.account_threshold
    }

    fn credential_keys(&self, idx: CredentialIndex) -> Option<&CredentialPublicKeys> {
        let versioned_cred = self.account_credentials.get(&idx)?;
        match versioned_cred.value {
            Upward::Known(crate::id::types::AccountCredentialWithoutProofs::Initial {
                ref icdv,
            }) => Some(&icdv.cred_account),
            Upward::Known(crate::id::types::AccountCredentialWithoutProofs::Normal {
                ref cdv,
                ..
            }) => Some(&cdv.cred_key_info),
            Upward::Unknown => None,
        }
    }
}
