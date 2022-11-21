//! This module contains types and their implementations related to the CIS-2
//! token standard.

pub use concordium_base::cis2_types::*;
use concordium_base::contracts_common::{Cursor, Deserial, ParseError};

/// Attempt to parse the contract event into an event. This requires that the
/// entire input is consumed if it is a known CIS2 event.
impl<'a> TryFrom<&'a super::smart_contracts::ContractEvent> for Event {
    type Error = ParseError;

    fn try_from(value: &'a super::smart_contracts::ContractEvent) -> Result<Self, Self::Error> {
        let data = value.as_ref();
        let mut cursor = Cursor::new(data);
        let res = Self::deserial(&mut cursor)?;
        if cursor.offset == data.len() || matches!(&res, Self::Unknown) {
            Ok(res)
        } else {
            Err(ParseError {})
        }
    }
}
