//! Network related types.

use crate::generated_types::peer_element::CatchupStatus;
use crypto_common::{SerdeDeserialize, SerdeSerialize};
use derive_more::{Display, From, FromStr, Into};
use std::{fmt, net::IpAddr, num::ParseIntError};

#[derive(Debug)]
pub struct PeerElement {
    pub node_id:        String,
    pub port:           u16,
    pub ip:             IpAddr,
    pub catchup_status: CatchupStatus,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct RemotePeerId {
    id: u64,
}

/// Parse from a (possibly 0 padded) hex value.
impl std::str::FromStr for RemotePeerId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, ParseIntError> {
        let id = u64::from_str_radix(s, 16)?;
        Ok(RemotePeerId { id })
    }
}

/// Display as a 0-padded hex value.
impl std::fmt::Display for RemotePeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:016x}", self.id) }
}

#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct NetworkId {
    pub(crate) network_id: u16,
}
