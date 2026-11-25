use cbor::{CborDeserialize, CborSerialize};
use concordium_base::{
    common::{
        cbor::{
            self, value::Value, CborDecoder, CborEncoder, CborMapEncoder, CborMaybeKnown,
            CborSerializationError, CborSerializationResult,
        },
        types::TransactionTime,
        CborDeserialize, CborSerialize,
    },
    protocol_level_locks::LockRecipients,
    protocol_level_tokens::{CborHolderAccount, RawCbor, TokenId},
};

/// Supported lock configuration versions, encoded as flat CBOR maps.
/// Decode as [`CborUpward<LockConfig>`](crate::v2::upward::CborUpward) to retain unknown versions.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockConfig {
    /// Version zero, which can contain unknown variants or capabilities.
    V0(LockConfigV0),
}

/// Version-zero lock configuration and effective permissions.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockConfigV0 {
    /// Variant specified at creation.
    pub variant: LockVariant,
    /// Accounts permitted to receive locked funds.
    pub recipients: LockRecipients,
    /// Accounts permitted to hold locked funds.
    pub holders: Vec<CborHolderAccount>,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Effective operation permissions, independent of recipient membership.
    pub roles: Vec<LockRole>,
    /// Token identifiers permitted in the lock.
    pub tokens: Vec<TokenId>,
    /// Opaque metadata bytes, not checked for nested CBOR validity.
    pub metadata: Option<RawCbor>,
}

/// Lock variant reported by the node.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockVariant {
    /// Simple lock created with `simpleV0`.
    SimpleV0,
    /// An unrecognized variant.
    Unknown(String),
}

impl LockVariant {
    /// Return the variant, including unrecognized names unchanged.
    pub fn as_str(&self) -> &str {
        match self {
            Self::SimpleV0 => "simpleV0",
            Self::Unknown(name) => name,
        }
    }
}

impl CborSerialize for LockVariant {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(self.as_str())
    }
}

impl CborDeserialize for LockVariant {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        let name = String::deserialize(decoder)?;
        Ok(match name.as_str() {
            "simpleV0" => Self::SimpleV0,
            _ => Self::Unknown(name),
        })
    }
}

/// Effective operation capability reported by the node.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockCapability {
    /// Authorizes funding the lock.
    Fund,
    /// Authorizes releasing funds to their owner.
    Release,
    /// Authorizes sending funds, subject to token policies.
    Send,
    /// Authorizes cancelling the lock before expiry.
    Cancel,
    /// An unrecognized capability.
    Unknown(String),
}

impl CborSerialize for LockCapability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(match self {
            Self::Fund => "fund",
            Self::Release => "release",
            Self::Send => "send",
            Self::Cancel => "cancel",
            Self::Unknown(name) => name,
        })
    }
}

impl CborDeserialize for LockCapability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        let name = String::deserialize(decoder)?;
        Ok(match name.as_str() {
            "fund" => Self::Fund,
            "release" => Self::Release,
            "send" => Self::Send,
            "cancel" => Self::Cancel,
            _ => Self::Unknown(name),
        })
    }
}

/// Effective capabilities for an account, including holder funding permissions.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockRole {
    /// Account receiving the capabilities.
    pub account: CborHolderAccount,
    /// Effective capabilities, which may include unrecognized capabilities.
    pub roles: Vec<LockCapability>,
}

impl CborSerialize for LockConfig {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let Self::V0(config) = self;
        let mut map = encoder.encode_map()?;
        map.serialize_entry("version", &0u64)?;
        map.serialize_entry("variant", &config.variant)?;
        map.serialize_entry("recipients", &config.recipients)?;
        map.serialize_entry("holders", &config.holders)?;
        map.serialize_entry("expiry", &config.expiry)?;
        map.serialize_entry("roles", &config.roles)?;
        map.serialize_entry("tokens", &config.tokens)?;
        if let Some(metadata) = &config.metadata {
            map.serialize_entry("metadata", metadata)?;
        }
        map.end()
    }
}

impl CborDeserialize for LockConfig {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        match Self::deserialize_maybe_known(decoder)? {
            CborMaybeKnown::Known(config) => Ok(config),
            CborMaybeKnown::Unknown(_) => Err(CborSerializationError::invalid_data(format_args!(
                "unsupported lock configuration version"
            ))),
        }
    }

    fn deserialize_maybe_known<C: CborDecoder>(
        decoder: C,
    ) -> CborSerializationResult<CborMaybeKnown<Self>> {
        let options = decoder.options();
        let value = Value::deserialize(decoder)?;
        let Value::Map(entries) = &value else {
            return Err(CborSerializationError::invalid_data(format_args!(
                "lock configuration must be a map"
            )));
        };
        let mut versions = entries.iter().filter_map(|(key, value)| match key {
            Value::Text(key) if key == "version" => Some(value),
            _ => None,
        });
        let Some(version) = versions.next() else {
            return Err(CborSerializationError::invalid_data(format_args!(
                "lock configuration requires an unsigned version"
            )));
        };
        if versions.next().is_some() {
            return Err(CborSerializationError::invalid_data(format_args!(
                "duplicate lock configuration version"
            )));
        }
        let Value::Positive(version) = version else {
            return Err(CborSerializationError::invalid_data(format_args!(
                "lock configuration requires an unsigned version"
            )));
        };
        if *version != 0 {
            return Ok(CborMaybeKnown::Unknown(value));
        }

        #[derive(CborDeserialize)]
        struct WireConfigV0 {
            #[cbor(key = "version")]
            _version: u64,
            variant: LockVariant,
            recipients: LockRecipients,
            holders: Vec<CborHolderAccount>,
            expiry: TransactionTime,
            roles: Vec<LockRole>,
            tokens: Vec<TokenId>,
            metadata: Option<RawCbor>,
        }

        // we re-encode here for convenience.
        let wire: WireConfigV0 =
            cbor::cbor_decode_with_options(cbor::cbor_encode(&value), options)?;
        Ok(CborMaybeKnown::Known(Self::V0(LockConfigV0 {
            variant: wire.variant,
            recipients: wire.recipients,
            holders: wire.holders,
            expiry: wire.expiry,
            roles: wire.roles,
            tokens: wire.tokens,
            metadata: wire.metadata,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::upward::CborUpward;
    use concordium_base::{contracts_common::AccountAddress, protocol_level_locks as base};

    const ACCOUNT: AccountAddress = AccountAddress([1; 32]);

    fn sdk_config(recipients: LockRecipients, metadata: Option<RawCbor>) -> LockConfigV0 {
        LockConfigV0 {
            variant: LockVariant::SimpleV0,
            recipients,
            holders: vec![ACCOUNT.into()],
            expiry: TransactionTime::from_seconds(1_804_806_000),
            roles: vec![LockRole {
                account: ACCOUNT.into(),
                roles: vec![
                    LockCapability::Fund,
                    LockCapability::Release,
                    LockCapability::Send,
                    LockCapability::Cancel,
                ],
            }],
            tokens: vec!["tT".parse().unwrap()],
            metadata,
        }
    }

    #[test]
    fn known_config_cross_decodes_with_base() {
        for recipients in [
            LockRecipients::Any,
            LockRecipients::Limited(vec![ACCOUNT.into()]),
        ] {
            for metadata in [None, Some(RawCbor::from(vec![0xff, 0x01]))] {
                let sdk = sdk_config(recipients.clone(), metadata);
                let base = base::LockConfig::V0(base::LockConfigV0 {
                    variant: base::LockVariant::SimpleV0,
                    recipients: sdk.recipients.clone(),
                    holders: sdk.holders.clone(),
                    expiry: sdk.expiry,
                    roles: vec![base::LockRole {
                        account: ACCOUNT.into(),
                        roles: vec![
                            base::LockCapability::Fund,
                            base::LockCapability::Release,
                            base::LockCapability::Send,
                            base::LockCapability::Cancel,
                        ],
                    }],
                    tokens: sdk.tokens.clone(),
                    metadata: sdk.metadata.clone(),
                });
                assert_eq!(sdk.variant.as_str(), "simpleV0");
                let sdk = LockConfig::V0(sdk);
                let encoded = cbor::cbor_encode(&base);
                assert_eq!(
                    cbor::cbor_decode::<CborUpward<LockConfig>>(encoded)
                        .unwrap()
                        .known(),
                    Some(sdk.clone())
                );
                assert_eq!(
                    cbor::cbor_decode::<base::LockConfig>(cbor::cbor_encode(&sdk)).unwrap(),
                    base
                );
            }
        }
    }

    #[test]
    fn unknown_version_round_trips_complete_value() {
        let original = Value::Map(vec![
            (Value::Text("expiry".into()), Value::Null),
            (Value::Text("version".into()), Value::Positive(42)),
        ]);
        let bytes = cbor::cbor_encode(&original);
        let decoded: CborUpward<LockConfig> = cbor::cbor_decode(&bytes).unwrap();
        assert_eq!(decoded, CborUpward::Unknown(original.clone()));
        assert_eq!(
            cbor::cbor_decode::<Value>(cbor::cbor_encode(&decoded)).unwrap(),
            original
        );
        assert!(cbor::cbor_decode::<LockConfig>(&bytes).is_err());
    }

    fn config_fields() -> Vec<(Value, Value)> {
        let config = LockConfig::V0(sdk_config(LockRecipients::Any, None));
        let Value::Map(fields) = cbor::cbor_decode(cbor::cbor_encode(&config)).unwrap() else {
            panic!("expected a config map");
        };
        fields
    }

    fn role_with_capability(capability: Value) -> Value {
        let account =
            cbor::cbor_decode(cbor::cbor_encode(&CborHolderAccount::from(ACCOUNT))).unwrap();
        Value::Array(vec![Value::Map(vec![
            (Value::Text("account".into()), account),
            (Value::Text("roles".into()), Value::Array(vec![capability])),
        ])])
    }

    #[test]
    fn unknown_strings_round_trip() {
        let fields = config_fields()
            .into_iter()
            .map(|(key, value)| {
                let value = match &key {
                    Value::Text(key) if key == "variant" => Value::Text("futureVariant".into()),
                    Value::Text(key) if key == "roles" => {
                        role_with_capability(Value::Text("futureCapability".into()))
                    }
                    _ => value,
                };
                (key, value)
            })
            .collect();
        let bytes = cbor::cbor_encode(&Value::Map(fields));
        let decoded: CborUpward<LockConfig> = cbor::cbor_decode(&bytes).unwrap();
        let Some(LockConfig::V0(config)) = decoded.as_known() else {
            panic!("expected a known version-zero configuration");
        };
        assert_eq!(config.variant.as_str(), "futureVariant");
        assert_eq!(
            config.roles[0].roles.last(),
            Some(&LockCapability::Unknown("futureCapability".into()))
        );
        assert_eq!(cbor::cbor_encode(&decoded), bytes);
    }
}
