// todo ar example

// //! Example that shows how to generate a verification audit anchor.
// //!
// //! You can run this example as follows:
// //! cargo run --example create_validation_audit_anchor -- --node http://localhost:20100 --account 3nhMYfA59MWaxBRjfHPKSYH9S4W5HdZZ721jozVdeToBGvXTU8.export
// use anyhow::Context as AnyhowContext;
// use clap::AppSettings;
// use concordium_rust_sdk::{
//     base::{
//         common::cbor,
//         id::{
//             constants::{ArCurve, IpPairing},
//             id_proof_types::{AtomicStatement, AttributeInRangeStatement},
//         },
//         web3id::{
//             did::Network,
//             sdk::protocol::{
//                 Context, CredentialType, IdentityProviderMethod, IdentityStatementRequest,
//                 VerificationRequestData,
//             },
//             v1::PresentationV1,
//             Web3IdAttribute,
//         },
//     },
//     common::types::TransactionTime,
//     types::WalletAccount,
//     v2::{self},
//     verifiable_presentation::protocol_v1::{
//         create_and_anchor_verification_request, verify_and_anchor_audit_record,
//         AnchorTransactionMetadata,
//     },
// };
// use rand::Rng;
// use std::{collections::HashMap, marker::PhantomData, path::PathBuf};
// use structopt::*;
//
// #[derive(StructOpt)]
// struct App {
//     #[structopt(
//         long = "node",
//         help = "GRPC interface of the node.",
//         default_value = "http://localhost:20100"
//     )]
//     endpoint: v2::Endpoint,
//     #[structopt(long = "account", help = "Path to the account key file.")]
//     keys_path: PathBuf,
// }
//
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    //     let app = {
    //         let app = App::clap().global_setting(AppSettings::ColoredHelp);
    //         let matches = app.get_matches();
    //         App::from_clap(&matches)
    //     };
    //     let mut client = v2::Client::new(app.endpoint).await?;
    //     let network = Network::Testnet;
    //
    //     // Load account keys and sender address from a file
    //     let keys: WalletAccount =
    //         WalletAccount::from_json_file(app.keys_path).context("Could not read the keys file.")?;
    //
    //     // Get the initial nonce at the last finalized block.
    //     let account_sequence_number = client
    //         .get_next_account_sequence_number(&keys.address)
    //         .await?;
    //     let account_sequence_number = account_sequence_number.nonce;
    //
    //     // Set expiry to now + 5min
    //     let expiry: TransactionTime =
    //         TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    //
    //     // First we generate the verification request.
    //     //
    //     // Generating the `context` and `credential_statements` will normally happen server-side.
    //     let mut rng = rand::thread_rng();
    //     let nonce: [u8; 32] = rng.gen(); // Note: This nonce has to be generated fresh/randomly for each request.
    //     let connection_id = "MyWalletConnectTopic".to_string(); // Note: Use the wallet connect topic in production.
    //     let context_string = "MyGreateApp".to_string();
    //     let context = Context::new_simple(nonce, connection_id, context_string);
    //
    //     let attribute_in_range_statement = AtomicStatement::AttributeInRange {
    //         statement: AttributeInRangeStatement {
    //             attribute_tag: 17.into(),
    //             lower: Web3IdAttribute::Numeric(80),
    //             upper: Web3IdAttribute::Numeric(1237),
    //             _phantom: PhantomData,
    //         },
    //     };
    //
    //     let verification_request_data = VerificationRequestData::new(context).add_statement_request(
    //         IdentityStatementRequest::default()
    //             .add_issuer(IdentityProviderMethod::new(0u32, network))
    //             .add_source(CredentialType::IdentityCredential)
    //             .add_statement(attribute_in_range_statement),
    //     );
    //
    //     let mut public_info = HashMap::new();
    //     public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));
    //
    //     let anchor_transaction_metadata = AnchorTransactionMetadata {
    //         signer: &keys,
    //         sender: keys.address,
    //         account_sequence_number,
    //         expiry,
    //     };
    //
    //     let verification_request = create_and_anchor_verification_request(
    //         client.clone(),
    //         anchor_transaction_metadata,
    //         verification_request_data,
    //         public_info.clone(),
    //     )
    //         .await?;
    //
    //     println!(
    //         "Verification request anchor transaction hash: {}",
    //         verification_request.anchor_transaction_hash
    //     );
    //
    //     let (bh, _) = client
    //         .wait_until_finalized(&verification_request.anchor_transaction_hash)
    //         .await?;
    //
    //     println!("Verification request anchor finalized in block {}.", bh);
    //
    //     // Note: The verification request is sent to the wallet/idApp and the
    //     // returned presentation would be used here instead.
    //     let presentation_json = r#"
    // {
    //   "type": [
    //     "VerifiablePresentation",
    //     "ConcordiumVerifiablePresentationV1"
    //   ],
    //   "presentationContext": {
    //     "given": [
    //         {
    //             "context": "0101010101010101010101010101010101010101010101010101010101010101",
    //             "label": "Nonce"
    //         },
    //         {
    //             "context": "MyConnection",
    //             "label": "ConnectionID"
    //         },
    //         {
    //             "context": "MyDappContext",
    //             "label": "ContextString"
    //         },
    //         {
    //             "context": "0202020202020202020202020202020202020202020202020202020202020202",
    //             "label": "PaymentHash"
    //         },
    //         {
    //             "context": "0303030303030303030303030303030303030303030303030303030303030303",
    //             "label": "BlockHash"
    //         },
    //         {
    //             "context": "MyRescourceId",
    //             "label": "ResourceID"
    //         }
    //     ],
    //     "requested": [
    //         {
    //             "context": "0101010101010101010101010101010101010101010101010101010101010101",
    //             "label": "Nonce"
    //         },
    //         {
    //             "context": "MyConnection",
    //             "label": "ConnectionID"
    //         },
    //         {
    //             "context": "MyDappContext",
    //             "label": "ContextString"
    //         },
    //         {
    //             "context": "0202020202020202020202020202020202020202020202020202020202020202",
    //             "label": "PaymentHash"
    //         },
    //         {
    //             "context": "0303030303030303030303030303030303030303030303030303030303030303",
    //             "label": "BlockHash"
    //         },
    //         {
    //             "context": "MyRescourceId",
    //             "label": "ResourceID"
    //         }
    //     ],
    //     "type": "ConcordiumContextInformationV1"
    //   },
    //   "verifiableCredential": [
    //     {
    //       "type": [
    //         "VerifiableCredential",
    //         "ConcordiumVerifiableCredentialV1",
    //         "ConcordiumAccountBasedCredential"
    //       ],
    //       "credentialSubject": {
    //         "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
    //         "statement": [
    //           {
    //             "type": "AttributeInRange",
    //             "attributeTag": "dob",
    //             "lower": 80,
    //             "upper": 1237
    //           },
    //           {
    //             "type": "AttributeInSet",
    //             "attributeTag": "sex",
    //             "set": [
    //               "aa",
    //               "ff",
    //               "zz"
    //             ]
    //           },
    //           {
    //             "type": "AttributeNotInSet",
    //             "attributeTag": "lastName",
    //             "set": [
    //               "aa",
    //               "ff",
    //               "zz"
    //             ]
    //           },
    //           {
    //             "type": "AttributeInRange",
    //             "attributeTag": "countryOfResidence",
    //             "lower": {
    //               "type": "date-time",
    //               "timestamp": "2023-08-27T23:12:15Z"
    //             },
    //             "upper": {
    //               "type": "date-time",
    //               "timestamp": "2023-08-29T23:12:15Z"
    //             }
    //           },
    //           {
    //             "type": "RevealAttribute",
    //             "attributeTag": "nationality"
    //           }
    //         ]
    //       },
    //       "issuer": "did:ccd:testnet:idp:17",
    //       "proof": {
    //         "createdAt": "2023-08-28T23:12:15Z",
    //         "proof": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
    //         "type": "ConcordiumZKProofV4"
    //       }
    //     }
    //   ],
    //   "proof": {
    //     "created": "2023-08-28T23:12:15Z",
    //     "proofValue": [],
    //     "type": "ConcordiumWeakLinkingProofV1"
    //   }
    // }
    //         "#;
    //
    //     let presentation: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
    //         serde_json::from_str(presentation_json).unwrap();
    //
    //     let id = "UUID".to_string();
    //
    //     let anchor_transaction_metadata = AnchorTransactionMetadata {
    //         signer: &keys,
    //         sender: keys.address,
    //         account_sequence_number: account_sequence_number.next(), // We have to increase the nonce as this is the second anchor tx.
    //         expiry,
    //     };
    //
    //     let anchored_verification_audit_record = verify_and_anchor_audit_record(
    //         &mut client,
    //         anchor_transaction_metadata,
    //         verification_request,
    //         presentation,
    //         id,
    //         public_info,
    //     )
    //         .await?;
    //
    //     println!(
    //         "Verification audit anchor transaction hash: {}",
    //         anchored_verification_audit_record.transaction_ref
    //     );
    //
    //     let (bh, bs) = client
    //         .wait_until_finalized(&anchored_verification_audit_record.transaction_ref)
    //         .await?;
    //
    //     println!("Verification request anchor finalized in block {}.", bh);
    //     println!("The outcome is {:#?}", bs);
    //
    //     println!(
    //         "Generated anchored verification audit record to be stored in database: {:#?}",
    //         anchored_verification_audit_record
    //     );
    //
    Ok(())
}
