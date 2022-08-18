#[cfg(test)]
mod tests {
    use crate::contract::{check_permission, handle, init, query};
    use crate::expiration::Expiration;
    use crate::inventory::Inventory;
    use crate::msg::{
        AccessLevel, Burn, ContractStatus, HandleAnswer, HandleMsg, InitConfig, InitMsg, Mint,
        PostInitCallback, QueryAnswer, QueryMsg, ReceiverInfo, Send, Transfer, Tx, TxAction,
    };
    use crate::receiver::Snip721ReceiveMsg;
    use crate::state::{
        get_txs, json_load, json_may_load, load, may_load, AuthList, Config, Permission,
        PermissionType, CONFIG_KEY, MINTERS_KEY, PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST,
        PREFIX_INFOS, PREFIX_MAP_TO_ID, PREFIX_MAP_TO_INDEX, PREFIX_OWNER_PRIV, PREFIX_PRIV_META,
        PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_VIEW_KEY,
    };
    use crate::token::{Extension, Metadata, Token};
    use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, to_binary, Api, Binary, BlockInfo, CanonicalAddr, Coin, CosmosMsg, Env,
        Extern, HandleResponse, HumanAddr, InitResponse, MessageInfo, StdError, StdResult, Uint128,
        WasmMsg,
    };
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use secret_toolkit::utils::space_pad;
    use std::any::Any;

    // Helper functions

    fn init_helper_default() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);

        let init_msg = InitMsg {
          name: "sec721".to_string(),
          symbol: "S721".to_string(),
          admin: Some(HumanAddr("admin".to_string())),
          entropy: "We're going to need a bigger boat".to_string(),
          royalty_info: None,
          config: Some(init_config),
          post_init_callback: None,
          snip20_hash: "9587d60b8e6b078ace12014ceeee089530b9fabcd76535d93666a6c127ad8813".to_string(),
          snip20_address: "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg".to_string(),
          mint_funds_distribution_info: None
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn init_helper_with_config(
        public_token_supply: bool,
        public_owner: bool,
        enable_sealed_metadata: bool,
        unwrapped_metadata_is_private: bool,
        minter_may_update_metadata: bool,
        owner_may_update_metadata: bool,
        enable_burn: bool,
    ) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);

        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_token_supply\":{},
            \"public_owner\":{},
            \"enable_sealed_metadata\":{},
            \"unwrapped_metadata_is_private\":{},
            \"minter_may_update_metadata\":{},
            \"owner_may_update_metadata\":{},
            \"enable_burn\":{}}}",
                public_token_supply,
                public_owner,
                enable_sealed_metadata,
                unwrapped_metadata_is_private,
                minter_may_update_metadata,
                owner_may_update_metadata,
                enable_burn,
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: Some(init_config),
            post_init_callback: None,
            snip20_hash: "9587d60b8e6b078ace12014ceeee089530b9fabcd76535d93666a6c127ad8813".to_string(),
            snip20_address: "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg".to_string(),
            mint_funds_distribution_info: None
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(_response) => panic!("Expected error, but had Ok response"),
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected error result {:?}", err),
            },
        }
    }

    fn extract_log(resp: StdResult<HandleResponse>) -> String {
        match resp {
            Ok(response) => response.log[0].value.clone(),
            Err(_err) => "These are not the logs you are looking for".to_string(),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        // test default
        let (init_result, deps) = init_helper_default();
        assert_eq!(init_result.unwrap(), InitResponse::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(
            config.admin,
            deps.api
                .canonical_address(&HumanAddr("admin".to_string()))
                .unwrap()
        );
        assert_eq!(config.symbol, "S721".to_string());
        assert_eq!(config.token_supply_is_public, false);
        assert_eq!(config.owner_is_public, false);
        assert_eq!(config.sealed_metadata_is_enabled, false);
        assert_eq!(config.unwrap_to_private, false);
        assert_eq!(config.minter_may_update_metadata, true);
        assert_eq!(config.owner_may_update_metadata, false);
        assert_eq!(config.burn_is_enabled, false);

        // test config specification
        let (init_result, deps) =
            init_helper_with_config(true, true, true, true, false, true, false);
        assert_eq!(init_result.unwrap(), InitResponse::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(
            config.admin,
            deps.api
                .canonical_address(&HumanAddr("admin".to_string()))
                .unwrap()
        );
        assert_eq!(config.symbol, "S721".to_string());
        assert_eq!(config.token_supply_is_public, true);
        assert_eq!(config.owner_is_public, true);
        assert_eq!(config.sealed_metadata_is_enabled, true);
        assert_eq!(config.unwrap_to_private, true);
        assert_eq!(config.minter_may_update_metadata, false);
        assert_eq!(config.owner_may_update_metadata, true);
        assert_eq!(config.burn_is_enabled, false);

        // test post init callback
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        // just picking a random short HandleMsg that wouldn't really make sense
        let post_init_msg = to_binary(&HandleMsg::MakeOwnershipPrivate { padding: None }).unwrap();
        let post_init_send = vec![Coin {
            amount: Uint128(100),
            denom: "uscrt".to_string(),
        }];
        let post_init_callback = Some(PostInitCallback {
            msg: post_init_msg.clone(),
            contract_address: HumanAddr("spawner".to_string()),
            code_hash: "spawner hash".to_string(),
            send: post_init_send.clone(),
        });

        let init_msg = InitMsg {
          name: "sec721".to_string(),
          symbol: "S721".to_string(),
          admin: Some(HumanAddr("admin".to_string())),
          entropy: "We're going to need a bigger boat".to_string(),
          royalty_info: None,
          config: Some(init_config),
          post_init_callback: None,
          snip20_hash: "9587d60b8e6b078ace12014ceeee089530b9fabcd76535d93666a6c127ad8813".to_string(),
          snip20_address: "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg".to_string(),
          mint_funds_distribution_info: None
        };

        let init_response = init(&mut deps, env, init_msg).unwrap();
        assert_eq!(
            init_response.messages,
            vec![CosmosMsg::Wasm(WasmMsg::Execute {
                msg: post_init_msg,
                contract_addr: HumanAddr("spawner".to_string()),
                callback_code_hash: "spawner hash".to_string(),
                send: post_init_send,
            })]
        );
    }

    // Handle tests

    // test batch mint
    #[test]
    fn test_batch_mint() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let empty_metadata = Metadata {
            token_uri: None,
            extension: Some(Extension::default()),
        };

        let alice = HumanAddr("alice".to_string());
        let alice_raw = deps.api.canonical_address(&alice).unwrap();
        let admin = HumanAddr("admin".to_string());
        let admin_raw = deps.api.canonical_address(&admin).unwrap();


        // // test minting when status prevents it
        // let handle_msg = HandleMsg::SetContractStatus {
        //     level: ContractStatus::StopTransactions,
        //     padding: None,
        // };
        // let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // let handle_msg = HandleMsg::BatchMintNft {
        //     mints: mints.clone(),
        //     padding: None,
        //     entropy: None,
        // };
        // let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // let error = extract_error_msg(handle_result);
        // assert!(error.contains("The contract admin has temporarily disabled this action"));

        // let handle_msg = HandleMsg::SetContractStatus {
        //     level: ContractStatus::Normal,
        //     padding: None,
        // };
        // let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // // test non-minter attempt
        // let handle_msg = HandleMsg::BatchMintNft {
        //     mints: mints.clone(),
        //     padding: None,
        //     entropy: None,
        // };
        // let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        // let error = extract_error_msg(handle_result);
        // assert!(error.contains("Only designated minters are allowed to mint"));

        // sanity check
        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted_vec = vec![
            "0".to_string(),
            "NFT2".to_string(),
            "NFT3".to_string(),
            "3".to_string(),
        ];
        let handle_answer: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            HandleAnswer::BatchMintNft { token_ids } => {
                assert_eq!(token_ids, minted_vec);
            }
            _ => panic!("unexpected"),
        }

        // verify the tokens are in the id and index maps
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index1: u32 = load(&map2idx, "0".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let index2: u32 = load(&map2idx, "NFT2".as_bytes()).unwrap();
        let token_key2 = index2.to_le_bytes();
        let index3: u32 = load(&map2idx, "NFT3".as_bytes()).unwrap();
        let token_key3 = index3.to_le_bytes();
        let index4: u32 = load(&map2idx, "3".as_bytes()).unwrap();
        let token_key4 = index4.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id1: String = load(&map2id, &token_key1).unwrap();
        assert_eq!("0".to_string(), id1);
        let id2: String = load(&map2id, &token_key2).unwrap();
        assert_eq!("NFT2".to_string(), id2);
        let id3: String = load(&map2id, &token_key3).unwrap();
        assert_eq!("NFT3".to_string(), id3);
        let id4: String = load(&map2id, &token_key4).unwrap();
        assert_eq!("3".to_string(), id4);
        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &token_key1).unwrap();
        assert_eq!(token1.owner, alice_raw);
        assert_eq!(token1.permissions, Vec::new());
        assert!(token1.unwrapped);
        let token2: Token = json_load(&info_store, &token_key2).unwrap();
        assert_eq!(token2.owner, admin_raw);
        assert_eq!(token2.permissions, Vec::new());
        assert!(token2.unwrapped);
        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta1: Metadata = load(&pub_store, &token_key1).unwrap();
        assert_eq!(pub_meta1, pub1);
        //let pub_meta2: Option<Metadata> = may_load(&pub_store, &token_key2).unwrap();
        //assert!(pub_meta2.is_none());
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        //let priv_meta1: Option<Metadata> = may_load(&priv_store, &token_key1).unwrap();
        //assert!(priv_meta1.is_none());
        let priv_meta2: Metadata = load(&priv_store, &token_key2).unwrap();
        assert_eq!(priv_meta2, priv2);
        // verify owner lists
        assert!(Inventory::owns(&deps.storage, &alice_raw, 0).unwrap());
        assert!(Inventory::owns(&deps.storage, &alice_raw, 2).unwrap());
        assert!(Inventory::owns(&deps.storage, &admin_raw, 1).unwrap());
        assert!(Inventory::owns(&deps.storage, &admin_raw, 3).unwrap());
        // verify mint tx was logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 4).unwrap();
        assert_eq!(total, 4);
        assert_eq!(txs[0].token_id, "3".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: admin.clone(),
                recipient: admin,
            }
        );
        assert_eq!(txs[0].memo, Some("has id 3".to_string()));

        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints,
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID NFT2 is already in use"));
    }

    // test minting
    #[test]
    fn test_mint() {
        let empty_metadata = Metadata {
            token_uri: None,
            extension: Some(Extension::default()),
        };

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        // test minting when status prevents it
        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test setting both token_uri and extension
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: Some("uri".to_string()),
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: Some(empty_metadata.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        println!("{:?}", error);
        assert!(error.contains("Keys cannot be added to a metadata using token_uri."));

        // test non-minter attempt
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Only designated minters are allowed to mint"));

        // sanity check
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let pub_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            entropy: None,
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: pub_meta.clone(),
            private_metadata: priv_meta.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };

        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted = extract_log(handle_result);
        assert!(minted.contains("MyNFT"));
        // verify the token is in the id and index maps
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        assert_eq!(token.owner, alice_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);
        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());
        // verify token is in owner list
        assert!(Inventory::owns(&deps.storage, &alice_raw, 0).unwrap());
        // verify mint tx was logged to both parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: HumanAddr("admin".to_string()),
                recipient: HumanAddr("alice".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Mint it baby!".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        // test minting with an existing token id
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            entropy: None,
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFTpriv".to_string()),
                    description: Some("Nifty".to_string()),
                    image: Some("privuri".to_string()),
                    ..Extension::default()
                }),
            }),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID MyNFT is already in use"));

        // test minting without specifying recipient or id and with entropy
        let pub_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("AdminNFT".to_string()),
                description: None,
                image: None,
                ..Extension::default()
            }),
        });
        let handle_msg = HandleMsg::MintNft {
            token_id: None,
            owner: None,
            public_metadata: pub_meta.clone(),
            private_metadata: Some(empty_metadata),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Admin wants his own".to_string()),
            padding: None,
            entropy: Some("test".to_string()),
        };

        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("AdminNFT".to_string()),
                description: None,
                image: None,
                ..Extension::default()
            }),
        });
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted_str = "1".to_string();
        let handle_answer: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            HandleAnswer::MintNft { token_id } => {
                assert_eq!(token_id, minted_str);
            }
            _ => panic!("unexpected"),
        }

        // verify token is in the token list
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "1".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("1".to_string(), id);
        // verify token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        assert_eq!(token.owner, admin_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);
        // verify metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());
        // (private meta test is no longer valid due to authentication)
        // let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        // let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
        // assert!(priv_meta.is_none());
        // verify token is in the owner list
        assert!(Inventory::owns(&deps.storage, &admin_raw, 1).unwrap());
        // verify mint tx was logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 10).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].token_id, "1".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: HumanAddr("admin".to_string()),
                recipient: HumanAddr("admin".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Admin wants his own".to_string()));
        assert_eq!(txs[1].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[1].action,
            TxAction::Mint {
                minter: HumanAddr("admin".to_string()),
                recipient: HumanAddr("alice".to_string()),
            }
        );
        assert_eq!(txs[1].memo, Some("Mint it baby!".to_string()));
    }

    
}
