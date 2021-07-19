use crate::mm2::lp_swap::maker_swap::{MakerSavedSwap, MakerSwap};
use crate::mm2::lp_swap::taker_swap::{TakerSavedSwap, TakerSwap};
use crate::mm2::lp_swap::{MySwapInfo, RecoveredSwap};
use async_trait::async_trait;
use coins::lp_coinfind;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use derive_more::Display;
use serde_json as json;
use uuid::Uuid;

pub type SavedSwapResult<T> = Result<T, MmError<SavedSwapError>>;

#[derive(Debug, Display)]
pub enum SavedSwapError {
    #[display(fmt = "Error uploading the a swap: {}", _0)]
    ErrorUploading(String),
    #[display(fmt = "Error loading a swap: {}", _0)]
    ErrorLoading(String),
    #[display(fmt = "Error deserializing a swap: {}", _0)]
    ErrorDeserializing(String),
    #[display(fmt = "Error serializing a swap: {}", _0)]
    ErrorSerializing(String),
    #[allow(dead_code)]
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SavedSwap {
    Maker(MakerSavedSwap),
    Taker(TakerSavedSwap),
}

impl SavedSwap {
    pub fn is_finished(&self) -> bool {
        match self {
            SavedSwap::Maker(swap) => swap.is_finished(),
            SavedSwap::Taker(swap) => swap.is_finished(),
        }
    }

    pub fn uuid(&self) -> &Uuid {
        match self {
            SavedSwap::Maker(swap) => &swap.uuid,
            SavedSwap::Taker(swap) => &swap.uuid,
        }
    }

    pub fn maker_coin_ticker(&self) -> Result<String, String> {
        match self {
            SavedSwap::Maker(swap) => swap.maker_coin(),
            SavedSwap::Taker(swap) => swap.maker_coin(),
        }
    }

    pub fn taker_coin_ticker(&self) -> Result<String, String> {
        match self {
            SavedSwap::Maker(swap) => swap.taker_coin(),
            SavedSwap::Taker(swap) => swap.taker_coin(),
        }
    }

    pub fn get_my_info(&self) -> Option<MySwapInfo> {
        match self {
            SavedSwap::Maker(swap) => swap.get_my_info(),
            SavedSwap::Taker(swap) => swap.get_my_info(),
        }
    }

    pub async fn recover_funds(self, ctx: MmArc) -> Result<RecoveredSwap, String> {
        let maker_ticker = try_s!(self.maker_coin_ticker());
        let maker_coin = match lp_coinfind(&ctx, &maker_ticker).await {
            Ok(Some(c)) => c,
            Ok(None) => return ERR!("Coin {} is not activated", maker_ticker),
            Err(e) => return ERR!("Error {} on {} coin find attempt", e, maker_ticker),
        };

        let taker_ticker = try_s!(self.taker_coin_ticker());
        let taker_coin = match lp_coinfind(&ctx, &taker_ticker).await {
            Ok(Some(c)) => c,
            Ok(None) => return ERR!("Coin {} is not activated", taker_ticker),
            Err(e) => return ERR!("Error {} on {} coin find attempt", e, taker_ticker),
        };
        match self {
            SavedSwap::Maker(saved) => {
                let (maker_swap, _) = try_s!(MakerSwap::load_from_saved(ctx, maker_coin, taker_coin, saved));
                Ok(try_s!(maker_swap.recover_funds()))
            },
            SavedSwap::Taker(saved) => {
                let (taker_swap, _) = try_s!(TakerSwap::load_from_saved(ctx, maker_coin, taker_coin, saved));
                Ok(try_s!(taker_swap.recover_funds()))
            },
        }
    }

    pub fn is_recoverable(&self) -> bool {
        match self {
            SavedSwap::Maker(saved) => saved.is_recoverable(),
            SavedSwap::Taker(saved) => saved.is_recoverable(),
        }
    }
}

#[async_trait]
pub trait SavedSwapIo {
    async fn load_my_swap_from_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<SavedSwap>>;

    async fn load_all_my_swaps_from_db(ctx: &MmArc) -> SavedSwapResult<Vec<SavedSwap>>;

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_from_maker_stats_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<MakerSavedSwap>>;

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_all_from_maker_stats_db(ctx: &MmArc) -> SavedSwapResult<Vec<MakerSavedSwap>>;

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_from_taker_stats_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<TakerSavedSwap>>;

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_all_from_taker_stats_db(ctx: &MmArc) -> SavedSwapResult<Vec<TakerSavedSwap>>;

    /// Save the serialized `SavedSwap` to the swaps db.
    async fn save_to_db(&self, ctx: &MmArc) -> SavedSwapResult<()>;

    /// Save the inner maker/taker swap to the corresponding stats db.
    #[cfg(not(target_arch = "wasm32"))]
    async fn save_to_stats_db(&self, ctx: &MmArc) -> SavedSwapResult<()>;
}

#[cfg(not(target_arch = "wasm32"))]
mod native_impl {
    use super::*;
    use crate::mm2::lp_swap::maker_swap::{stats_maker_swap_dir, stats_maker_swap_file_path};
    use crate::mm2::lp_swap::taker_swap::{stats_taker_swap_dir, stats_taker_swap_file_path};
    use crate::mm2::lp_swap::{my_swap_file_path, my_swaps_dir};
    use async_std::fs;
    use common::log::error;
    use common::read_dir_async;
    use futures::AsyncWriteExt;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::ffi::OsStr;
    use std::io;
    use std::path::Path;

    #[async_trait]
    impl SavedSwapIo for SavedSwap {
        async fn load_my_swap_from_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<SavedSwap>> {
            let path = my_swap_file_path(ctx, &uuid);
            load_and_deserialize(&path).await
        }

        async fn load_all_my_swaps_from_db(ctx: &MmArc) -> SavedSwapResult<Vec<SavedSwap>> {
            let path = my_swaps_dir(&ctx);
            load_all_and_deserialize(&path).await
        }

        async fn load_from_maker_stats_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<MakerSavedSwap>> {
            let path = stats_maker_swap_file_path(ctx, &uuid);
            load_and_deserialize(&path).await
        }

        async fn load_all_from_maker_stats_db(ctx: &MmArc) -> SavedSwapResult<Vec<MakerSavedSwap>> {
            let path = stats_maker_swap_dir(ctx);
            load_all_and_deserialize(&path).await
        }

        async fn load_from_taker_stats_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<TakerSavedSwap>> {
            let path = stats_taker_swap_file_path(ctx, &uuid);
            load_and_deserialize(&path).await
        }

        async fn load_all_from_taker_stats_db(ctx: &MmArc) -> SavedSwapResult<Vec<TakerSavedSwap>> {
            let path = stats_taker_swap_dir(ctx);
            load_all_and_deserialize(&path).await
        }

        async fn save_to_db(&self, ctx: &MmArc) -> SavedSwapResult<()> {
            let path = my_swap_file_path(ctx, self.uuid());
            serialize_and_save(self, &path).await
        }

        /// Save the inner maker/taker swap to the corresponding stats db.
        async fn save_to_stats_db(&self, ctx: &MmArc) -> SavedSwapResult<()> {
            match self {
                SavedSwap::Maker(maker) => {
                    let path = stats_maker_swap_file_path(ctx, &maker.uuid);
                    serialize_and_save(maker, &path).await
                },
                SavedSwap::Taker(taker) => {
                    let path = stats_taker_swap_file_path(ctx, &taker.uuid);
                    serialize_and_save(taker, &path).await
                },
            }
        }
    }

    async fn load_and_deserialize<Swap>(path: &Path) -> SavedSwapResult<Option<Swap>>
    where
        Swap: DeserializeOwned,
    {
        let content = match fs::read(path).await {
            Ok(content) => content,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return MmError::err(SavedSwapError::ErrorLoading(e.to_string())),
        };
        json::from_slice(&content).map_to_mm(|e| SavedSwapError::ErrorDeserializing(e.to_string()))
    }

    async fn load_all_and_deserialize<Swap>(dir_path: &Path) -> SavedSwapResult<Vec<Swap>>
    where
        Swap: DeserializeOwned,
    {
        let json_ext = Some(OsStr::new("json"));
        let entries: Vec<_> = read_dir_async(dir_path)
            .await
            .map_to_mm(SavedSwapError::ErrorLoading)?
            .into_iter()
            .filter(|path| path.extension() == json_ext)
            .collect();

        let mut result = Vec::new();
        for swap_path in entries {
            match load_and_deserialize(&swap_path).await {
                Ok(Some(swap)) => result.push(swap),
                Ok(None) => {
                    error!(
                        "Expected a saved swap at the file {}, found 'None'",
                        swap_path.display()
                    );
                    continue;
                },
                Err(e) => {
                    error!("Error reading the swap from the file {}: {}", swap_path.display(), e);
                    continue;
                },
            };
        }
        Ok(result)
    }

    async fn serialize_and_save<Swap>(swap: &Swap, path: &Path) -> SavedSwapResult<()>
    where
        Swap: Serialize,
    {
        let content = json::to_vec(swap).map_to_mm(|e| SavedSwapError::ErrorSerializing(e.to_string()))?;

        let fs_fut = async {
            let mut file = fs::File::create(&path).await?;
            file.write_all(&content).await?;
            file.flush().await?;
            Ok(())
        };

        let res: io::Result<_> = fs_fut.await;
        if let Err(e) = res {
            let error = format!("Error '{}' creating/writing the file {}", e, path.display());
            return MmError::err(SavedSwapError::ErrorUploading(error));
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use super::*;
    use crate::mm2::lp_swap::swap_db::{DbTransactionError, InitDbError, ItemId, SavedSwapTable};
    use crate::mm2::lp_swap::SwapsContext;

    impl From<DbTransactionError> for SavedSwapError {
        fn from(e: DbTransactionError) -> Self {
            let desc = e.to_string();
            match e {
                DbTransactionError::NoSuchTable { .. }
                | DbTransactionError::ErrorCreatingTransaction(_)
                | DbTransactionError::ErrorOpeningTable { .. }
                | DbTransactionError::ErrorSerializingIndex { .. }
                | DbTransactionError::MultipleItemsByUniqueIndex { .. }
                | DbTransactionError::NoSuchIndex { .. }
                | DbTransactionError::InvalidIndex { .. }
                | DbTransactionError::UnexpectedState(_)
                | DbTransactionError::TransactionAborted => SavedSwapError::InternalError(desc),
                DbTransactionError::ErrorDeserializingItem(_) => SavedSwapError::ErrorDeserializing(desc),
                DbTransactionError::ErrorSerializingItem(_) => SavedSwapError::ErrorSerializing(desc),
                DbTransactionError::ErrorGettingItems(_) => SavedSwapError::ErrorLoading(desc),
                DbTransactionError::ErrorUploadingItem(_) | DbTransactionError::ErrorDeletingItems(_) => {
                    SavedSwapError::ErrorUploading(desc)
                },
            }
        }
    }

    impl From<InitDbError> for SavedSwapError {
        fn from(e: InitDbError) -> Self { SavedSwapError::InternalError(e.to_string()) }
    }

    #[async_trait]
    impl SavedSwapIo for SavedSwap {
        async fn load_my_swap_from_db(ctx: &MmArc, uuid: Uuid) -> SavedSwapResult<Option<SavedSwap>> {
            let swaps_ctx = SwapsContext::from_ctx(ctx).map_to_mm(SavedSwapError::InternalError)?;
            let db = swaps_ctx.swap_db().await?;
            let transaction = db.transaction().await?;
            let table = transaction.table::<SavedSwapTable>().await?;

            let saved_swap_json = match table.get_item_by_unique_index("uuid", uuid).await? {
                Some((_item_id, SavedSwapTable { saved_swap, .. })) => saved_swap,
                None => return Ok(None),
            };

            json::from_value(saved_swap_json).map_to_mm(|e| SavedSwapError::ErrorDeserializing(e.to_string()))
        }

        async fn load_all_my_swaps_from_db(ctx: &MmArc) -> SavedSwapResult<Vec<SavedSwap>> {
            let swaps_ctx = SwapsContext::from_ctx(ctx).map_to_mm(SavedSwapError::InternalError)?;
            let db = swaps_ctx.swap_db().await?;
            let transaction = db.transaction().await?;
            let table = transaction.table::<SavedSwapTable>().await?;

            let swaps = table.get_all_items().await?;
            swaps
                .into_iter()
                .map(|(_item_id, SavedSwapTable { saved_swap, .. })| saved_swap)
                .map(json::from_value)
                .map(|res: Result<SavedSwap, _>| res.map_to_mm(|e| SavedSwapError::ErrorDeserializing(e.to_string())))
                .collect()
        }

        async fn save_to_db(&self, ctx: &MmArc) -> SavedSwapResult<()> {
            let saved_swap = json::to_value(self).map_to_mm(|e| SavedSwapError::ErrorSerializing(e.to_string()))?;
            let saved_swap_item = SavedSwapTable {
                uuid: *self.uuid(),
                saved_swap,
            };

            let swaps_ctx = SwapsContext::from_ctx(ctx).map_to_mm(SavedSwapError::InternalError)?;
            let db = swaps_ctx.swap_db().await?;
            let transaction = db.transaction().await?;
            let table = transaction.table::<SavedSwapTable>().await?;

            table
                .replace_item_by_unique_index("uuid", *self.uuid(), &saved_swap_item)
                .await?;
            transaction.wait_for_complete().await?;
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use crate::mm2::lp_swap::swap_db::{ItemId, SavedSwapTable};
    use crate::mm2::lp_swap::SwapsContext;
    use common::mm_ctx::MmCtxBuilder;
    use common::new_uuid;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    async fn get_all_items(ctx: &MmArc) -> Vec<(ItemId, SavedSwapTable)> {
        let swaps_ctx = SwapsContext::from_ctx(&ctx).unwrap();
        let db = swaps_ctx.swap_db().await.expect("Error getting SwapDb");
        let transaction = db.transaction().await.expect("Error creating transaction");
        let table = transaction
            .table::<SavedSwapTable>()
            .await
            .expect("Error opening table");
        table.get_all_items().await.expect("Error getting items")
    }

    #[wasm_bindgen_test]
    async fn test_saved_swap_table() {
        let ctx = MmCtxBuilder::new().with_test_db_namespace().into_mm_arc();

        let saved_swap_str = r#"{"type":"Maker","error_events":["StartFailed","NegotiateFailed","TakerFeeValidateFailed","MakerPaymentTransactionFailed","MakerPaymentDataSendFailed","TakerPaymentValidateFailed","TakerPaymentSpendFailed","TakerPaymentSpendConfirmFailed","MakerPaymentRefunded","MakerPaymentRefundFailed"],"events":[{"event":{"data":{"lock_duration":7800,"maker_amount":"3.54932734","maker_coin":"KMD","maker_coin_start_block":1452970,"maker_payment_confirmations":1,"maker_payment_lock":1563759539,"my_persistent_pub":"031bb83b58ec130e28e0a6d5d2acf2eb01b0d3f1670e021d47d31db8a858219da8","secret":"e1c9bd12a83f810813dc078ac398069b63d56bf1e94657def995c43cd1975302","started_at":1563743939,"taker":"101ace6b08605b9424b0582b5cce044b70a3c8d8d10cb2965e039b0967ae92b9","taker_amount":"0.02004833998671660000000000","taker_coin":"ETH","taker_coin_start_block":8196380,"taker_payment_confirmations":1,"uuid":"3447b727-fe93-4357-8e5a-8cf2699b7e86"},"type":"Started"},"timestamp":1563743939211},{"event":{"data":{"taker_payment_locktime":1563751737,"taker_pubkey":"03101ace6b08605b9424b0582b5cce044b70a3c8d8d10cb2965e039b0967ae92b9"},"type":"Negotiated"},"timestamp":1563743979835},{"event":{"data":{"tx_hash":"a59203eb2328827de00bed699a29389792906e4f39fdea145eb40dc6b3821bd6","tx_hex":"f8690284ee6b280082520894d8997941dd1346e9231118d5685d866294f59e5b865af3107a4000801ca0743d2b7c9fad65805d882179062012261be328d7628ae12ee08eff8d7657d993a07eecbd051f49d35279416778faa4664962726d516ce65e18755c9b9406a9c2fd"},"type":"TakerFeeValidated"},"timestamp":1563744052878},{"event":{"data":{"error":"lp_swap:1888] eth:654] RPC error: Error { code: ServerError(-32010), message: \"Transaction with the same hash was already imported.\", data: None }"},"type":"MakerPaymentTransactionFailed"},"timestamp":1563744118577},{"event":{"type":"Finished"},"timestamp":1563763243350}],"success_events":["Started","Negotiated","TakerFeeValidated","MakerPaymentSent","TakerPaymentReceived","TakerPaymentWaitConfirmStarted","TakerPaymentValidatedAndConfirmed","TakerPaymentSpent","TakerPaymentSpendConfirmStarted","TakerPaymentSpendConfirmed","TakerPaymentSpendConfirmStarted","TakerPaymentSpendConfirmed","Finished"],"uuid":"3447b727-fe93-4357-8e5a-8cf2699b7e86"}"#;
        let mut saved_swap: SavedSwap = json::from_str(saved_swap_str).unwrap();
        let first_saved_item = SavedSwapTable {
            uuid: *saved_swap.uuid(),
            saved_swap: json::to_value(&saved_swap).unwrap(),
        };

        saved_swap.save_to_db(&ctx).await.expect("!save_to_db");

        let first_item_id = {
            let items = get_all_items(&ctx).await;
            assert_eq!(items.len(), 1);
            let (first_item_id, item) = items.into_iter().next().unwrap();
            assert_eq!(item, first_saved_item);
            first_item_id
        };

        match saved_swap {
            SavedSwap::Maker(ref mut maker_saved_swap) => maker_saved_swap.hide_secret(),
            _ => panic!(),
        }

        let second_saved_item = SavedSwapTable {
            uuid: *saved_swap.uuid(),
            saved_swap: json::to_value(&saved_swap).unwrap(),
        };
        assert_ne!(first_saved_item, second_saved_item);

        saved_swap.save_to_db(&ctx).await.expect("!save_to_db");

        {
            let items = get_all_items(&ctx).await;
            assert_eq!(items.len(), 1);
            let (second_item_id, item) = items.into_iter().next().unwrap();
            assert_eq!(first_item_id, second_item_id);
            assert_eq!(item, second_saved_item);
        }

        let actual_saved_swap = SavedSwap::load_my_swap_from_db(&ctx, *saved_swap.uuid())
            .await
            .expect("!load_from_db")
            .expect("Swap not found");
        let actual_saved_item = SavedSwapTable {
            uuid: *actual_saved_swap.uuid(),
            saved_swap: json::to_value(actual_saved_swap).unwrap(),
        };
        assert_eq!(actual_saved_item, second_saved_item);
    }
}
