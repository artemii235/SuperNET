use async_trait::async_trait;
use common::indexed_db::{DbIdentifier, DbInstance, DbUpgrader, IndexedDb, IndexedDbBuilder, OnUpgradeError,
                         OnUpgradeResult, TableSignature};
use common::mm_error::prelude::*;
use derive_more::Display;
use std::ops::Deref;
use uuid::Uuid;

pub use common::indexed_db::{DbTransactionError, DbTransactionResult, InitDbError, InitDbResult, ItemId};
pub use tables::{SavedSwapTable, SwapLockTable};

const DB_NAME: &str = "swap";
const DB_VERSION: u32 = 1;

pub struct SwapDb {
    inner: IndexedDb,
}

#[async_trait]
impl DbInstance for SwapDb {
    fn db_name() -> &'static str { DB_NAME }

    async fn init(db_id: DbIdentifier) -> InitDbResult<Self> {
        let inner = IndexedDbBuilder::new(db_id)
            .with_version(DB_VERSION)
            .with_table::<SwapLockTable>()
            .with_table::<SavedSwapTable>()
            .build()
            .await?;
        Ok(SwapDb { inner })
    }
}

impl Deref for SwapDb {
    type Target = IndexedDb;

    fn deref(&self) -> &Self::Target { &self.inner }
}

pub mod tables {
    use super::*;
    use serde_json::Value as Json;

    #[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
    pub struct SwapLockTable {
        pub uuid: Uuid,
        pub timestamp: u64,
    }

    impl TableSignature for SwapLockTable {
        fn table_name() -> &'static str { "swap_lock" }

        fn on_upgrade_needed(upgrader: &DbUpgrader, old_version: u32, new_version: u32) -> OnUpgradeResult<()> {
            on_upgrade_swap_table_by_uuid_v1(upgrader, old_version, new_version, Self::table_name())
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub struct SavedSwapTable {
        pub uuid: Uuid,
        pub saved_swap: Json,
    }

    impl TableSignature for SavedSwapTable {
        fn table_name() -> &'static str { "saved_swap" }

        fn on_upgrade_needed(upgrader: &DbUpgrader, old_version: u32, new_version: u32) -> OnUpgradeResult<()> {
            on_upgrade_swap_table_by_uuid_v1(upgrader, old_version, new_version, Self::table_name())
        }
    }

    /// [`TableSignature::on_upgrade_needed`] implementation common for the most tables with the only `uuid` unique index.
    fn on_upgrade_swap_table_by_uuid_v1(
        upgrader: &DbUpgrader,
        old_version: u32,
        new_version: u32,
        table_name: &'static str,
    ) -> OnUpgradeResult<()> {
        match (old_version, new_version) {
            (0, 1) => {
                let table = upgrader.create_table(table_name)?;
                table.create_index("uuid", true)?;
            },
            _ => (),
        }
        Ok(())
    }
}
