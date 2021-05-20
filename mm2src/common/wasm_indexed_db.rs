use crate::log::{debug, error};
use crate::mm_error::prelude::*;
use crate::{stringify_js_error, WasmUnwrapExt};
use derive_more::Display;
use futures::channel::mpsc;
use futures::{FutureExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{DomException, IdbDatabase, IdbIndexParameters, IdbObjectStore, IdbObjectStoreParameters,
              IdbOpenDbRequest, IdbRequest, IdbTransaction, IdbTransactionMode, IdbVersionChangeEvent};

lazy_static! {
    static ref OPEN_DATABASES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub type OnUpgradeResult<T> = Result<T, MmError<OnUpgradeError>>;
pub type InitDbResult<T> = Result<T, MmError<InitDbError>>;
type Indexes = HashSet<String>;
type Tables = Vec<Box<dyn TableSignature>>;

#[derive(Debug, Display, PartialEq)]
pub enum InitDbError {
    #[display(fmt = "Database {} is open already", db_name)]
    DbIsOpenAlready { db_name: String },
    #[display(fmt = "It seems this browser doesn't support 'IndexedDb': {}", _0)]
    NotSupported(String),
    #[display(fmt = "Invalid Database version: {}", _0)]
    InvalidVersion(String),
    #[display(fmt = "Couldn't open Database: {}", _0)]
    OpeningError(String),
    #[display(fmt = "Type mismatch: expected '{}', found '{}'", expected, found)]
    TypeMismatch { expected: String, found: String },
    #[display(fmt = "Error occurred due to an unexpected state: {:?}", _0)]
    UnexpectedState(String),
    #[display(
        fmt = "Error occurred due to the Database upgrading from {} to {} version: {}",
        old_version,
        new_version,
        error
    )]
    UpgradingError {
        old_version: u32,
        new_version: u32,
        error: OnUpgradeError,
    },
}

#[derive(Debug, Display, PartialEq)]
pub enum OnUpgradeError {
    #[display(fmt = "Error occurred due to creating the '{}' table: {}", table, description)]
    ErrorCreatingTable { table: String, description: String },
    #[display(fmt = "Error occurred due to opening the '{}' table: {}", table, description)]
    ErrorOpeningTable { table: String, description: String },
    #[display(fmt = "Error occurred due to creating the '{}' index: {}", index, description)]
    ErrorCreatingIndex { index: String, description: String },
}

pub struct IndexedDb {
    db: IdbDatabase,
    db_name: String,
    tables: Tables,
}

impl fmt::Debug for IndexedDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tables: Vec<_> = self.tables.iter().map(|table| table.name()).collect();
        write!(f, "IndexedDb {{ db_name: {:?}, tables: {:?} }}", self.db_name, tables)
    }
}

/// Although wasm is currently single-threaded, we can implement the `Send` trait for `IndexedDb`,
/// but it won't be safe when wasm becomes multi-threaded.
unsafe impl Send for IndexedDb {}

impl IndexedDb {
    pub async fn init(db_name: &str, db_version: u32, tables: Tables) -> InitDbResult<Self> {
        Self::check_if_db_is_not_open(db_name)?;

        let window = web_sys::window().expect("!window");
        let indexed_db = match window.indexed_db() {
            Ok(Some(db)) => db,
            Ok(None) => return MmError::err(InitDbError::NotSupported("Unknown error".to_owned())),
            Err(e) => return MmError::err(InitDbError::NotSupported(stringify_js_error(&e))),
        };

        let db_request = match indexed_db.open_with_u32(db_name, db_version) {
            Ok(r) => r,
            Err(e) => return MmError::err(InitDbError::InvalidVersion(stringify_js_error(&e))),
        };
        let (tx, mut rx) = mpsc::channel(1);

        let onerror_closure = construct_open_event_closure(DbOpenEvent::Failed, tx.clone());
        let onsuccess_closure = construct_open_event_closure(DbOpenEvent::Success, tx.clone());
        let onupgradeneeded_closure = construct_open_event_closure(DbOpenEvent::UpgradeNeeded, tx.clone());

        db_request.set_onerror(Some(onerror_closure.as_ref().unchecked_ref()));
        db_request.set_onsuccess(Some(onsuccess_closure.as_ref().unchecked_ref()));
        db_request.set_onupgradeneeded(Some(onupgradeneeded_closure.as_ref().unchecked_ref()));

        while let Some(event) = rx.next().await {
            match event {
                DbOpenEvent::Failed(e) => return MmError::err(InitDbError::OpeningError(stringify_js_error(&e))),
                DbOpenEvent::UpgradeNeeded(event) => Self::on_upgrade_needed(event, &db_request, &tables)?,
                DbOpenEvent::Success(_) => {
                    let db = Self::get_db_from_request(&db_request)?;
                    let db_name = db_name.to_owned();
                    Self::cache_open_db(db_name.clone());

                    return Ok(IndexedDb {
                        db,
                        db_name: db_name.to_owned(),
                        tables,
                    });
                },
            }
        }
        unreachable!("The event channel must not be closed before either 'DbOpenEvent::Success' or 'DbOpenEvent::Failed' is received");
    }

    fn on_upgrade_needed(event: JsValue, db_request: &IdbOpenDbRequest, tables: &Tables) -> InitDbResult<()> {
        let db = Self::get_db_from_request(&db_request)?;
        let transaction = Self::get_transaction_from_request(&db_request)?;

        let version_event = match event.dyn_into::<IdbVersionChangeEvent>() {
            Ok(version) => version,
            Err(e) => {
                return MmError::err(InitDbError::TypeMismatch {
                    expected: "IdbVersionChangeEvent".to_owned(),
                    found: format!("{:?}", e),
                })
            },
        };
        let old_version = version_event.old_version() as u32;
        let new_version = version_event
            .new_version()
            .ok_or(MmError::new(InitDbError::InvalidVersion(
                "Expected a new_version".to_owned(),
            )))? as u32;

        let upgrader = DbUpgrader { db, transaction };
        for table in tables.iter() {
            table
                .on_upgrade_needed(&upgrader, old_version, new_version)
                .mm_err(|error| InitDbError::UpgradingError {
                    old_version,
                    new_version,
                    error,
                })?;
        }
        Ok(())
    }

    fn cache_open_db(db_name: String) {
        let mut open_databases = OPEN_DATABASES.lock().expect_wasm("!OPEN_DATABASES.lock()");
        open_databases.insert(db_name);
    }

    fn check_if_db_is_not_open(db_name: &str) -> InitDbResult<()> {
        let open_databases = OPEN_DATABASES.lock().expect_wasm("!OPEN_DATABASES.lock()");
        if open_databases.contains(db_name) {
            MmError::err(InitDbError::DbIsOpenAlready {
                db_name: db_name.to_owned(),
            })
        } else {
            Ok(())
        }
    }

    fn get_db_from_request(db_request: &IdbOpenDbRequest) -> InitDbResult<IdbDatabase> {
        let db_result = match db_request.result() {
            Ok(res) => res,
            Err(e) => return MmError::err(InitDbError::UnexpectedState(stringify_js_error(&e))),
        };
        db_result.dyn_into::<IdbDatabase>().map_err(|db_result| {
            MmError::new(InitDbError::TypeMismatch {
                expected: "IdbDatabase".to_owned(),
                found: format!("{:?}", db_result),
            })
        })
    }

    fn get_transaction_from_request(db_request: &IdbOpenDbRequest) -> InitDbResult<IdbTransaction> {
        let transaction = match db_request.transaction() {
            Some(res) => res,
            None => {
                return MmError::err(InitDbError::UnexpectedState(
                    "Expected 'IdbOpenDbRequest::transaction'".to_owned(),
                ))
            },
        };
        transaction.dyn_into::<IdbTransaction>().map_err(|transaction| {
            MmError::new(InitDbError::TypeMismatch {
                expected: "IdbTransaction".to_owned(),
                found: format!("{:?}", transaction),
            })
        })
    }
}

impl Drop for IndexedDb {
    fn drop(&mut self) {
        self.db.close();
        let mut open_databases = OPEN_DATABASES.lock().expect_wasm("!OPEN_DATABASES.lock()");
        open_databases.remove(&self.db_name);
    }
}

pub struct DbUpgrader {
    db: IdbDatabase,
    transaction: IdbTransaction,
}

impl DbUpgrader {
    pub fn create_table(&self, table: &str) -> OnUpgradeResult<TableUpgrader> {
        const PRIMARY_KEY: &str = "__id";
        let mut params = IdbObjectStoreParameters::new();
        // We use the [out-of-line](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Basic_Concepts_Behind_IndexedDB#gloss_outofline_key) primary keys.
        params.auto_increment(true).key_path(Some(&JsValue::from(PRIMARY_KEY)));

        match self.db.create_object_store_with_optional_parameters(table, &params) {
            Ok(object_store) => Ok(TableUpgrader { object_store }),
            Err(e) => MmError::err(OnUpgradeError::ErrorCreatingTable {
                table: table.to_owned(),
                description: stringify_js_error(&e),
            }),
        }
    }

    /// Open the `table` if it was created already.
    pub fn open_table(&self, table: &str) -> OnUpgradeResult<TableUpgrader> {
        match self.transaction.object_store(table) {
            Ok(object_store) => Ok(TableUpgrader { object_store }),
            Err(e) => MmError::err(OnUpgradeError::ErrorOpeningTable {
                table: table.to_owned(),
                description: stringify_js_error(&e),
            }),
        }
    }
}

pub struct TableUpgrader {
    object_store: IdbObjectStore,
}

impl TableUpgrader {
    pub fn create_index(&self, index: &str, unique: bool) -> OnUpgradeResult<()> {
        let mut params = IdbIndexParameters::new();
        params.unique(unique);
        self.object_store
            .create_index_with_str_and_optional_parameters(index, index, &params)
            .map(|_| ())
            .map_to_mm(|e| OnUpgradeError::ErrorCreatingIndex {
                index: index.to_owned(),
                description: stringify_js_error(&e),
            })
    }
}

pub trait TableSignature: 'static {
    fn name(&self) -> &'static str;

    fn on_upgrade_needed(&self, upgrader: &DbUpgrader, old_version: u32, new_version: u32) -> OnUpgradeResult<()>;

    fn into_boxed(self) -> Box<dyn TableSignature>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

#[derive(Debug)]
enum DbOpenEvent {
    Failed(JsValue),
    UpgradeNeeded(JsValue),
    Success(JsValue),
}

/// Please note the `Event` type can be `JsValue`. It doesn't lead to a runtime error, because [`JsValue::dyn_into<JsValue>()`] returns itself.
fn construct_open_event_closure<F>(mut f: F, mut event_tx: mpsc::Sender<DbOpenEvent>) -> Closure<dyn FnMut(JsValue)>
where
    F: FnMut(JsValue) -> DbOpenEvent + 'static,
{
    Closure::new(move |event: JsValue| {
        let open_event = f(event);
        if let Err(e) = event_tx.try_send(open_event) {
            let error = e.to_string();
            let event = e.into_inner();
            error!("Error sending DbOpenEvent {:?}: {}", event, error);
        }
    })
}

mod tests {
    use super::*;
    use crate::for_tests::register_wasm_log;
    use crate::log::LogLevel;
    use std::sync::Arc;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    struct TxTable;

    impl TableSignature for TxTable {
        fn name(&self) -> &'static str { "tx_table" }

        fn on_upgrade_needed(&self, upgrader: &DbUpgrader, old_version: u32, _new_version: u32) -> OnUpgradeResult<()> {
            if old_version > 0 {
                // the table is initialized already
                return Ok(());
            }
            let table_upgrader = upgrader.create_table("tx_table")?;
            table_upgrader.create_index("ticker", false)?;
            table_upgrader.create_index("tx_hash", true)
        }
    }

    #[wasm_bindgen_test]
    async fn test_upgrade_needed() {
        const DB_NAME: &str = "TEST_UPGRADE_NEEDED";

        struct UpgradableTable {
            old_new_versions: Arc<Mutex<Option<(u32, u32)>>>,
        }

        impl TableSignature for UpgradableTable {
            fn name(&self) -> &'static str { "upgradable_table" }

            fn on_upgrade_needed(
                &self,
                upgrader: &DbUpgrader,
                old_version: u32,
                new_version: u32,
            ) -> OnUpgradeResult<()> {
                let mut versions = self.old_new_versions.lock().expect_wasm("!old_new_versions.lock()");
                *versions = Some((old_version, new_version));

                match old_version {
                    0 => {
                        let table = upgrader.create_table("upgradable_table")?;
                        table.create_index("first_index", false)?;
                    },
                    1 => {
                        let table = upgrader.open_table("upgradable_table")?;
                        table.create_index("second_index", false)?;
                    },
                    v => panic!("Unexpected old_version: {}", v),
                }
                Ok(())
            }
        }

        async fn init_and_check(version: u32, expected_old_new_versions: Option<(u32, u32)>) -> Result<(), String> {
            let old_new_versions = Arc::new(Mutex::new(None));
            let table = UpgradableTable {
                old_new_versions: old_new_versions.clone(),
            };
            let _db = IndexedDb::init(DB_NAME, version, vec![table.into_boxed()])
                .await
                .map_err(|e| format!("{}", e));
            let actual_versions = old_new_versions.lock().unwrap_wasm();
            if *actual_versions == expected_old_new_versions {
                Ok(())
            } else {
                Err(format!(
                    "Expected {:?}, found {:?}",
                    expected_old_new_versions, actual_versions
                ))
            }
        }

        register_wasm_log(LogLevel::Debug);

        init_and_check(1, Some((0, 1))).await.unwrap_wasm();
        init_and_check(2, Some((1, 2))).await.unwrap_wasm();
        // the same 2 version, `on_upgrade_needed` must not be called
        init_and_check(2, None).await.unwrap_wasm();
    }

    #[wasm_bindgen_test]
    async fn test_open_twice() {
        const DB_NAME: &str = "TEST_OPEN_TWICE";
        const DB_VERSION: u32 = 1;

        register_wasm_log(LogLevel::Debug);

        let tables = vec![TxTable.into_boxed()];
        let _db = IndexedDb::init(DB_NAME, DB_VERSION, tables)
            .await
            .expect_wasm("!IndexedDb::init first time");

        let tables = vec![TxTable.into_boxed()];
        let err = IndexedDb::init(DB_NAME, DB_VERSION + 1, tables)
            .await
            .expect_err_wasm("!IndexedDb::init should have failed");
        assert_eq!(err.into_inner(), InitDbError::DbIsOpenAlready {
            db_name: DB_NAME.to_owned()
        });
    }

    #[wasm_bindgen_test]
    async fn test_open_close_and_open() {
        const DB_NAME: &str = "TEST_OPEN_CLOSE_AND_OPEN";
        const DB_VERSION: u32 = 1;

        register_wasm_log(LogLevel::Debug);

        let tables = vec![TxTable.into_boxed()];
        let db = IndexedDb::init(DB_NAME, DB_VERSION, tables)
            .await
            .expect_wasm("!IndexedDb::init first time");
        drop(db);

        let tables = vec![TxTable.into_boxed()];
        let _db = IndexedDb::init(DB_NAME, DB_VERSION, tables)
            .await
            .expect_wasm("!IndexedDb::init second time");
    }
}
