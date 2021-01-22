/// The module responsible for working with SQLite database
use crate::mm2::lp_swap::{my_swaps_dir, MyRecentSwapsReq, SavedSwap};
use common::rusqlite::ToSql;
use common::{log::{debug, error, info},
             mm_ctx::MmArc,
             read_dir,
             rusqlite::{Connection, Error, Result, NO_PARAMS}};
use gstuff::slurp;
use serde_json::{self as json};
use sql_builder::SqlBuilder;
use std::convert::TryInto;
use uuid::Uuid;

static MY_SWAPS_TABLE: &str = "my_swaps";
static INSERT_MY_SWAP: &str = "INSERT INTO my_swaps VALUES (NULL, ?1, ?2, ?3, ?4)";
static SELECT_MIGRATION: &str = "SELECT * FROM migration ORDER BY current_migration DESC LIMIT 1;";

fn get_current_migration(conn: &Connection) -> Result<i64> {
    conn.query_row(SELECT_MIGRATION, NO_PARAMS, |row| row.get(0))
}

pub fn init_and_migrate_db(ctx: &MmArc, conn: &Connection) -> Result<()> {
    info!("Checking the current SQLite migration");
    match get_current_migration(conn) {
        Ok(current_migration) => {
            if current_migration >= 1 {
                info!(
                    "Current migration is {}, skipping the init, trying to migrate",
                    current_migration
                );
                migrate_sqlite_database(ctx, conn, current_migration)?;
                return Ok(());
            }
        },
        Err(e) => {
            debug!("Error {} on getting current migration. The database is either empty or corrupted, trying to clean it first", e);
            if let Err(e) = conn.execute_batch(
                "DROP TABLE migration;
                    DROP TABLE my_swaps;",
            ) {
                error!("Error {} on SQLite database cleanup", e);
            }
        },
    };

    info!("Trying to initialize the SQLite database");

    let init_batch = "BEGIN;
        CREATE TABLE IF NOT EXISTS migration (current_migration INTEGER PRIMARY KEY);
        INSERT INTO migration VALUES (NULL);
        CREATE TABLE IF NOT EXISTS my_swaps (
            id INTEGER PRIMARY KEY,
            my_coin VARCHAR(255) NOT NULL,
            other_coin VARCHAR(255) NOT NULL,
            uuid VARCHAR(255) NOT NULL UNIQUE,
            started_at INTEGER NOT NULL
        );
        COMMIT;";
    conn.execute_batch(init_batch)?;
    migrate_sqlite_database(ctx, conn, 1)?;
    info!("SQLite database initialization is successful");
    Ok(())
}

pub fn insert_new_started_swap(
    ctx: &MmArc,
    my_coin: &str,
    other_coin: &str,
    uuid: &str,
    started_at: &str,
) -> Result<()> {
    debug!("Inserting new swap {} to the SQLite database", uuid);
    let conn = ctx
        .sqlite_connection
        .as_option()
        .expect("SQLite connection is not initialized");
    let params = [my_coin, other_coin, uuid, started_at];
    conn.execute(INSERT_MY_SWAP, &params).map(|_| ())
}

fn insert_saved_swap_sql(swap: SavedSwap) -> Option<(&'static str, Vec<String>)> {
    let swap_info = match swap.get_my_info() {
        Some(s) => s,
        // get_my_info returning None means that swap did not even start - so we can keep it away from indexing.
        None => return None,
    };
    let params = vec![
        swap_info.my_coin,
        swap_info.other_coin,
        swap.uuid().to_string(),
        swap_info.started_at.to_string(),
    ];
    Some((INSERT_MY_SWAP, params))
}

fn migration_1(ctx: &MmArc) -> Vec<(&'static str, Vec<String>)> {
    let swap_files = read_dir(&my_swaps_dir(&ctx)).expect("Reading swaps dir should not fail at this point");
    let mut result = vec![];
    for (_, file) in swap_files {
        let content = slurp(&file);
        match json::from_slice::<SavedSwap>(&content) {
            Ok(swap) => {
                if let Some(sql_with_params) = insert_saved_swap_sql(swap) {
                    result.push(sql_with_params);
                }
            },
            Err(e) => error!(
                "Error {} on file {} content {:?} deserialization to SavedSwap",
                e,
                file.display(),
                content
            ),
        }
    }
    result
}

fn statements_for_migration(ctx: &MmArc, current_migration: i64) -> Option<Vec<(&'static str, Vec<String>)>> {
    match current_migration {
        1 => Some(migration_1(ctx)),
        _ => None,
    }
}

pub fn migrate_sqlite_database(ctx: &MmArc, conn: &Connection, mut current_migration: i64) -> Result<()> {
    info!("migrate_sqlite_database, current migration {}", current_migration);
    let transaction = conn.unchecked_transaction()?;
    while let Some(statements_with_params) = statements_for_migration(ctx, current_migration) {
        for (statement, params) in statements_with_params {
            debug!("Executing SQL statement {:?} with params {:?}", statement, params);
            transaction.execute(&statement, params)?;
        }
        transaction.execute("INSERT INTO migration VALUES (NULL);", NO_PARAMS)?;
        current_migration += 1;
    }
    transaction.commit()?;
    info!("migrate_sqlite_database complete, migrated to {}", current_migration);
    Ok(())
}

#[derive(Debug)]
pub enum SelectRecentSwapsUuidsErr {
    Sql(Error),
    Parse(uuid::parser::ParseError),
}

impl std::fmt::Display for SelectRecentSwapsUuidsErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{:?}", self) }
}

impl From<Error> for SelectRecentSwapsUuidsErr {
    fn from(err: Error) -> Self { SelectRecentSwapsUuidsErr::Sql(err) }
}

impl From<uuid::parser::ParseError> for SelectRecentSwapsUuidsErr {
    fn from(err: uuid::parser::ParseError) -> Self { SelectRecentSwapsUuidsErr::Parse(err) }
}

#[derive(Debug, Default)]
pub struct RecentSwapsSelectResult {
    /// UUIDs of swaps matching the query
    uuids: Vec<Uuid>,
    /// Total count of swaps matching the query
    total_count: usize,
    /// The number of skipped UUIDs
    skipped: usize,
}

pub fn select_uuids_for_recent_swaps_req(
    conn: &Connection,
    req: &MyRecentSwapsReq,
) -> Result<RecentSwapsSelectResult, SelectRecentSwapsUuidsErr> {
    let mut query_builder = SqlBuilder::select_from(MY_SWAPS_TABLE);
    let mut params = vec![];
    if let Some(my_coin) = &req.my_coin {
        query_builder.and_where("my_coin = :my_coin");
        params.push((":my_coin", my_coin.clone()));
    }

    if let Some(other_coin) = &req.other_coin {
        query_builder.and_where("other_coin = :other_coin");
        params.push((":other_coin", other_coin.clone()));
    }

    if let Some(from_timestamp) = &req.from_timestamp {
        query_builder.and_where("started_at >= :from_timestamp");
        params.push((":from_timestamp", from_timestamp.to_string()));
    }

    if let Some(to_timestamp) = &req.to_timestamp {
        query_builder.and_where("started_at < :to_timestamp");
        params.push((":to_timestamp", to_timestamp.to_string()));
    }

    let mut count_builder = query_builder.clone();
    count_builder.count("id");

    let count_query = count_builder.sql().expect("SQL query builder should never fail here");
    debug!("Trying to execute SQL query {} with params {:?}", count_query, params);

    let params_as_trait: Vec<_> = params.iter().map(|(key, value)| (*key, value as &dyn ToSql)).collect();
    let total_count: isize = conn.query_row_named(&count_query, params_as_trait.as_slice(), |row| row.get(0))?;
    let total_count = total_count.try_into().expect("COUNT should always be >= 0");
    if total_count == 0 {
        return Ok(RecentSwapsSelectResult::default());
    }

    query_builder.field("uuid");
    query_builder.field("ROW_NUMBER() OVER (ORDER BY started_at DESC) AS NoId");
    query_builder.order_desc("started_at");
    query_builder.limit(req.limit);
    let skipped = match req.page_number {
        Some(page) => (page.get() - 1) * req.limit,
        None => 0,
    };
    query_builder.offset(skipped);

    let uuids_query = query_builder.sql().expect("SQL query builder should never fail here");
    debug!("Trying to execute SQL query {} with params {:?}", uuids_query, params);
    let mut stmt = conn.prepare(&uuids_query)?;
    let uuids = stmt
        .query_map_named(params_as_trait.as_slice(), |row| row.get(0))?
        .collect::<Result<Vec<String>>>()?;
    let uuids: Result<Vec<_>, _> = uuids.into_iter().map(|uuid| uuid.parse()).collect();
    let uuids = uuids?;

    Ok(RecentSwapsSelectResult {
        uuids,
        total_count,
        skipped,
    })
}
