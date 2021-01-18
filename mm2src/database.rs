/// The module responsible for working with SQLite database
use crate::mm2::lp_swap::{my_swaps_dir, SavedSwap};
use common::{log::{debug, error, info},
             mm_ctx::MmArc,
             read_dir,
             rusqlite::{Connection, Result, NO_PARAMS}};
use gstuff::slurp;
use serde_json::{self as json};

fn get_current_migration(conn: &Connection) -> Result<i64> {
    conn.query_row(
        "SELECT * FROM migration ORDER BY current_migration DESC LIMIT 1;",
        NO_PARAMS,
        |row| Ok(row.get(0)?),
    )
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

fn insert_my_swap_sql(swap: SavedSwap) -> Option<(&'static str, Vec<String>)> {
    let sql = "INSERT INTO my_swaps VALUES (NULL, ?1, ?2, ?3, ?4)";
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
    Some((sql, params))
}

fn migration_1(ctx: &MmArc) -> Vec<(&'static str, Vec<String>)> {
    let swap_files = read_dir(&my_swaps_dir(&ctx)).expect("Reading swaps dir should not fail at this point");
    let mut result = vec![];
    for (_, file) in swap_files {
        let content = slurp(&file);
        match json::from_slice::<SavedSwap>(&content) {
            Ok(swap) => {
                if let Some(sql_with_params) = insert_my_swap_sql(swap) {
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
