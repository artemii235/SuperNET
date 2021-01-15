/// The module responsible for working with SQLite database
use common::log::{debug, info};
use common::rusqlite::{Connection, Result, ToSql, NO_PARAMS};

fn get_current_migration(conn: &Connection) -> Result<i64> {
    conn.query_row(
        "SELECT * FROM migration ORDER BY current_migration DESC LIMIT 1;",
        NO_PARAMS,
        |row| Ok(row.get(0)?),
    )
}

pub fn init_and_migrate_db(conn: &Connection) -> Result<()> {
    debug!("Checking the current migration");
    match get_current_migration(conn) {
        Ok(current_migration) => {
            if current_migration >= 1 {
                debug!(
                    "Current migration is {}, skipping the init, trying to migrate",
                    current_migration
                );
                migrate_sqlite_database(conn, current_migration)?;
                return Ok(());
            }
        },
        Err(e) => {
            debug!("Error {} on getting current migration. The database is either empty or corrupted, try to clean it first", e);
            if let Err(e) = conn.execute_batch(
                "DROP TABLE migration;
                    DROP TABLE my_swaps;",
            ) {
                debug!("Error {} on SQLite database cleanup", e);
            }
        },
    };

    debug!("Trying to initialize the SQLite database");

    let init_batch = "BEGIN;
        CREATE TABLE IF NOT EXISTS migration (current_migration INTEGER PRIMARY KEY);
        INSERT INTO migration VALUES (NULL);
        CREATE TABLE IF NOT EXISTS my_swaps (
            id INTEGER PRIMARY KEY,
            my_coin VARCHAR(255) NOT NULL,
            other_coin VARCHAR(255) NOT NULL,
            uuid VARCHAR(255) NOT NULL,
            started_at INTEGER NOT NULL
        );
        COMMIT;";
    conn.execute_batch(init_batch)?;
    migrate_sqlite_database(conn, 1)?;
    debug!("SQLite database initialization is successful");
    Ok(())
}

fn statements_for_migration(current_migration: i64) -> Option<Vec<(String, &'static [&'static dyn ToSql])>> { None }

pub fn migrate_sqlite_database(conn: &Connection, mut current_migration: i64) -> Result<()> {
    info!("migrate_sqlite_database, current migration {}", current_migration);
    let transaction = conn.unchecked_transaction()?;
    while let Some(statements_with_params) = statements_for_migration(current_migration) {
        for (statement, params) in statements_with_params {
            transaction.execute(&statement, params)?;
            transaction.execute("INSERT INTO migration VALUES (NULL);", NO_PARAMS)?;
        }
        current_migration += 1;
    }
    transaction.commit()?;
    info!("migrate_sqlite_database complete, migrated to {}", current_migration);
    Ok(())
}
