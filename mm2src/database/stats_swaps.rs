use crate::mm2::lp_swap::{stats_maker_swap_dir, stats_taker_swap_dir, SavedSwap};
use common::{log::error, mm_ctx::MmArc, read_dir};
use gstuff::slurp;

const CREATE_STATS_SWAPS_TABLE: &str = "CREATE TABLE IF NOT EXISTS stats_swaps (
    id INTEGER NOT NULL PRIMARY KEY,
    maker_coin VARCHAR(255) NOT NULL,
    taker_coin VARCHAR(255) NOT NULL,
    uuid VARCHAR(255) NOT NULL UNIQUE,
    maker_started_at INTEGER,
    taker_started_at INTEGER,
    maker_amount DECIMAL,
    taker_amount DECIMAL
);";

const INSERT_STATS_SWAP: &str = "INSERT INTO stats_swaps (
    maker_coin,
    taker_coin,
    uuid, 
    maker_started_at, 
    taker_started_at, 
    maker_amount, 
    taker_amount
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

/// Returns SQL statements to initially fill stats_swaps table using existing DB with JSON files
pub fn fill_my_swaps_from_json_statements(ctx: &MmArc) -> Vec<(&'static str, Vec<String>)> {
    let maker_swap_files =
        read_dir(&stats_maker_swap_dir(&ctx)).expect("Reading swaps dir should not fail at this point");
    let mut result = vec![];
    for (_, file) in swap_files {
        let content = slurp(&file).expect("slurp should not fail at this point");
        match json::from_slice::<SavedSwap>(&content) {
            Ok(swap) => {
                if let Some(sql_with_params) = insert_stats_swap_sql(swap) {
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

fn insert_stats_swap_sql(swap: &SavedSwap) -> Option<(&'static str, Vec<String>)> {
    let maker_coin = match swap.maker_coin_ticker() {
        Ok(ticker) => ticker,
        Err(e) => {
            error!("Error {} on maker_coin_ticker ticker of swap {}", e, swap.uuid());
            return None;
        },
    };

    let taker_coin = match swap.taker_coin_ticker() {
        Ok(ticker) => ticker,
        Err(e) => {
            error!("Error {} on taker_coin_ticker ticker of swap {}", e, swap.uuid());
            return None;
        },
    };

    let maker_amount = match swap.maker_coin_ticker() {
        Ok(ticker) => ticker,
        Err(e) => {
            error!("Error {} on maker_coin_ticker ticker of swap {}", e, swap.uuid());
            return None;
        },
    };

    let taker_amount = match swap.taker_coin_ticker() {
        Ok(ticker) => ticker,
        Err(e) => {
            error!("Error {} on taker_coin_ticker ticker of swap {}", e, swap.uuid());
            return None;
        },
    };
}
