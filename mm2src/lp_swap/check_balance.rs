use bigdecimal::BigDecimal;
use coins::{BalanceError, TradePreimageError};
use common::mm_error::prelude::*;
use derive_more::Display;

pub type CheckBalanceResult<T> = Result<T, MmError<CheckBalanceError>>;

// TODO move all check_balance functions here

#[derive(Debug, Display)]
pub enum CheckBalanceError {
    #[display(
        fmt = "Not enough {} for swap: available {}, required at least {}, locked by swaps {:?}",
        coin,
        available,
        required,
        locked_by_swaps
    )]
    NotSufficientBalance {
        coin: String,
        available: BigDecimal,
        required: BigDecimal,
        locked_by_swaps: Option<BigDecimal>,
    },
    #[display(
        fmt = "Not enough base coin {} balance for swap: available {}, required at least {}, locked by swaps {:?}",
        coin,
        available,
        required,
        locked_by_swaps
    )]
    NotSufficientBaseCoinBalance {
        coin: String,
        available: BigDecimal,
        required: BigDecimal,
        locked_by_swaps: Option<BigDecimal>,
    },
    #[display(fmt = "Max volume {} less than minimum transaction amount", volume)]
    MaxVolumeLessThanDust { volume: BigDecimal },
    #[display(fmt = "The volume {} is too small", volume)]
    VolumeIsTooSmall { volume: BigDecimal },
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

impl From<BalanceError> for CheckBalanceError {
    fn from(e: BalanceError) -> Self {
        match e {
            BalanceError::Transport(transport) | BalanceError::InvalidResponse(transport) => {
                CheckBalanceError::Transport(transport)
            },
            BalanceError::Internal(internal) => CheckBalanceError::InternalError(internal),
        }
    }
}

impl CheckBalanceError {
    pub fn not_sufficient_balance(&self) -> bool {
        matches!(self,
            CheckBalanceError::NotSufficientBalance {..}
            | CheckBalanceError::NotSufficientBaseCoinBalance {..}
            | CheckBalanceError::MaxVolumeLessThanDust {..}
        )
    }

    /// Construct [`CheckBalanceError`] from [`coins::TradePreimageError`] using the additional `ticker` argument.
    /// `ticker` is used to identify whether the `NotSufficientBalance` or `NotSufficientBaseCoinBalance` has occurred.
    pub fn from_trade_preimage_error(trade_preimage_err: TradePreimageError, ticker: &str) -> CheckBalanceError {
        match trade_preimage_err {
            TradePreimageError::NotSufficientBalance {
                coin,
                available,
                required,
            } => {
                if coin == ticker {
                    CheckBalanceError::NotSufficientBalance {
                        coin,
                        available,
                        locked_by_swaps: None,
                        required,
                    }
                } else {
                    CheckBalanceError::NotSufficientBaseCoinBalance {
                        coin,
                        available,
                        locked_by_swaps: None,
                        required,
                    }
                }
            },
            TradePreimageError::UpperBoundAmountIsTooSmall { amount } => {
                CheckBalanceError::MaxVolumeLessThanDust { volume: amount }
            },
            TradePreimageError::AmountIsTooSmall { amount } => CheckBalanceError::VolumeIsTooSmall { volume: amount },
            TradePreimageError::Transport(transport) => CheckBalanceError::Transport(transport),
            TradePreimageError::InternalError(internal) => CheckBalanceError::InternalError(internal),
        }
    }
}
