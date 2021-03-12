//! Some specifics of using the [`wasm_bindgen`] library:
//!
//! # Currently only `Result<T, JsValue>` is allowed
//! [tracking issue]: https://github.com/rustwasm/wasm-bindgen/issues/1004
//!
//! # JavaScript enums do not support methods at all
//! [tracking issue]: https://github.com/rustwasm/wasm-bindgen/issues/1715
//!
//! # WASM is currently single-threaded
//! There is very few types in [`wasm_bindgen`] crate that are `Send` and `Sync`.
//! Although wasm is currently single-threaded and it's possible to create a wrapper type and then implement `Send` and `Sync`,
//! but it won't be safe when wasm becomes multi-threaded.
//! [blogpost]: https://rustwasm.github.io/2018/10/24/multithreading-rust-and-wasm.html

use super::*;
use common::executor;
use gstuff::any_to_str;
use js_sys::Array;
use num_traits::FromPrimitive;
use std::cell::RefCell;
use std::panic::catch_unwind;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

macro_rules! console_err {
    ($($args: tt)+) => {{
        let msg = format!($($args)+);
        let msg = format!("mm2_wasm_lib:{}] {}", line!(), msg);
        web_sys::console::error_1(&JsValue::from(msg));
    }};
}

macro_rules! console_info {
    ($($args: tt)+) => {{
        let msg = format!($($args)+);
        let msg = format!("mm2_wasm_lib:{}] {}", line!(), msg);
        web_sys::console::info_1(&JsValue::from(msg));
    }};
}

/// The MarketMaker2 errors that can be thrown when using the library functions.
#[wasm_bindgen]
#[derive(Primitive)]
pub enum ApiError {
    Mm2AlreadyRuns = 1,
}

/// Try to convert the thrown error into [`ApiError`].
#[wasm_bindgen]
pub fn api_err_from(val: &JsValue) -> Option<ApiError> {
    let err_code: i32 = match val.into_serde() {
        Ok(code) => code,
        Err(e) => {
            console_err!("Expected an error code, found {:?}: {}", val, e);
            return None;
        },
    };
    let res = ApiError::from_i32(err_code);
    if res.is_none() {
        console_err!("Unknown error code {}", err_code);
    }
    res
}

impl From<ApiError> for JsValue {
    fn from(e: ApiError) -> Self { JsValue::from(e as i32) }
}

/// Run the MarketMaker2.
///
/// # Usage
///
/// Please see [`start_executor_poll`] on how to start the MarketMaker2 executor polling.
#[wasm_bindgen]
pub fn mm2_main(conf: String) -> Result<(), JsValue> {
    if LP_MAIN_RUNNING.load(Ordering::Relaxed) {
        return Err(ApiError::Mm2AlreadyRuns.into());
    }
    CTX.store(0, Ordering::Relaxed); // Remove the old context ID during restarts.

    let fut = async move {
        if LP_MAIN_RUNNING.compare_and_swap(false, true, Ordering::Relaxed) {
            console_err!("lp_main already started!");
            return;
        }
        let ctx_cb = |ctx| CTX.store(ctx, Ordering::Relaxed);
        match catch_unwind(move || mm2::run_lp_main(Some(&conf), &ctx_cb)) {
            Ok(Ok(_)) => console_info!("run_lp_main finished"),
            Ok(Err(err)) => console_err!("run_lp_main error: {}", err),
            Err(err) => console_err!("run_lp_main panic: {:?}", any_to_str(&*err)),
        };
        LP_MAIN_RUNNING.store(false, Ordering::Relaxed)
    };
    executor::spawn(fut);

    Ok(())
}

/// Get the MarketMaker2 status.
#[wasm_bindgen]
pub fn mm2_main_status() -> i8 { mm2_status() as i8 }
