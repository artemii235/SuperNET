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
use crate::mm2::LpMainParams;
use common::executor;
use common::log::{register_callback, LogLevel, WasmCallback};
use gstuff::any_to_str;
use js_sys::Array;
use num_traits::FromPrimitive;
use serde_json::{self as json, Value as Json};
use std::cell::RefCell;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// The MarketMaker2 errors that can be thrown when using the library functions.
#[wasm_bindgen]
#[derive(Primitive)]
pub enum Mm2MainErr {
    AlreadyRuns = 1,
    InvalidParams = 2,
    NoCoinsInConf = 3,
}

impl From<Mm2MainErr> for JsValue {
    fn from(e: Mm2MainErr) -> Self { JsValue::from(e as i32) }
}

#[derive(Deserialize)]
struct MainParams {
    conf: Json,
    log_level: LogLevel,
}

impl From<MainParams> for LpMainParams {
    fn from(orig: MainParams) -> Self { LpMainParams::with_conf(orig.conf).log_filter(orig.log_level) }
}

/// Run the MarketMaker2.
///
/// # Parameters
///
/// The `conf` first argument is a UTF-8 string JSON.
/// The `log_cb` second argument is a JS function with the following signature:
/// ```typescript
/// function(level: number, line: string)
/// ```
///
/// # Usage
///
/// TODO
#[wasm_bindgen]
pub fn mm2_main(params: JsValue, log_cb: js_sys::Function) -> Result<(), JsValue> {
    let params: MainParams = match params.into_serde() {
        Ok(p) => p,
        Err(e) => {
            console_err!("Expected 'MainParams' as the first argument, found {:?}: {}", params, e);
            return Err(Mm2MainErr::InvalidParams.into());
        },
    };
    if params.conf["coins"].is_null() {
        console_err!("Config must contain 'coins' field: {:?}", params.conf);
        return Err(Mm2MainErr::NoCoinsInConf.into());
    }
    let params = LpMainParams::from(params);

    if LP_MAIN_RUNNING.load(Ordering::Relaxed) {
        return Err(Mm2MainErr::AlreadyRuns.into());
    }
    CTX.store(0, Ordering::Relaxed); // Remove the old context ID during restarts.

    register_callback(WasmCallback::with_js_function(log_cb));
    let fut = async move {
        if LP_MAIN_RUNNING.compare_and_swap(false, true, Ordering::Relaxed) {
            console_err!("lp_main already started!");
            return;
        }
        let ctx_cb = |ctx| CTX.store(ctx, Ordering::Relaxed);
        // use futures::FutureExt;
        // match mm2::lp_main(params, &ctx_cb).catch_unwind().await {
        //     Ok(Ok(_)) => console_info!("run_lp_main finished"),
        //     Ok(Err(err)) => console_err!("run_lp_main error: {}", err),
        //     Err(err) => console_err!("run_lp_main panic: {:?}", any_to_str(&*err)),
        // };
        match mm2::lp_main(params, &ctx_cb).await {
            Ok(()) => console_info!("run_lp_main finished"),
            Err(err) => console_err!("run_lp_main error: {}", err),
        };
        LP_MAIN_RUNNING.store(false, Ordering::Relaxed)
    };
    executor::spawn_local(fut);

    Ok(())
}

/// Get the MarketMaker2 status.
#[wasm_bindgen]
pub fn mm2_main_status() -> MainStatus { mm2_status() }
