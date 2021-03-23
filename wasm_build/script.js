// Use ES module import syntax to import functionality from the module
// that we have compiled.
//
// Note that the `default` import is an initialization function which
// will "boot" the module and make it ready to use. Currently browsers
// don't support natively imported WebAssembly as an ES module, but
// eventually the manual initialization won't be required!
import init, {mm2_main, mm2_main_status, LogLevel, Mm2MainErr, MainStatus} from "./deps/pkg/mm2.js";

const LOG_LEVEL = LogLevel.Debug;

// Loads the wasm file, so we use the
// default export to inform it where the wasm file is located on the
// server, and then we wait on the returned promise to wait for the
// wasm to be loaded.
async function init_wasm() {
    try {
        await init();
    } catch (e) {
        alert(`Oops: ${e}`);
    }
}

// TODO add params
async function run_mm2(params) {
    // run an MM2 instance
    try {
        mm2_main(params, handle_log);
    } catch (e) {
        switch (e) {
            case Mm2MainErr.AlreadyRuns:
                alert("MM2 already runs, please wait...");
                return;
            case Mm2MainErr.InvalidParams:
                alert("Invalid config");
                return;
            case Mm2MainErr.NoCoinsInConf:
                alert("No 'coins' field in config");
                return;
            default:
                alert(`Oops: ${e}`);
                return;
        }
    }

    // wait for the MM2 instance is ready
    try {
        await wait_for_ready();
    } catch (e) {
        alert(e);
        return;
    }

    console.info("script.js] Mm2 instance has started");
}

// async function

function handle_log(level, line) {
    switch (level) {
        case LogLevel.Off:
            break;
        case LogLevel.Error:
            console.error(line);
            break;
        case LogLevel.Warn:
            console.warn(line);
            break;
        case LogLevel.Info:
            console.info(line);
            break;
        case LogLevel.Debug:
            console.log(line);
            break;
        case LogLevel.Trace:
            // TODO add why the `console.trace` is not used
            console.debug(line);
            break;
        default:
            console.debug(line);
            break;
    }
}

async function wait_for_ready() {
    for (let i = 0; i < 10; ++i) {
        const status = mm2_main_status();
        switch (status) {
            case MainStatus.NotRunning:
            case MainStatus.NoContext:
            case MainStatus.NoRpc:
                break;
            case MainStatus.RpcIsUp:
                return;
            default:
                throw new Error(`Expected MainStatus, found: ${status}`);
        }

        await sleep(1000);
    }

    throw new Error("Timeout expired waiting for a RocIsUp");
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// The script starts here

init_wasm();

const run_mm2_button = document.getElementById("wid_run_mm2_button");
run_mm2_button.addEventListener('click', async () => {
    const conf = document.getElementById("wid_conf_input").value;
    let params;
    try {
        const conf_js = JSON.parse(conf);
        params = {
            conf: conf_js,
            log_level: LOG_LEVEL,
        };
    } catch (e) {
        alert(`Expected config in JSON, found '${conf}'\nError : ${e}`);
        return;
    }

    await run_mm2(params);
});
