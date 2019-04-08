// The script here will translate some of the C headers necessary for the gradual Rust port into the corresponding Rust files.
// Going to take the *whitelisting* approach, converting just the necessary definitions, in order to keep the builds fast.

// The script is experimentally formatted with `rustfmt`. Probably not going to use `rustfmt` for the rest of the project though.

// Bindgen requirements: https://rust-lang-nursery.github.io/rust-bindgen/requirements.html
//              Windows: https://github.com/rust-lang-nursery/rustup.rs/issues/1003#issuecomment-289825927
// On build.rs: https://doc.rust-lang.org/cargo/reference/build-scripts.html

extern crate bindgen;
extern crate cc;
extern crate duct;
#[macro_use]
extern crate fomat_macros;
extern crate futures;
extern crate futures_cpupool;
extern crate gstuff;
extern crate hyper;
extern crate hyper_rustls;
extern crate num_cpus;
extern crate regex;
#[macro_use]
extern crate unwrap;
extern crate winapi;

use duct::cmd;
use futures::{Future, Stream};
use futures_cpupool::CpuPool;
use gstuff::{last_modified_sec, now_float, slurp};
use hyper_rustls::HttpsConnector;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::iter::empty;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Ongoing (RLS) builds might interfere with a precise time comparison.
const SLIDE: f64 = 60.;

fn bindgen<
    'a,
    TP: AsRef<Path>,
    FI: Iterator<Item = &'a &'a str>,
    TI: Iterator<Item = &'a &'a str>,
    DI: Iterator<Item = &'a &'a str>,
>(
    from: Vec<String>,
    to: TP,
    functions: FI,
    types: TI,
    defines: DI,
) {
    // We'd like to regenerate the bindings whenever the build.rs changes, in case we changed bindgen configuration here.
    let lm_build_rs = unwrap!(last_modified_sec(&"build.rs"), "Can't stat build.rs");

    let to = to.as_ref();

    let mut lm_from = 0f64;
    for header_path in &from {
        lm_from = match last_modified_sec(&header_path) {
            Ok(sec) => lm_from.max(sec),
            Err(err) => panic!("Can't stat the header {:?}: {}", from, err),
        };
    }
    let lm_to = last_modified_sec(&to).unwrap_or(0.);
    if lm_from >= lm_to - SLIDE || lm_build_rs >= lm_to - SLIDE {
        let bindings = {
            // https://docs.rs/bindgen/0.37.*/bindgen/struct.Builder.html
            let mut builder = bindgen::builder();
            for header_path in from {
                builder = builder.header(header_path)
            }
            builder = builder.ctypes_prefix("::libc");
            builder = builder.whitelist_recursively(true);
            builder = builder.layout_tests(false);
            builder = builder.derive_default(true);
            // Currently works for functions but not for variables such as `extern uint32_t DOCKERFLAG`.
            builder = builder.generate_comments(true);
            if cfg!(windows) {
                // Normally we should be checking for `_WIN32`, but `nn_config.h` checks for `WIN32`.
                // (Note that it's okay to have WIN32 defined for 64-bit builds,
                // cf https://github.com/rust-lang-nursery/rust-bindgen/issues/1062#issuecomment-334804738).
                builder = builder.clang_arg("-D WIN32");
            }
            for name in functions {
                builder = builder.whitelist_function(name)
            }
            for name in types {
                builder = builder.whitelist_type(name)
            }
            // Looks like C defines should be whitelisted both on the function and the variable levels.
            for name in defines {
                builder = builder.whitelist_function(name);
                builder = builder.whitelist_var(name)
            }
            match builder.generate() {
                Ok(bindings) => bindings,
                Err(()) => panic!("Error generating the bindings for {:?}", to),
            }
        };

        if let Err(err) = bindings.write_to_file(to) {
            panic!("Error writing to {:?}: {}", to, err)
        }
    }
}

fn generate_bindings() {
    let _ = fs::create_dir("c_headers");

    // NB: curve25519.h and cJSON.h are needed to parse LP_include.h.
    bindgen(
        vec![
            "../../includes/curve25519.h".into(),
            "../../includes/cJSON.h".into(),
            "../../iguana/exchanges/LP_include.h".into(),
        ],
        "c_headers/LP_include.rs",
        [
            // functions
            "cJSON_Parse",
            "cJSON_GetErrorPtr",
            "cJSON_Delete",
            "cJSON_GetArraySize",
            "j64bits",
            "jadd",
            "jarray",
            "jitem",
            "jint",
            "juint",
            "jstr",
            "jdouble",
            "jobj",
            "jprint",
            "free_json",
            "jaddstr",
            "unstringify",
            "jaddnum",
            "LP_NXT_redeems",
            "LPinit",
            "LP_addpeer",
            "LP_peer_recv",
            "LP_initpublicaddr",
            "LP_ports",
            "LP_rpcport",
            "unbuffered_output_support",
            "calc_crc32",
            "LP_userpass",
            "LP_mutex_init",
            "LP_tradebots_timeslice",
            "stats_JSON",
            "LP_priceinfofind",
            "prices_loop",
            "LP_portfolio",
            "LP_coinadd_",
            "LP_priceinfoadd",
            "LP_dPoW_request",
            "LP_conflicts_find",
            "LP_coinjson",
            "LP_portfolio_trade",
            "LP_portfolio_order",
            "LP_pricesparse",
            "LP_ticker",
            "LP_queuecommand",
            "LP_CMCbtcprice",
            "LP_fundvalue",
            "LP_coinsearch",
            "LP_instantdex_deposit",
            "LP_mypriceset",
            "LP_pricepings",
            "LP_autopriceset",
            "LP_alicequery_clear",
            "LP_txfees",
            "LP_address_minmax",
            "LP_fomoprice",
            "LP_quoteinfoinit",
            "LP_quotedestinfo",
            "gen_quote_uuid",
            "decode_hex",
            "LP_aliceid_calc",
            "LP_rand",
            "LP_query",
            "LP_quotejson",
            "LP_mpnet_send",
            "LP_recent_swaps",
            "LP_address",
            "LP_address_utxo_ptrs",
            "LP_command_process",
            "LP_balances",
            "LP_KMDvalue",
            "LP_quoteparse",
            "LP_requestinit",
            "LP_tradecommand_log",
            "bits256_str", // cf. `impl fmt::Display for bits256`
            "vcalc_sha256",
            "calc_rmd160_sha256",
            "bitcoin_address",
            "bitcoin_pubkey33",
            "LP_alice_eligible",
            "LP_quotecmp",
            "LP_instantdex_proofcheck",
            "LP_myprice",
            "LP_pricecache",
            "LP_pricevalid",
            "LP_pubkeyadd",
            "LP_pubkeyfind",
            "LP_pubkey_sigcheck",
            "LP_aliceid",
            "LP_quotereceived",
            "LP_dynamictrust",
            "LP_kmdvalue",
            "LP_trades_alicevalidate",
            "LP_failedmsg",
            "LP_quote_validate",
            "LP_availableset",
            "LP_tradebot_pauseall",
            "LP_portfolio_reset",
            "LP_priceinfos_clear",
            "LP_privkeycalc",
            "LP_privkey_updates",
            "LP_privkey_init",
            "LP_privkey",
            "LP_importaddress",
            "LP_otheraddress",
            "LP_swapsfp_update",
            "LP_unavailableset",
            "LP_trades_pricevalidate",
            "LP_allocated",
            "LP_basesatoshis",
            "LP_trades_bobprice",
            "LP_RTmetrics_blacklisted",
            "LP_getheight",
            "LP_reservation_check",
            "LP_nanobind",
            "LP_instantdex_txids",
            "LP_pendswap_add",
            "LP_price_sig",
            "LP_coin_curl_init",
            "LP_postprice_recv",
        ]
        .iter(),
        // types
        [
            "_bits256",
            "cJSON",
            "iguana_info",
            "LP_utxoinfo",
            "electrum_info",
            "LP_trade",
            "LP_swap_remember",
        ]
        .iter(),
        [
            // defines
            "bitcoind_RPC_inittime",
            "GLOBAL_DBDIR",
            "DOCKERFLAG",
            "USERHOME",
            "LP_profitratio",
            "LP_RPCPORT",
            "LP_MAXPRICEINFOS",
            "LP_showwif",
            "LP_coins",
            "LP_IS_ZCASHPROTOCOL",
            "LP_IS_BITCOINCASH",
            "LP_IS_BITCOINGOLD",
            "BOTS_BONDADDRESS",
            "LP_MIN_TXFEE",
            "IAMLP",
            "LP_gui",
            "LP_canbind",
            "LP_fixed_pairport",
            "LP_myipaddr",
            "LP_myipaddr_from_command_line",
            "LP_autoprices",
            "num_LP_autorefs",
            "LP_STOP_RECEIVED",
            "IPC_ENDPOINT",
            "SPAWN_RPC",
            "LP_autorefs",
            "G",
            "LP_mypubsock",
            "LP_mypullsock",
            "LP_mypeer",
            "RPC_port",
            "LP_ORDERBOOK_DURATION",
            "LP_AUTOTRADE_TIMEOUT",
            "LP_RESERVETIME",
            "Alice_expiration",
            "LP_Alicequery",
            "LP_Alicemaxprice",
            "LP_Alicedestpubkey",
            "GTCorders",
            "LP_QUEUE_COMMAND",
            "LP_RTcount",
            "LP_swapscount",
            "LP_REQUEST",
            "LP_RESERVED",
            "LP_CONNECT",
            "LP_CONNECTED",
            "LP_Alicereserved",
            "dstr",
            "INSTANTDEX_PUBKEY",
        ]
        .iter(),
    );

    bindgen(
        vec!["../../crypto777/OS_portable.h".into()],
        "c_headers/OS_portable.rs",
        [
            // functions
            "OS_init",
            "OS_ensure_directory",
            "OS_compatible_path",
            "calc_ipbits",
        ]
        .iter(),
        empty(), // types
        empty(), // defines
    );
}

/// The build script will usually help us by putting the MarketMaker version
/// into the "MM_VERSION" environment or the "MM_VERSION" file.
/// If neither is there then we're probably in a non-released, local development branch
/// (we're using the "UNKNOWN" version designator then).
/// This function ensures that we have the "MM_VERSION" variable during the build.
fn mm_version() -> String {
    if let Some(have) = option_env!("MM_VERSION") {
        // The variable is already there.
        return have.into();
    }

    // Try to load the variable from the file.
    let mut buf;
    let version = if let Ok(mut file) = fs::File::open("../../MM_VERSION") {
        buf = String::new();
        unwrap!(file.read_to_string(&mut buf), "Can't read from MM_VERSION");
        buf.trim()
    } else {
        "UNKNOWN"
    };
    println!("cargo:rustc-env=MM_VERSION={}", version);
    version.into()
}

/// Formats a vector of command-line arguments into a printable string, for the build log.
fn show_args<'a, I: IntoIterator<Item = &'a String>>(args: I) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    for arg in args {
        if arg.contains(' ') {
            let _ = write!(&mut buf, " \"{}\"", arg);
        } else {
            buf.push(' ');
            buf.push_str(arg)
        }
    }
    buf
}

/// Like the `duct` `cmd!` but also prints the command into the standard error stream.
macro_rules! ecmd {
    ( $program:expr ) => {{
        eprintln!("$ {}", $program);
        cmd($program, empty::<String>())
    }};
    ( $program:expr $(, $arg:expr )* ) => {{
        let mut args: Vec<String> = Vec::new();
        $(
            args.push(Into::<String>::into($arg));
        )*
        eprintln!("$ {}{}", $program, show_args(&args));
        cmd($program, args)
    }};
}

/// See if we have the required libraries.
#[cfg(windows)]
fn windows_requirements() {
    use std::ffi::OsString;
    use std::mem::uninitialized;
    use std::os::windows::ffi::OsStringExt;
    use std::path::Path;
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms724373(v=vs.85).aspx
    use winapi::um::sysinfoapi::GetSystemDirectoryW;

    let system = {
        let mut buf: [u16; 1024] = unsafe { uninitialized() };
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), (buf.len() - 1) as u32) };
        if len <= 0 {
            panic!("!GetSystemDirectoryW")
        }
        let len = len as usize;
        let system = OsString::from_wide(&buf[0..len]);
        Path::new(&system).to_path_buf()
    };
    eprintln!("windows_requirements] System directory is {:?}.", system);

    // `msvcr100.dll` is required by `ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/dll/x64/pthreadVC2.dll`
    let msvcr100 = system.join("msvcr100.dll");
    if !msvcr100.exists() {
        panic! ("msvcr100.dll is missing. \
            You can install it from https://www.microsoft.com/en-us/download/details.aspx?id=14632.");
    }

    // I don't exactly know what DLLs this download installs. Probably "msvcp140...". Might prove useful later.
    //You can install it from https://aka.ms/vs/15/release/vc_redist.x64.exe,
    //see https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
}

#[cfg(not(windows))]
fn windows_requirements() {}

/// SuperNET's root.
fn root() -> PathBuf {
    let common = Path::new(env!("CARGO_MANIFEST_DIR"));
    let super_net = common.join("../..");
    let super_net = match super_net.canonicalize() {
        Ok(p) => p,
        Err(err) => panic!("Can't canonicalize {:?}: {}", super_net, err),
    };
    // On Windows we're getting these "\\?\" paths from canonicalize but they aren't any good for CMake.
    if cfg!(windows) {
        let s = path2s(super_net);
        Path::new(if s.starts_with(r"\\?\") {
            &s[4..]
        } else {
            &s[..]
        })
        .into()
    } else {
        super_net
    }
}

/// Absolute path taken from SuperNET's root + `path`.  
fn rabs(rrel: &str) -> PathBuf {
    root().join(rrel)
}

fn path2s(path: PathBuf) -> String {
    unwrap!(path.to_str(), "Non-stringy path {:?}", path).into()
}

/// Downloads a file, placing it into the given path
/// and sharing the download status on the standard error stream.
///
/// Panics on errors.
///
/// The idea is to replace wget and cURL build dependencies, particularly on Windows.
/// Being able to see the status of the download in the terminal
/// seems more important here than the Future-based parallelism.
fn hget(url: &str, to: PathBuf) {
    // NB: Not using reqwest because I don't see a "hyper-rustls" option in
    // https://github.com/seanmonstar/reqwest/commit/82bc1be89e576b34f09f0f016b0ff38a22820ac5
    use hyper::client::HttpConnector;
    use hyper::header::{CONTENT_LENGTH, LOCATION};
    use hyper::{Body, Client, Request, StatusCode};

    eprintln!("hget] Downloading {} ...", url);

    let https = HttpsConnector::new(1);
    let pool = CpuPool::new(1);
    let client = Arc::new(Client::builder().executor(pool.clone()).build(https));

    fn rec(
        client: Arc<Client<HttpsConnector<HttpConnector>>>,
        request: Request<Body>,
        to: PathBuf,
    ) -> Box<Future<Item = (), Error = ()> + Send> {
        Box::new(client.request(request) .then(move |res| -> Box<Future<Item=(), Error=()> + Send> {
            let res = unwrap!(res);
            let status = res.status();
            if status == StatusCode::FOUND {
                let location = unwrap!(res.headers()[LOCATION].to_str());

                epintln!("hget] Redirected to "
                    if location.len() < 99 {  // 99 here is a numerically convenient screen width.
                        (location) " …"
                    } else {
                        (&location[0..33]) '…' (&location[location.len()-44..location.len()]) " …"
                    }
                );

                let request = unwrap!(Request::builder().uri(location) .body(Body::empty()));
                rec(client, request, to)
            } else if status == StatusCode::OK {
                let mut file = unwrap!(fs::File::create(&to), "hget] Can't create {:?}", to);
                // "cargo build -vv" shares the stderr with the user but buffers it on a line by line basis,
                // meaning that without some dirty terminal tricks we won't be able to share
                // a download status one-liner.
                // The alternative, then, is to share the status updates based on time:
                // If the download was working for five-ten seconds we want to share the status
                // with the user in order not to keep her in the dark.
                let mut received = 0;
                let mut last_status_update = now_float();
                let len: Option<usize> = res.headers().get(CONTENT_LENGTH) .map(|hv| unwrap!(unwrap!(hv.to_str()).parse()));
                Box::new(res.into_body().for_each(move |chunk| {
                    received += chunk.len();
                    if now_float() - last_status_update > 3. {
                        last_status_update = now_float();
                        epintln!(
                            {"hget] Fetched {:.0} KiB", received as f64 / 1024.}
                            if let Some(len) = len {{" out of {:.0}", len as f64 / 1024.}}
                            " …"
                        );
                    }
                    unwrap!(file.write_all(&chunk));
                    Ok(())
                }).then(move |r| -> Result<(), ()> {unwrap!(r); Ok(())}))
            } else {
                panic!("hget] Unknown status: {:?} (headers: {:?}", status, res.headers())
            }
        }))
    }

    let request = unwrap!(Request::builder().uri(url).body(Body::empty()));
    unwrap!(pool.spawn(rec(client, request, to)).wait())
}

/// Loads the `path`, runs `update` on it and saves back the result if it differs.
fn in_place(path: &AsRef<Path>, update: &mut dyn FnMut(Vec<u8>) -> Vec<u8>) {
    let path: &Path = path.as_ref();
    if !path.is_file() {
        return;
    }
    let dir = unwrap!(path.parent());
    let name = unwrap!(unwrap!(path.file_name()).to_str());
    let bulk = slurp(&path);
    if bulk.is_empty() {
        return;
    }
    let updated = update(bulk.clone());
    if bulk != updated {
        let tmp = dir.join(fomat! ((name) ".tmp"));
        {
            let mut file = unwrap!(fs::File::create(&tmp));
            unwrap!(file.write_all(&updated));
        }
        unwrap!(fs::rename(tmp, path))
    }
}

/// Disable specific optional dependencies in CMakeLists.txt.
fn cmake_opt_out(path: &AsRef<Path>, dependencies: &[&str]) {
    in_place(path, &mut |mut clists| {
        for dep in dependencies {
            let exp = unwrap!(regex::bytes::Regex::new(
                &fomat! (r"(?xm) ^ [\t ]*? find_public_dependency\(" (regex::escape (dep)) r"\) $")
            ));
            clists = exp.replace_all(&clists, b"# $0" as &[u8]).into();
        }
        clists
    })
}

/// Downloads and builds libtorrent.
/// Only for UNIX and macOS as of now (Windows needs a different approach to Boost).
fn build_libtorrent() {
    let mmd = root().join("marketmaker_depends");
    let _ = fs::create_dir(&mmd);

    let tgz = mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz");
    if !tgz.exists() {
        hget (
            "https://github.com/arvidn/libtorrent/releases/download/libtorrent-1_2_0_RC/libtorrent-rasterbar-1.2.0-rc.tar.gz",
            tgz.clone()
        );
        assert!(tgz.exists());
    }

    let rasterbar = mmd.join("libtorrent-rasterbar-1.2.0-rc");
    if !rasterbar.exists() {
        unwrap!(
            ecmd!("tar", "-xzf", "libtorrent-rasterbar-1.2.0-rc.tar.gz")
                .dir(&mmd)
                .stdout_to_stderr()
                .run(),
            "Can't unpack libtorrent-rasterbar-1.2.0-rc.tar.gz"
        );
        assert!(rasterbar.exists());

        // NB: Building against OpenSSL imposes additional restrictions on the server configuration,
        // e.g. certain versions of GCC, Boost, libtorrent and OpenSSL will not compile due to the various C++ compatibility issues.
        cmake_opt_out(
            &rasterbar.join("CMakeLists.txt"),
            &["Iconv", "OpenSSL", "LibGcrypt"],
        );
    }

    let build = rasterbar.join("build");
    let _ = fs::create_dir(&build);

    // https://github.com/arvidn/libtorrent/blob/master/docs/building.rst#building-with-cmake
    unwrap!(ecmd!(
        "cmake",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_CXX_STANDARD=11",
        "-DBUILD_SHARED_LIBS=off",
        "-DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=true", // Adds "-fPIC".
        "-Di2p=off",
        if cfg!(target_os = "macos") {
            "-DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2p"
        } else {
            ""
        },
        ".."
    )
    .dir(&build)
    .stdout_to_stderr()
    .unchecked()
    .run()); // NB: Returns an error despite working.
    assert!(
        build.join("Makefile").exists(),
        "Can't cmake: Makefile wasn't generated"
    );

    let lt_flags = build.join("CMakeFiles/torrent-rasterbar.dir/flags.make");
    assert!(lt_flags.exists(), "No flags.make at {:?}", lt_flags);
    let lt_flags = String::from_utf8_lossy(&slurp(&lt_flags)).into_owned();
    eprintln!("libtorrent CMake flags:\n---\n{}---", lt_flags);

    // NB: Shouldn't be too greedy on parallelism here because Rust will be building some other crates in parallel to `common`.
    unwrap!(
        ecmd!("make", "-j2").dir(&build).stdout_to_stderr().run(),
        "Can't make"
    );
}

fn libtorrent() {
    // TODO: If we decide to keep linking with libtorrent then we should distribute the
    //       https://github.com/arvidn/libtorrent/blob/master/LICENSE.

    if cfg!(windows) {
        // NB: The "marketmaker_depends" folder is cached in the AppVeyour build,
        // allowing us to build Boost only once.
        // NB: The Windows build is different from `fn build_libtorrent` in that we're
        // 1) Using the cached marketmaker_depends.
        //    (It's only cached after a successful build, cf. https://www.appveyor.com/docs/build-cache/#saving-cache-for-failed-build).
        // 2) Using ".bat" files and "cmd /c" shims.
        // 3) Using "b2" and pointing it at the Boost sources,
        // as recommended at https://github.com/arvidn/libtorrent/blob/master/docs/building.rst#building-with-bbv2,
        // in hopes of avoiding the otherwise troubling Boost linking concerns.
        //
        // We can try building the Windows libtorrent with CMake.
        // Though as of now having both build systems tested gives as a leeway in case one of them breaks.
        let mmd = root().join("marketmaker_depends");
        let _ = fs::create_dir(&mmd);

        let boost = mmd.join("boost_1_68_0");
        if boost.exists() {
            // Cache maintenance.
            let _ = fs::remove_file(mmd.join("boost_1_68_0.zip"));
            let _ = fs::remove_dir_all(boost.join("doc")); // 80 MiB.
            let _ = fs::remove_dir_all(boost.join("libs")); // 358 MiB, documentation and examples.
            let _ = fs::remove_dir_all(boost.join("more"));
        } else {
            // [Download and] unpack Boost.
            if !mmd.join("boost_1_68_0.zip").exists() {
                hget(
                    "https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.zip",
                    mmd.join("boost_1_68_0.zip.tmp"),
                );
                unwrap!(fs::rename(
                    mmd.join("boost_1_68_0.zip.tmp"),
                    mmd.join("boost_1_68_0.zip")
                ));
            }

            // TODO: Unzip without requiring the user to install unzip.
            unwrap!(
                ecmd!("unzip", "boost_1_68_0.zip")
                    .dir(&mmd)
                    .stdout_to_stderr()
                    .run(),
                "Can't unzip boost. Missing http://gnuwin32.sourceforge.net/packages/unzip.htm ?"
            );
            assert!(boost.exists());
            let _ = fs::remove_file(mmd.join("boost_1_68_0.zip"));
        }

        let b2 = boost.join("b2.exe");
        if !b2.exists() {
            unwrap!(ecmd!("cmd", "/c", "bootstrap.bat")
                .dir(&boost)
                .stdout_to_stderr()
                .run());
            assert!(b2.exists());
        }

        let boost_system = boost.join("stage/lib/libboost_system-vc141-mt-x64-1_68.lib");
        if !boost_system.exists() {
            unwrap!(ecmd!(
                // For some weird reason this particular executable won't start without the "cmd /c"
                // even though some other executables (copied into the same folder) are working NP.
                "cmd",
                "/c",
                "b2.exe",
                "release",
                "toolset=msvc-14.1",
                "address-model=64",
                "link=static",
                "stage",
                "--with-date_time",
                "--with-system"
            )
            .dir(&boost)
            .stdout_to_stderr()
            .unchecked()
            .run());
            assert!(boost_system.exists());
        }

        let rasterbar = mmd.join("libtorrent-rasterbar-1.2.0-rc");
        if rasterbar.exists() {
            // Cache maintenance.
            let _ = fs::remove_file(mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz"));
            let _ = fs::remove_dir_all(rasterbar.join("docs"));
        } else {
            // [Download and] unpack.
            if !mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz").exists() {
                hget (
                    "https://github.com/arvidn/libtorrent/releases/download/libtorrent-1_2_0_RC/libtorrent-rasterbar-1.2.0-rc.tar.gz",
                    mmd.join ("libtorrent-rasterbar-1.2.0-rc.tar.gz.tmp")
                );
                unwrap!(fs::rename(
                    mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz.tmp"),
                    mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz")
                ));
            }

            unwrap!(
                ecmd!("tar", "-xzf", "libtorrent-rasterbar-1.2.0-rc.tar.gz")
                    .dir(&mmd)
                    .stdout_to_stderr()
                    .run(),
                "Can't unpack libtorrent-rasterbar-1.2.0-rc.tar.gz"
            );
            assert!(rasterbar.exists());
            let _ = fs::remove_file(mmd.join("libtorrent-rasterbar-1.2.0-rc.tar.gz"));

            cmake_opt_out(
                &rasterbar.join("CMakeLists.txt"),
                &["Iconv", "OpenSSL", "LibGcrypt"],
            );
        }

        let lt = rasterbar.join(
            r"bin\msvc-14.1\release\address-model-64\link-static\threading-multi\libtorrent.lib",
        );
        if !lt.exists() {
            unwrap!(
                ecmd! (
                    "cmd", "/c",
                    "b2 release toolset=msvc-14.1 address-model=64 link=static dht=on debug-symbols=off"
                )
                .env(
                    "PATH",
                    format!("{};{}", unwrap!(boost.to_str()), unwrap!(env::var("PATH")))
                )
                .env("BOOST_BUILD_PATH", unwrap!(boost.to_str()))
                .env("BOOST_ROOT", unwrap!(boost.to_str()))
                .dir(&rasterbar)
                .stdout_to_stderr()
                .run()
            );
            assert!(lt.exists());
        }

        let lm_dht = unwrap!(last_modified_sec(&"dht.cc"), "Can't stat dht.cc");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libdht.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_dht >= lm_lib - SLIDE {
            cc::Build::new()
                .file("dht.cc")
                .warnings(true)
                .include(rasterbar.join("include"))
                .include(boost)
                // https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt?view=vs-2017
                .define("_WIN32_WINNT", "0x0600")
                // cf. https://stackoverflow.com/questions/4573536/ehsc-vc-eha-synchronous-vs-asynchronous-exception-handling
                .flag("/EHsc")
                // https://stackoverflow.com/questions/7582394/strdup-or-strdup
                .flag("-D_CRT_NONSTDC_NO_DEPRECATE")
                .compile("dht");
        }
        println!("cargo:rustc-link-lib=static=dht");
        println!("cargo:rustc-link-search=native={}", out_dir);

        println!("cargo:rustc-link-lib=static=libtorrent");
        println!(
            "cargo:rustc-link-search=native={}",
            unwrap!(unwrap!(lt.parent()).to_str())
        );

        println!("cargo:rustc-link-lib=static=libboost_system-vc141-mt-x64-1_68");
        println!("cargo:rustc-link-lib=static=libboost_date_time-vc141-mt-x64-1_68");
        println!(
            "cargo:rustc-link-search=native={}",
            unwrap!(unwrap!(boost_system.parent()).to_str())
        );

        println!("cargo:rustc-link-lib=iphlpapi"); // NotifyAddrChange.
    } else if cfg!(target_os = "macos") {
        // NB: Homebrew's version of libtorrent-rasterbar (1.1.10) is currently too old.

        let boost_system_mt = Path::new("/usr/local/lib/libboost_system-mt.a");
        if !boost_system_mt.exists() {
            unwrap!(
                ecmd!("brew", "install", "boost").stdout_to_stderr().run(),
                "Can't brew install boost"
            );
            assert!(boost_system_mt.exists());
        }

        build_libtorrent();
        println!("cargo:rustc-link-lib=static=torrent-rasterbar");
        println!(
            "cargo:rustc-link-search=native={}",
            unwrap!(root()
                .join("marketmaker_depends/libtorrent-rasterbar-1.2.0-rc/build")
                .to_str())
        );
        println!("cargo:rustc-link-lib=c++");
        println!("cargo:rustc-link-lib=boost_system-mt");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=SystemConfiguration");

        let lm_dht = unwrap!(last_modified_sec(&"dht.cc"), "Can't stat dht.cc");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libdht.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_dht >= lm_lib - SLIDE {
            cc::Build::new()
                .file("dht.cc")
                .warnings(true)
                .flag("-std=c++11")
                .include(root().join("marketmaker_depends/libtorrent-rasterbar-1.2.0-rc/include"))
                .include(r"/usr/local/Cellar/boost/1.68.0/include/")
                .compile("dht");
        }
        println!("cargo:rustc-link-lib=static=dht");
        println!("cargo:rustc-link-search=native={}", out_dir);
    } else {
        // Assume UNIX by default.
        if !Path::new("/usr/include/boost").exists()
            && !Path::new("/usr/local/include/boost").exists()
        {
            panic!("Found no Boost in /usr/include/boost or /usr/local/include/boost");
        }

        build_libtorrent();
        println!("cargo:rustc-link-lib=static=torrent-rasterbar");
        println!(
            "cargo:rustc-link-search=native={}",
            unwrap!(root()
                .join("marketmaker_depends/libtorrent-rasterbar-1.2.0-rc/build")
                .to_str())
        );

        let lm_dht = unwrap!(last_modified_sec(&"dht.cc"), "Can't stat dht.cc");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libdht.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_dht >= lm_lib - SLIDE {
            cc::Build::new()
                .file("dht.cc")
                .warnings(true)
                // cf. marketmaker_depends/libtorrent-rasterbar-1.2.0-rc/build/CMakeFiles/torrent-rasterbar.dir/flags.make
                // Mismatch between the libtorrent and the dht.cc flags
                // might produce weird "undefined reference" link errors.
                .flag("-std=c++14")
                .flag("-fPIC")
                .include(root().join("marketmaker_depends/libtorrent-rasterbar-1.2.0-rc/include"))
                .include("/usr/local/include")
                .compile("dht");
        }
        println!("cargo:rustc-link-lib=static=dht");
        println!("cargo:rustc-link-search=native={}", out_dir);

        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=boost_system");
    }
}

/// Build helper C code.
///
/// I think "git clone ... && cargo build" should be enough to start hacking on the Rust code.
///
/// For now we're building the Structured Exception Handling code here,
/// but in the future we might subsume the rest of the C build under build.rs.
fn build_c_code(mm_version: &str) {
    // Link in the Windows-specific crash handling code.

    if cfg!(windows) {
        let lm_seh = unwrap!(last_modified_sec(&"seh.c"), "Can't stat seh.c");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libseh.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_seh >= lm_lib - SLIDE {
            cc::Build::new().file("seh.c").warnings(true).compile("seh");
        }
        println!("cargo:rustc-link-lib=static=seh");
        println!("cargo:rustc-link-search=native={}", out_dir);
    }

    // The MM1 library.

    let _ = fs::create_dir(root().join("build"));
    let _ = fs::create_dir_all(root().join("target/debug"));

    // NB: With "duct 0.11.0" the `let _` variable binding is necessary in order for the build not to fall detached into background.
    let mut cmake_prep_args: Vec<String> = Vec::new();
    if cfg!(windows) {
        // To flush the build problems early we explicitly specify that we want a 64-bit MSVC build and not a GNU or 32-bit one.
        cmake_prep_args.push("-G".into());
        cmake_prep_args.push("Visual Studio 15 2017 Win64".into());
    }
    cmake_prep_args.push("-DETOMIC=ON".into());
    cmake_prep_args.push(format!("-DMM_VERSION={}", mm_version));
    cmake_prep_args.push("-DCMAKE_BUILD_TYPE=Debug".into());
    cmake_prep_args.push("..".into());
    eprintln!("$ cmake{}", show_args(&cmake_prep_args));
    unwrap!(
        cmd("cmake", cmake_prep_args)
            .dir(root().join("build"))
            .stdout_to_stderr() // NB: stderr is visible through "cargo build -vv".
            .run(),
        "!cmake"
    );

    let mut cmake_args: Vec<String> = vec![
        "--build".into(),
        ".".into(),
        "--target".into(),
        "marketmaker-lib".into(),
    ];
    if !cfg!(windows) {
        // Doesn't currently work on AppVeyor.
        cmake_args.push("-j".into());
        cmake_args.push(format!("{}", num_cpus::get()));
    }
    eprintln!("$ cmake{}", show_args(&cmake_args));
    unwrap!(
        cmd("cmake", cmake_args)
            .dir(root().join("build"))
            .stdout_to_stderr() // NB: stderr is visible through "cargo build -vv".
            .run(),
        "!cmake"
    );

    println!("cargo:rustc-link-lib=static=marketmaker-lib");

    // Link in the libraries needed for MM1.

    println!("cargo:rustc-link-lib=static=libcrypto777");
    println!("cargo:rustc-link-lib=static=libjpeg");

    if cfg!(windows) {
        println!("cargo:rustc-link-search=native={}", path2s(rabs("x64")));
        // When building locally with CMake 3.12.0 on Windows the artefacts are created in the "Debug" folders:
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/iguana/exchanges/Debug"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/Debug"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/jpeg/Debug"))
        );
    // https://stackoverflow.com/a/10234077/257568
    //println!(r"cargo:rustc-link-search=native=c:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC\14.14.26428\lib\x64");
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/iguana/exchanges"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/jpeg"))
        );
    }

    println!(
        "cargo:rustc-link-lib={}",
        if cfg!(windows) { "libcurl" } else { "curl" }
    );
    if cfg!(windows) {
        // https://sourceware.org/pthreads-win32/
        // ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/
        println!("cargo:rustc-link-lib=pthreadVC2");
        println!("cargo:rustc-link-lib=mswsock"); // For nanomsg.
        unwrap!(
            fs::copy(
                root().join("x64/pthreadVC2.dll"),
                root().join("target/debug/pthreadVC2.dll")
            ),
            "Can't copy pthreadVC2.dll"
        );
        unwrap!(
            fs::copy(
                root().join("x64/libcurl.dll"),
                root().join("target/debug/libcurl.dll")
            ),
            "Can't copy libcurl.dll"
        );
    } else {
        println!("cargo:rustc-link-lib=crypto");
    }
}

fn main() {
    // NB: `rerun-if-changed` will ALWAYS invoke the build.rs if the target does not exists.
    // cf. https://github.com/rust-lang/cargo/issues/4514#issuecomment-330976605
    //     https://github.com/rust-lang/cargo/issues/4213#issuecomment-310697337
    // `RUST_LOG=cargo::core::compiler::fingerprint cargo build` shows the fingerprit files used.

    // Rebuild when we work with C files.
    println!(
        "rerun-if-changed={}",
        path2s(rabs("iguana/exchanges/etomicswap"))
    );
    println!("rerun-if-changed={}", path2s(rabs("iguana/exchanges")));
    println!("rerun-if-changed={}", path2s(rabs("crypto777")));
    println!("rerun-if-changed={}", path2s(rabs("crypto777/jpeg")));
    println!("rerun-if-changed={}", path2s(rabs("OSlibs/win")));
    println!("rerun-if-changed={}", path2s(rabs("CMakeLists.txt")));

    // NB: Using `rerun-if-env-changed` disables the default dependency heuristics.
    // cf. https://github.com/rust-lang/cargo/issues/4587
    // We should avoid using it for now.

    // Rebuild when we change certain features.
    //println!("rerun-if-env-changed=CARGO_FEATURE_ETOMIC");
    //println!("rerun-if-env-changed=CARGO_FEATURE_NOP");

    windows_requirements();
    libtorrent();
    let mm_version = mm_version();
    build_c_code(&mm_version);
    generate_bindings();
}
