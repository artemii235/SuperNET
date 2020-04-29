use futures01::{Future, Poll};
use common::executor::Timer;
use common::mm_metrics::transport::TransportMetricsBox;
use common::wio::slurp_reqʹ;
use futures::compat::{Compat};
use futures::future::{select, Either};
use gstuff::binprint;
use http::header::HeaderValue;
use jsonrpc_core::{Call, Response};
use serde_json::{Value as Json};
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use web3::{RequestId, Transport};
use web3::error::{Error, ErrorKind};
use web3::helpers::{build_request, to_result_from_output, to_string};

/// Parse bytes RPC response into `Result`.
/// Implementation copied from Web3 HTTP transport
fn single_response<T: Deref<Target = [u8]>>(response: T) -> Result<Json, Error> {
    let response = serde_json::from_slice(&*response).map_err(|e| Error::from(ErrorKind::InvalidResponse(format!("{}", e))))?;

    match response {
        Response::Single(output) => to_result_from_output(output),
        _ => Err(ErrorKind::InvalidResponse("Expected single, got batch.".into()).into()),
    }
}

pub struct Web3Transport {
    id: Arc<AtomicUsize>,
    uris: Vec<http::Uri>,
    metrics: TransportMetricsBox,
}

impl fmt::Debug for Web3Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Web3Transport")
            .field("id", &self.id)
            .field("uris", &self.uris)
            // skip the metrics
            .finish()
    }
}

impl Clone for Web3Transport {
    fn clone(&self) -> Self {
        Web3Transport {
            id: self.id.clone(),
            uris: self.uris.clone(),
            metrics: self.metrics.clone_into_box(),
        }
    }
}

impl Web3Transport {
    pub fn new(urls: Vec<String>, metrics: TransportMetricsBox) -> Result<Self, String> {
        let mut uris = vec![];
        for url in urls.iter() {
            uris.push(try_s!(url.parse()));
        }
        Ok(Web3Transport {
            id: Arc::new(AtomicUsize::new(0)),
            uris,
            metrics,
        })
    }
}

struct SendFuture<T>(T);

impl<T: Future> Future for SendFuture<T> {
    type Item = T::Item;

    type Error = T::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

unsafe impl<T> Send for SendFuture<T> {}
unsafe impl<T> Sync for SendFuture<T> {}

impl Transport for Web3Transport {
    type Out = Box<dyn Future<Item=Json, Error=Error> + Send>;

    fn prepare(&self, method: &str, params: Vec<Json>) -> (RequestId, Call) {
        let id = self.id.fetch_add(1, Ordering::AcqRel);
        let request = build_request(id, method, params);

        (id, request)
    }

    #[cfg(not(feature="w-bindgen"))]
    fn send(&self, _id: RequestId, request: Call) -> Self::Out {
        Box::new(Compat::new(Box::pin(sendʹ(request, self.uris.clone(), self.metrics.clone_into_box()))))
    }

    #[cfg(feature="w-bindgen")]
    fn send(&self, _id: RequestId, request: Call) -> Self::Out {
        use js_sys;
        use js_sys::Promise;
        use wasm_bindgen::prelude::*;
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response as JsResponse};

        let body = to_string(&request);
        self.metrics.on_outgoing_request(body.len());

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.body(Some(&JsValue::from_str(&body)));

        let request = Request::new_with_str_and_init(
            "http://195.201.0.6:8565",
            &opts,
        ).unwrap();

        request
            .headers()
            .set("Accept", "application/json")
            .unwrap();

        request
            .headers()
            .set("Content-Type", "application/json")
            .unwrap();

        let window = web_sys::window().unwrap();
        let request_promise = window.fetch_with_request(&request);
        use web_sys::console;

        let future = JsFuture::from(request_promise);
        let metrics = self.metrics.clone_into_box();
        let res = async move {
            let resp_value = future.await.unwrap();
            assert!(resp_value.is_instance_of::<JsResponse>());
            let resp: JsResponse = resp_value.dyn_into().unwrap();
            let json_value = JsFuture::from(resp.json().unwrap()).await.unwrap();
            let response: Json = json_value.into_serde().unwrap();

            let response = serde_json::to_vec(&response).unwrap();
            metrics.on_incoming_response(response.len());

            single_response(response)
        };
        Box::new(SendFuture(Box::pin(res).compat()))
    }
}

async fn sendʹ(request: Call, uris: Vec<http::Uri>, metrics: TransportMetricsBox) -> Result<Json, Error> {
    let mut errors = Vec::new();
    for uri in uris.iter() {
        let request = to_string(&request);
        metrics.on_outgoing_request(request.len());

        let mut req = http::Request::new(request.clone().into_bytes());
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = uri.clone();
        req.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let timeout = Timer::sleep(60.);
        let req = Box::pin(slurp_reqʹ(req));
        let rc = select(req, timeout).await;
        let res = match rc {
            Either::Left((r, _t)) => r,
            Either::Right((_t, _r)) => {errors.push(ERRL!("timeout")); continue}
        };

        let (status, _headers, body) = match res {
            Ok(r) => r,
            Err(err) => {
                errors.push(err);
                continue
            }
        };

        metrics.on_incoming_response(body.len());

        if !status.is_success() {
            errors.push(ERRL!("!200: {}, {}", status, binprint(&body, b'.')));
            continue
        }

        return single_response(body)
    }
    Err(ErrorKind::Transport(fomat!(
        "request " [request] " failed: "
        for err in errors {(err)} sep {"; "}
    )).into())
}
