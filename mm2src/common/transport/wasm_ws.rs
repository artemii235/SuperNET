use crate::executor::spawn;
use crate::log::{debug, error};
use crate::state_machine::prelude::*;
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, Stream, StreamExt};
use serde_json::{self as json, Value as Json};
use std::sync::Arc;
use wasm_bindgen::closure::WasmClosure;
use wasm_bindgen::convert::FromWasmAbi;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

const NORMAL_CLOSURE_CODE: u16 = 1000;

pub type ConnIdx = usize;

pub type WsOutgoingReceiver = mpsc::Receiver<Json>;
pub type WsOutgoingSender = mpsc::Sender<Json>;

pub type WsIncomingReceiver = mpsc::Receiver<(ConnIdx, WebSocketEvent)>;
pub type WebSocketSender = mpsc::Sender<(ConnIdx, WebSocketEvent)>;

type WsTransportReceiver = mpsc::Receiver<WsTransportEvent>;
type WsTransportSender = mpsc::Sender<WsTransportEvent>;

pub type OnOpenClosure = Closure<dyn FnMut(JsValue)>;
pub type OnCloseClosure = Closure<dyn FnMut(CloseEvent)>;
pub type OnErrorClosure = Closure<dyn FnMut(ErrorEvent)>;
pub type OnMessageClosure = Closure<dyn FnMut(MessageEvent)>;

#[derive(Debug)]
pub enum WebSocketEvent {
    /// A WebSocket connection is established.
    Establish,
    /// A WebSocket connection is being closing and it should not be used anymore.
    Closing,
    /// A WebSocket connection has been closed.
    Closed,
    /// An error has occurred.
    /// Please note some of the errors lead to the connection close.
    Error(WebSocketError),
    /// A message has been received through a WebSocket connection.
    Incoming(Json),
}

#[derive(Debug)]
pub enum WebSocketError {
    OutgoingError { reason: OutgoingError, outgoing: Json },
    UnderlyingError { description: String },
    InvalidIncoming { description: String },
}

#[derive(Debug)]
pub enum OutgoingError {
    IsNotConnected,
    SerializingError(String),
}

// TODO change the error type
pub fn spawn_ws_transport(idx: ConnIdx, url: &str) -> Result<(WsOutgoingSender, WsIncomingReceiver), String> {
    let (ws, closures, ws_transport_rx) = init_ws(url)?;
    let (incoming_tx, incoming_rx) = mpsc::channel(1024);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(1024);

    let internal_event_rx = TransportAndOutgoingListener::new(outgoing_rx, ws_transport_rx);
    let ws_ctx = WsContext {
        idx,
        ws,
        event_tx: incoming_tx,
        internal_event_rx,
    };

    let fut = async move {
        let state_machine: StateMachine<_, ()> = StateMachine::from_ctx(ws_ctx);
        state_machine.run(ConnectingState).await;
        // do any action to move the `closures` into this async block to keep it alive until the `state_machine` finishes
        drop(closures);
    };
    spawn(fut);

    Ok((outgoing_tx, incoming_rx))
}

/// The JS closures that have to be alive until the corresponding WebSocket exists.
struct WsClosures {
    onopen_closure: OnOpenClosure,
    onclose_closure: OnCloseClosure,
    onerror_closure: OnErrorClosure,
    onmessage_closure: OnMessageClosure,
}

/// Although wasm is currently single-threaded, we can implement the `Send` trait for `WsClosures`,
/// but it won't be safe when wasm becomes multi-threaded.
unsafe impl Send for WsClosures {}

fn init_ws(url: &str) -> Result<(WebSocket, WsClosures, WsTransportReceiver), String> {
    // TODO figure out how to extract an error description without stack trace
    let ws = WebSocket::new(url).map_err(|e| format!("{:?}", e))?;

    let (tx, rx) = mpsc::channel(1024);

    let onopen_closure = construct_ws_event_closure(move |_: JsValue| WsTransportEvent::Establish, tx.clone());
    let onclose_closure: Closure<dyn FnMut(CloseEvent)> =
        construct_ws_event_closure(WsTransportEvent::from, tx.clone());
    let onerror_closure: Closure<dyn FnMut(ErrorEvent)> =
        construct_ws_event_closure(WsTransportEvent::from, tx.clone());
    let onmessage_closure = construct_ws_event_closure(
        move |message: MessageEvent| match decode_incoming(message) {
            Ok(response) => WsTransportEvent::Incoming(response),
            Err(e) => WsTransportEvent::Error(e),
        },
        tx.clone(),
    );

    ws.set_onopen(Some(onopen_closure.as_ref().unchecked_ref()));
    ws.set_onclose(Some(onclose_closure.as_ref().unchecked_ref()));
    ws.set_onerror(Some(onerror_closure.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(onmessage_closure.as_ref().unchecked_ref()));

    // keep the closures in the memory until the `ws` exists
    let closures = WsClosures {
        onopen_closure,
        onclose_closure,
        onerror_closure,
        onmessage_closure,
    };

    Ok((ws, closures, rx))
}

struct WsContext {
    idx: ConnIdx,
    ws: WebSocket,
    /// The sender used to send the transport events outside (to the userspace).
    event_tx: WebSocketSender,
    /// The stream of internal events that may come from either WebSocket transport or outside (userspace, such as outgoing messages).
    internal_event_rx: TransportAndOutgoingListener,
}

impl WsContext {
    /// Send the `event` to the corresponding `WebSocketReceiver` instance.
    /// Use [`WsContext::send_if_open`] if an event channel of `WebSocketEvent` may be closed already.
    fn send_event(&mut self, event: WebSocketEvent) {
        if let Err(e) = self.event_tx.try_send((self.idx, event)) {
            let error = e.to_string();
            let event = e.into_inner();
            error!("Error sending WebSocketEvent {:?}: {}", event, error);
        }
    }

    /// Send the `event` to the corresponding `WebSocketReceiver` instance.
    /// Use this method if the channel of `WebSocketEvent` may be closed already
    /// to prevent `error!("Error sending WebSocketEvent)` from being logged.
    fn send_if_open(&mut self, event: WebSocketEvent) {
        // check if the channel is open because [`WsContext::send_event`] would log an error if it is not
        if !self.event_tx.is_closed() {
            self.send_event(event)
        }
    }

    fn close_ws(&self, closure_code: u16) {
        if let Err(e) = self.ws.close_with_code(closure_code) {
            // TODO figure out how to extract an error description without stack trace
            error!("Unexpected error when closing WebSocket: {:?}", e);
        }
    }
}

/// `WsContext` is not thread-safety `Send` because [`WebSocket::ws`] is not `Send` by default.
/// Although wasm is currently single-threaded, we can implement the `Send` trait for `WsContext`,
/// but it won't be safe when wasm becomes multi-threaded.
unsafe impl Send for WsContext {}

struct TransportAndOutgoingListener {
    rx: Box<dyn Stream<Item = TransportAndOutgoingEvent> + Unpin + Send>,
}

impl TransportAndOutgoingListener {
    /// Combine the `outgoing_stream` and `ws_stream` into one stream of the internal events.
    /// `ws_stream` - is a stream of the `WebSocket` events.
    /// `outgoing_stream` - is a stream of the outgoing messages came from outside (userspace).
    fn new(outgoing_stream: WsOutgoingReceiver, ws_stream: WsTransportReceiver) -> Self {
        let end_of_outgoing_rx = futures::future::ready(TransportAndOutgoingEvent::OutgoingStreamClosed).into_stream();
        let outgoing_to_internal = outgoing_stream
            .map(TransportAndOutgoingEvent::OutgoingMessage)
            .chain(end_of_outgoing_rx);

        let end_of_ws_rx = futures::future::ready(TransportAndOutgoingEvent::WsTransportStreamClosed).into_stream();
        let ws_to_internal = ws_stream
            .map(TransportAndOutgoingEvent::WsTransportEvent)
            .chain(end_of_ws_rx);

        // combine the streams into one
        let internal_stream = futures::stream::select(outgoing_to_internal, ws_to_internal);
        TransportAndOutgoingListener {
            rx: Box::new(internal_stream),
        }
    }

    async fn receive_one(&mut self) -> Option<TransportAndOutgoingEvent> { self.rx.next().await }
}

/// The combination of `WsTransportEvent` and `OutgoingEvent`
/// obtained by merging `WsTransportReceiver` and `WsOutgoingReceiver` listeners.
#[derive(Debug)]
enum TransportAndOutgoingEvent {
    /// The corresponding `WsOutgoingReceiver` instance has been dropped.
    OutgoingStreamClosed,
    /// The corresponding `WsTransportReceiver` instance has been dropped.
    WsTransportStreamClosed,
    /// Received an outgoing message. It should be forwarded to `WebSocket`.
    OutgoingMessage(Json),
    /// Received a `WsTransportEvent` event. It might be an incoming message from `WebSocket` or something else.
    WsTransportEvent(WsTransportEvent),
}

#[derive(Debug)]
enum WsTransportEvent {
    Establish,
    Close,
    Error(String),
    Incoming(Json),
}

impl From<CloseEvent> for WsTransportEvent {
    fn from(_: CloseEvent) -> Self { WsTransportEvent::Close }
}

impl From<ErrorEvent> for WsTransportEvent {
    fn from(error: ErrorEvent) -> Self {
        // do not use [`ErrorEvent::message()`] because sometimes it panics
        WsTransportEvent::Error(format!("{:?}", error))
    }
}

struct ConnectingState;
struct OpenState;
struct ClosingState;
struct ClosedState;
struct ClosedUnexpectedlyState {
    desc: &'static str,
}

impl TransitionFrom<ConnectingState> for OpenState {}
impl TransitionFrom<ConnectingState> for ClosingState {}
impl TransitionFrom<ConnectingState> for ClosedState {}
impl TransitionFrom<ConnectingState> for ClosedUnexpectedlyState {}
impl TransitionFrom<OpenState> for ClosingState {}
impl TransitionFrom<OpenState> for ClosedState {}
impl TransitionFrom<OpenState> for ClosedUnexpectedlyState {}
impl TransitionFrom<ClosingState> for ClosedState {}
impl TransitionFrom<ClosingState> for ClosedUnexpectedlyState {}

#[async_trait]
impl LastState for ClosedState {
    type Ctx = WsContext;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> Self::Result {
        debug!("WebSocket idx={} => ClosedState", ctx.idx);
        ctx.send_if_open(WebSocketEvent::Closed)
    }
}

#[async_trait]
impl LastState for ClosedUnexpectedlyState {
    type Ctx = WsContext;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> Self::Result {
        error!("WebSocket idx={} has been closed unexpectedly: {}", ctx.idx, self.desc);
        ctx.send_if_open(WebSocketEvent::Closed)
    }
}

#[async_trait]
impl State for ConnectingState {
    type Ctx = WsContext;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> StateResult<Self::Ctx, Self::Result> {
        debug!("WebSocket idx={} => ConnectingState", ctx.idx);
        match ctx.internal_event_rx.receive_one().await {
            Some(TransportAndOutgoingEvent::WsTransportStreamClosed) => {
                let desc = "WsTransportReceiver is closed, but state is Connecting";
                Self::change_state(ClosedUnexpectedlyState { desc })
            },
            Some(TransportAndOutgoingEvent::OutgoingStreamClosed) => {
                // there is no need to keep the connection, so close the socket and change the state into `GracefulClosingState`
                Self::change_state(ClosingState)
            },
            Some(TransportAndOutgoingEvent::OutgoingMessage(outgoing)) => {
                error!(
                    "Unexpected outgoing message while the socket idx={} is not open",
                    ctx.idx
                );
                let error = WebSocketEvent::Error(WebSocketError::OutgoingError {
                    reason: OutgoingError::IsNotConnected,
                    outgoing,
                });
                ctx.send_event(error);
                Self::change_state(ClosingState)
            },
            Some(TransportAndOutgoingEvent::WsTransportEvent(event)) => {
                match event {
                    WsTransportEvent::Establish => Self::change_state(OpenState),
                    WsTransportEvent::Close => Self::change_state(ClosedState),
                    WsTransportEvent::Error(description) => {
                        // notify the listener
                        let error = WebSocketEvent::Error(WebSocketError::UnderlyingError { description });
                        ctx.send_event(error);

                        // if an underlying error has occurred, it's better to close the socket
                        Self::change_state(ClosingState)
                    },
                    WsTransportEvent::Incoming(incoming) => {
                        error!(
                            "Unexpected incoming message {} while the socket idx={} state is connecting",
                            ctx.idx, incoming
                        );
                        Self::change_state(ClosingState)
                    },
                }
            },
            None => {
                ctx.close_ws(NORMAL_CLOSURE_CODE);
                let desc = "WsTransportReceiver AND WsOutgoingReceiver are closed, but state is Connecting";
                Self::change_state(ClosedUnexpectedlyState { desc })
            },
        }
    }
}

#[async_trait]
impl State for OpenState {
    type Ctx = WsContext;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> StateResult<Self::Ctx, Self::Result> {
        debug!("WebSocket idx={} => OpenState", ctx.idx);
        // notify the listener about the changed state
        ctx.send_event(WebSocketEvent::Establish);

        while let Some(event) = ctx.internal_event_rx.receive_one().await {
            match event {
                TransportAndOutgoingEvent::WsTransportStreamClosed => {
                    let desc = "WsTransportReceiver is closed, but state is Open";
                    return Self::change_state(ClosedUnexpectedlyState { desc });
                },
                TransportAndOutgoingEvent::OutgoingStreamClosed => {
                    // there is no need to keep the connection, so close the socket and change the state into `GracefulClosingState`
                    return Self::change_state(ClosingState);
                },
                TransportAndOutgoingEvent::OutgoingMessage(outgoing) => {
                    if let Err(e) = send_to_ws(&ctx.ws, outgoing) {
                        error!("{:?}", e);
                        ctx.send_event(WebSocketEvent::Error(e));
                    }
                },
                TransportAndOutgoingEvent::WsTransportEvent(event) => match event {
                    WsTransportEvent::Establish => {
                        error!("Unexpected WsTransportEvent: {:?}", WsTransportEvent::Establish);
                    },
                    WsTransportEvent::Close => return Self::change_state(ClosedState),
                    WsTransportEvent::Error(description) => {
                        // notify the listener
                        let error = WebSocketEvent::Error(WebSocketError::UnderlyingError { description });
                        ctx.send_event(error);

                        // if an underlying error has occurred, it's better to close the socket immediately
                        return Self::change_state(ClosingState);
                    },
                    WsTransportEvent::Incoming(incoming) => ctx.send_event(WebSocketEvent::Incoming(incoming)),
                },
            }
        }

        ctx.close_ws(NORMAL_CLOSURE_CODE);
        let desc = "WsTransportReceiver AND WsOutgoingReceiver are closed, but state is Open";
        Self::change_state(ClosedUnexpectedlyState { desc })
    }
}

#[async_trait]
impl State for ClosingState {
    type Ctx = WsContext;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> StateResult<Self::Ctx, Self::Result> {
        debug!("WebScoket idx={} => ClosingState", ctx.idx);
        // notify the listener about the changed state to prevent new outgoing messages
        ctx.send_if_open(WebSocketEvent::Closing);
        ctx.close_ws(NORMAL_CLOSURE_CODE);

        // wait for the `WsTransportEvent::Close` event or another one
        while let Some(event) = ctx.internal_event_rx.receive_one().await {
            match event {
                TransportAndOutgoingEvent::WsTransportStreamClosed => {
                    let desc = "WsTransportReceiver is closed, but state is Closing";
                    return Self::change_state(ClosedUnexpectedlyState { desc });
                },
                TransportAndOutgoingEvent::OutgoingStreamClosed => (), // ignore this event because we are waiting for the connection to close already
                TransportAndOutgoingEvent::OutgoingMessage(outgoing) => {
                    error!(
                        "Unexpected outgoing message while the WebSocket idx={} is closing already",
                        ctx.idx
                    );
                    let error = WebSocketEvent::Error(WebSocketError::OutgoingError {
                        reason: OutgoingError::IsNotConnected,
                        outgoing,
                    });
                    ctx.send_event(error);
                },
                TransportAndOutgoingEvent::WsTransportEvent(event) => match event {
                    WsTransportEvent::Close => return Self::change_state(ClosedState),
                    WsTransportEvent::Error(description) => {
                        // notify the listener
                        let error = WebSocketEvent::Error(WebSocketError::UnderlyingError { description });
                        ctx.send_event(error);
                    },
                    event => error!("Unexpected event: {:?}", event),
                },
            }
        }

        let desc = "WsTransportReceiver AND WsOutgoingReceiver are closed, but state is Closing";
        Self::change_state(ClosedUnexpectedlyState { desc })
    }
}

fn send_to_ws(ws: &WebSocket, outgoing: Json) -> Result<(), WebSocketError> {
    match json::to_string(&outgoing) {
        Ok(req) => ws.send_with_str(&req).map_err(|error| {
            let description = format!("{:?}", error);
            WebSocketError::UnderlyingError { description }
        }),
        Err(e) => {
            let reason = OutgoingError::SerializingError(e.to_string());
            Err(WebSocketError::OutgoingError { reason, outgoing })
        },
    }
}

fn decode_incoming(incoming: MessageEvent) -> Result<Json, String> {
    match incoming.data().dyn_into::<js_sys::JsString>() {
        Ok(txt) => {
            // todo measure
            let txt = String::from(txt);
            json::from_str(&txt).map_err(|e| format!("Error deserializing an incoming payload: {}", e))
        },
        Err(e) => Err(format!("Unknown MessageEvent {:?}", e)),
    }
}

fn construct_ws_event_closure<F, Event>(mut f: F, mut event_tx: WsTransportSender) -> Closure<dyn FnMut(Event)>
where
    F: FnMut(Event) -> WsTransportEvent + 'static,
    Event: FromWasmAbi + 'static,
{
    Closure::new(move |event| {
        let transport_event = f(event);
        if let Err(e) = event_tx.try_send(transport_event) {
            let error = e.to_string();
            let event = e.into_inner();
            error!("Error sending WebSocketEvent {:?}: {}", event, error);
        }
    })
}

mod tests {
    use super::*;
    use crate::block_on;
    use crate::executor::Timer;
    use crate::for_tests::register_wasm_log;
    use crate::log::LogLevel;
    use futures::future::{select, Either};
    use futures::SinkExt;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    async fn wait_for_event(rx: &mut WsIncomingReceiver, seconds: f64) -> Option<(ConnIdx, WebSocketEvent)> {
        let fut = select(rx.next(), Timer::sleep(seconds));
        match fut.await {
            Either::Left((event, _timer)) => event,
            Either::Right(_) => panic!("Timeout expired waiting for a transport event"),
        }
    }

    #[wasm_bindgen_test]
    async fn test_websocket() {
        const CONN_IDX: ConnIdx = 0;
        register_wasm_log(LogLevel::Debug);

        let (mut outgoing_tx, mut incoming_rx) =
            spawn_ws_transport(CONN_IDX, "wss://electrum1.cipig.net:30017").expect("!spawn_ws_transport");

        match wait_for_event(&mut incoming_rx, 5.).await {
            Some((CONN_IDX, WebSocketEvent::Establish)) => (),
            other => panic!("Expected 'Establish' event, found: {:?}", other),
        }

        let get_version = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "server.version",
            "params": ["1.2", "1.4"],
        });
        outgoing_tx.send(get_version).await.expect("!outgoing_tx.send");

        match wait_for_event(&mut incoming_rx, 5.).await {
            Some((CONN_IDX, WebSocketEvent::Incoming(response))) => {
                debug!("Response: {:?}", response);
                assert!(response.get("result").is_some());
            },
            other => panic!("Expected 'Incoming' event, found: {:?}", other),
        }

        drop(outgoing_tx);
        match wait_for_event(&mut incoming_rx, 0.5).await {
            Some((CONN_IDX, WebSocketEvent::Closing)) => (),
            other => panic!("Expected 'Closing' event, found: {:?}", other),
        }
        match wait_for_event(&mut incoming_rx, 0.5).await {
            Some((CONN_IDX, WebSocketEvent::Closed)) => (),
            other => panic!("Expected 'Closed' event, found: {:?}", other),
        }
    }

    #[wasm_bindgen_test]
    async fn test_websocket_unreachable_url() {
        const CONN_IDX: ConnIdx = 1;
        register_wasm_log(LogLevel::Debug);

        // TODO check if outgoing messages are ignored non-open states
        let (_outgoing_tx, mut incoming_rx) =
            spawn_ws_transport(CONN_IDX, "wss://electrum1.cipig.net:10017").expect("!spawn_ws_transport");

        match wait_for_event(&mut incoming_rx, 5.).await {
            Some((CONN_IDX, WebSocketEvent::Error(WebSocketError::UnderlyingError { .. }))) => (),
            other => panic!("Expected 'UnderlyingError', found: {:?}", other),
        }
        match wait_for_event(&mut incoming_rx, 0.5).await {
            Some((CONN_IDX, WebSocketEvent::Closing)) => (),
            other => panic!("Expected 'Closing' event, found: {:?}", other),
        }
        match wait_for_event(&mut incoming_rx, 0.5).await {
            Some((CONN_IDX, WebSocketEvent::Closed)) => (),
            other => panic!("Expected 'Closed' event, found: {:?}", other),
        }
    }

    #[wasm_bindgen_test]
    async fn test_websocket_invalid_url() {
        const CONN_IDX: ConnIdx = 2;
        register_wasm_log(LogLevel::Debug);

        let _error =
            spawn_ws_transport(CONN_IDX, "invalid address").expect_err("!spawn_ws_transport but should be error");
        // TODO print the error when there is a way to extract the error message
        // error!("{}", error)
    }
}
