use crate::executor::{spawn, Timer};
use crate::log::Tag;
use crate::mm_ctx::{MmArc, MmWeak};
use gstuff::Constructible;
use hdrhistogram::Histogram;
use metrics_core::{Builder, Drain, Key, Label, Observe, Observer};
use metrics_runtime::{observers::JsonBuilder, Receiver};
pub use metrics_runtime::Sink;
use metrics_util::{parse_quantiles, Quantile};
use serde_json::{self as json, Value as Json};
use std::collections::BTreeMap;
use std::fmt::Write as WriteFmt;
use std::slice::Iter;

/// Increment counter if an MmArc is not dropped yet and metrics system is initialized already.
#[macro_export]
macro_rules! mm_counter {
    ($ctx_weak:expr, $name:expr, $value:expr) => {{
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            sink.increment_counter($name, $value);
        }
    }};

    ($ctx_weak:expr, $name:expr, $value:expr, $($labels:tt)*) => {{
        use metrics::labels;
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            let labels = labels!( $($labels)* );
            sink.increment_counter_with_labels($name, $value, labels);
        }
    }};
}

/// Update gauge if an MmArc is not dropped yet and metrics system is initialized already.
#[macro_export]
macro_rules! mm_gauge {
    ($ctx_weak:expr, $name:expr, $value:expr) => {{
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            sink.update_gauge($name, $value);
        }
    }};

    ($ctx_weak:expr, $name:expr, $value:expr, $($labels:tt)*) => {{
        use metrics::labels;
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            let labels = labels!( $($labels)* );
            sink.update_gauge_with_labels($name, $value, labels);
        }
    }};
}

/// Pass new timing value if an MmArc is not dropped yet and metrics system is initialized already.
#[macro_export]
macro_rules! mm_timing {
    ($ctx_weak:expr, $name:expr, $start:expr, $end:expr) => {{
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            sink.record_timing($name, $start, $end);
        }
    }};

    ($ctx_weak:expr, $name:expr, $start:expr, $end:expr, $($labels:tt)*) => {{
        use metrics::labels;
        if let Some(mut sink) = $crate::mm_metrics::try_sink_from_ctx(&$ctx_weak) {
            let labels = labels!( $($labels)* );
            sink.record_timing_with_labels($name, $start, $end, labels);
        }
    }};
}

pub fn try_sink_from_ctx(ctx: &MmWeak) -> Option<Sink> {
    let ctx = MmArc::from_weak(&ctx)?;
    ctx.metrics.sink().ok()
}

/// Default quantiles are "min" and "max"
const QUANTILES: &[f64] = &[0., 1.];

#[derive(Default)]
pub struct Metrics {
    /// `Receiver` receives and collect all the metrics sent through the `sink`.
    /// The `receiver` can be initialized only once time.
    receiver: Constructible<Receiver>,
}

impl Metrics {
    /// Create a new Metrics instance
    pub fn new() -> Metrics {
        Default::default()
    }

    /// If the instance was not initialized yet, create the `receiver` else return an error.
    pub fn init(&self) -> Result<(), String> {
        if self.receiver.is_some() {
            return ERR!("metrics system is initialized already");
        }

        let receiver = try_s!(Receiver::builder().build());
        let _ = try_s!(self.receiver.pin(receiver));

        Ok(())
    }

    /// If the instance was not initialized yet, create the `receiver`
    /// and spawn the metrics recording into the log, else return an error.
    pub fn init_with_dashboard(&self, ctx: MmWeak, record_interval: f64) -> Result<(), String> {
        self.init()?;

        let controller = self.receiver.as_option().unwrap().controller();

        let observer = TagObserver::new(QUANTILES);
        let exporter = TagExporter { ctx, controller, observer };

        spawn(exporter.run(record_interval));

        Ok(())
    }

    /// Handle for sending metric samples.
    pub fn sink(&self) -> Result<Sink, String> {
        Ok(try_s!(self.try_receiver()).sink())
    }

    /// Collect the metrics as Json.
    pub fn collect_json(&self) -> Result<Json, String> {
        let receiver = try_s!(self.try_receiver());
        let controller = receiver.controller();

        // pretty_json is false by default
        let builder = JsonBuilder::new().set_quantiles(QUANTILES);
        let mut observer = builder.build();

        controller.observe(&mut observer);

        let string = observer.drain();

        Ok(try_s!(json::from_str(&string)))
    }

    fn try_receiver(&self) -> Result<&Receiver, String> {
        self.receiver.ok_or("metrics system is not initialized yet".into())
    }
}

#[derive(Eq, PartialEq)]
struct OrdKey(Key);

#[derive(Eq, PartialEq)]
struct OrdLabel<'a>(&'a Label);

impl<'a> Ord for OrdLabel<'a> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let cmp = self.0.key().cmp(other.0.key());
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
        self.0.value().cmp(other.0.value())
    }
}

impl<'a> PartialOrd for OrdLabel<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Deref for OrdKey {
    type Target = Key;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for OrdKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let cmp = self.name().cmp(&other.name());
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }

        let self_ord_labels = self.labels().map(|label| OrdLabel(label));
        let other_ord_labels = other.labels().map(|label| OrdLabel(label));

        // compare the labels of these iterators
        self_ord_labels.cmp(other_ord_labels)
    }
}

impl PartialOrd for OrdKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

enum Integer {
    Signed(i64),
    Unsigned(u64),
}

impl ToString for Integer {
    fn to_string(&self) -> String {
        match self {
            Integer::Signed(x) => format!("{}", x),
            Integer::Unsigned(x) => format!("{}", x),
        }
    }
}

struct PreparedMetric {
    tags: Vec<Tag>,
    message: String,
}

/// Observes metrics and histograms in Tag format.
struct TagObserver {
    /// Supported quantiles like Min, 0.5, 0.8, Max
    quantiles: Vec<Quantile>,
    /// Key-value container of metrics like counters and gauge
    metrics: BTreeMap<OrdKey, Integer>,
    /// Histograms present set of time measurements and analysis over the measurements
    histograms: BTreeMap<OrdKey, Histogram<u64>>,
}

impl TagObserver {
    fn new(quantiles: &[f64]) -> Self {
        TagObserver {
            quantiles: parse_quantiles(quantiles),
            metrics: Default::default(),
            histograms: Default::default(),
        }
    }

    fn prepare_metrics(&self) -> Vec<PreparedMetric> {
        self.metrics.iter()
            .map(|(key, val)| {
                let mut tags = labels_to_tags(key.labels());
                tags.push(Tag { key: key.name().to_string(), val: None });
                let message = format!("metric={}", val.to_string());

                PreparedMetric { tags, message }
            })
            .collect()
    }

    fn prepare_histograms(&self) -> Vec<PreparedMetric> {
        self.histograms.iter()
            .map(|(key, hist)| {
                let mut tags = labels_to_tags(key.labels());
                tags.push(Tag { key: key.name().to_string(), val: None });
                let message = hist_to_message(hist, &self.quantiles);

                PreparedMetric { tags, message }
            })
            .collect()
    }
}

impl Observer for TagObserver {
    fn observe_counter(&mut self, key: Key, value: u64) {
        self.metrics.insert(OrdKey(key), Integer::Unsigned(value));
    }

    fn observe_gauge(&mut self, key: Key, value: i64) {
        self.metrics.insert(OrdKey(key), Integer::Signed(value));
    }

    fn observe_histogram(&mut self, key: Key, values: &[u64]) {
        let entry = self.histograms
            .entry(OrdKey(key))
            .or_insert({
                // Use default significant figures value.
                // For more info on `sigfig` see the Historgam::new_with_bounds().
                let sigfig = 3;
                match Histogram::new(sigfig) {
                    Ok(x) => x,
                    Err(err) => {
                        ERRL!("failed to create histogram: {}", err);
                        // do nothing on error
                        return;
                    }
                }
            });

        for value in values {
            if let Err(err) = entry.record(*value) {
                ERRL!("failed to observe histogram value: {}", err);
            }
        }
    }
}

/// Exports metrics by converting them to a Tag format and log them using log::Status.
struct TagExporter<C>
{
    /// Exporter needs access to the context in order to use the logging methods.
    /// Using a weak reference by default in order to avoid circular references and leaks.
    ctx: MmWeak,
    /// Handle for acquiring metric snapshots.
    controller: C,
    /// Handle for converting snapshots into log.
    observer: TagObserver,
}

impl<C> TagExporter<C>
    where
        C: Observe {
    /// Run endless async loop
    async fn run(mut self, interval: f64) {
        loop {
            Timer::sleep(interval).await;
            self.turn();
        }
    }

    /// Observe metrics and histograms and record it into the log in Tag format
    fn turn(&mut self) {
        let ctx = match MmArc::from_weak(&self.ctx) {
            Some(x) => x,
            // MmCtx is dropped already
            _ => return
        };

        log!(">>>>>>>>>> DEX metrics <<<<<<<<<");

        // Observe means fill the observer's metrics and histograms with actual values
        self.controller.observe(&mut self.observer);

        for PreparedMetric { tags, message } in self.observer.prepare_metrics() {
            ctx.log.log_deref_tags("", tags, &message);
        }

        for PreparedMetric { tags, message } in self.observer.prepare_histograms() {
            ctx.log.log_deref_tags("", tags, &message);
        }

        // don't clear the collected metrics because the keys don't changes often unlike values
    }
}

fn labels_to_tags(labels: Iter<Label>) -> Vec<Tag> {
    labels
        .map(|label| Tag {
            key: label.key().to_string(),
            val: Some(label.value().to_string()),
        })
        .collect()
}

fn hist_to_message(
    hist: &Histogram<u64>,
    quantiles: &[Quantile],
) -> String {
    let mut message = String::with_capacity(256);
    let fmt_quantiles = quantiles
        .iter()
        .map(|quantile| {
            let key = quantile.label().to_string();
            let val = hist.value_at_quantile(quantile.value());
            format!("{}={}", key, val)
        });

    match wite!(message, for q in fmt_quantiles { (q) } separated {' '}) {
        Ok(_) => message,
        Err(err) => {
            log!("Error " (err) " on format hist to message");
            String::new()
        }
    }
}

pub mod transport {
    pub type TransportMetricsBox = Box<dyn TransportMetrics + Send + Sync + 'static>;

    /// Common methods to measure the outgoing requests and incoming responses statistics.
    pub trait TransportMetrics {
        /// Increase outgoing bytes count by `bytes` and increase the sent requests count by 1.
        fn on_outgoing_request(&self, bytes: u64);

        /// Increase incoming bytes count by `bytes` and increase the received responses count by 1.
        fn on_incoming_response(&self, bytes: u64);

        /// Implement the custom clone method similar to impl<T: Clone> Clone for Box<T>.
        /// But the `TransportMetrics` can't implement `Clone` trait cause the trait is used by dynamic dispatch.
        fn clone_into_box(&self) -> TransportMetricsBox;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_on, mm_ctx::MmCtxBuilder};
    use metrics_runtime::Delta;

    #[test]
    fn test_initialization() {
        let ctx = MmCtxBuilder::new().into_mm_arc();
        let metrics = Metrics::new();

        // metrics system is not initialized yet
        assert!(metrics.sink().is_err());

        unwrap!(metrics.init());
        assert!(metrics.init().is_err());
        assert!(metrics.init_with_dashboard(ctx.weak(), 1.).is_err());

        let _ = unwrap!(metrics.sink());
    }

    #[test]
    #[ignore]
    fn test_dashboard() {
        let ctx = MmCtxBuilder::new().into_mm_arc();
        let ctx_weak = ctx.weak();

        ctx.metrics.init_with_dashboard(ctx_weak.clone(), 5.).unwrap();
        let sink = ctx.metrics.sink().unwrap();

        let start = sink.now();

        mm_counter!(ctx_weak, "rpc.traffic.tx", 62, "coin" => "BTC");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 105, "coin"=> "BTC");

        mm_counter!(ctx_weak, "rpc.traffic.tx", 54, "coin" => "KMD");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 158, "coin" => "KMD");

        mm_gauge!(ctx_weak, "rpc.connection.count", 3, "coin" => "KMD");

        let end = sink.now();
        mm_timing!(ctx_weak,
                   "rpc.query.spent_time",
                   start,
                   end,
                   "coin" => "KMD",
                   "method" => "blockchain.transaction.get");

        block_on(async { Timer::sleep(6.).await });

        mm_counter!(ctx_weak, "rpc.traffic.tx", 30, "coin" => "BTC");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 44, "coin" => "BTC");

        mm_gauge!(ctx_weak, "rpc.connection.count", 5, "coin" => "KMD");

        let end = sink.now();
        mm_timing!(ctx_weak,
                   "rpc.query.spent_time",
                   start,
                   end,
                   "coin"=> "KMD",
                   "method"=>"blockchain.transaction.get");

        // measure without labels
        mm_counter!(ctx_weak, "test.counter", 0);
        mm_gauge!(ctx_weak, "test.gauge", 1);
        let end = sink.now();
        mm_timing!(ctx_weak, "test.uptime", start, end);

        block_on(async { Timer::sleep(6.).await });
    }

    #[test]
    fn test_collect_json() {
        fn do_query(sink: &Sink, duration: f64) -> (u64, u64) {
            let start = sink.now();
            block_on(async { Timer::sleep(duration).await });
            let end = sink.now();
            (start, end)
        }

        fn record_to_hist(hist: &mut Histogram<u64>, start_end: (u64, u64)) {
            let delta = start_end.1.delta(start_end.0);
            hist.record(delta).unwrap()
        }

        let ctx = MmCtxBuilder::new().into_mm_arc();
        let ctx_weak = ctx.weak();

        ctx.metrics.init().unwrap();

        let mut sink = ctx.metrics.sink().unwrap();

        mm_counter!(ctx_weak, "rpc.traffic.tx", 62, "coin" => "BTC");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 105, "coin" => "BTC");

        mm_counter!(ctx_weak, "rpc.traffic.tx", 30, "coin" => "BTC");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 44, "coin" => "BTC");

        mm_counter!(ctx_weak, "rpc.traffic.tx", 54, "coin" => "KMD");
        mm_counter!(ctx_weak, "rpc.traffic.rx", 158, "coin" => "KMD");

        mm_gauge!(ctx_weak, "rpc.connection.count", 3, "coin" => "KMD");

        // counter, gauge and timing may be collected also by sink API
        sink.update_gauge_with_labels("rpc.connection.count", 5, &[("coin", "KMD")]);

        let mut expected_hist = Histogram::new(3).unwrap();

        let query_time = do_query(&sink, 0.1);
        record_to_hist(&mut expected_hist, query_time);
        mm_timing!(ctx_weak,
                   "rpc.query.spent_time",
                   query_time.0, // start
                   query_time.1, // end
                   "coin" => "KMD",
                   "method" => "blockchain.transaction.get");

        let query_time = do_query(&sink, 0.2);
        record_to_hist(&mut expected_hist, query_time);
        mm_timing!(ctx_weak,
                   "rpc.query.spent_time",
                   query_time.0, // start
                   query_time.1, // end
                   "coin" => "KMD",
                   "method" => "blockchain.transaction.get");


        let expected = json!({
            "rpc": {
                "traffic": {
                    "tx{coin=\"BTC\"}": 92,
                    "rx{coin=\"BTC\"}": 149,
                    "tx{coin=\"KMD\"}": 54,
                    "rx{coin=\"KMD\"}": 158
                },
                "connection": {
                    "count{coin=\"KMD\"}": 5
                },
                "query": {
                    "spent_time{coin=\"KMD\",method=\"blockchain.transaction.get\"} count": 2,
                    "spent_time{coin=\"KMD\",method=\"blockchain.transaction.get\"} max": expected_hist.value_at_quantile(1.),
                    "spent_time{coin=\"KMD\",method=\"blockchain.transaction.get\"} min": expected_hist.value_at_quantile(0.)
                }
            }
        });

        let actual = ctx.metrics.collect_json().unwrap();
        assert_eq!(actual, expected);
    }
}
