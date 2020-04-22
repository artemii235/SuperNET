use crate::executor::{spawn, Timer};
use crate::log::Tag;
use crate::mm_ctx::{MmArc, MmWeak};
use hdrhistogram::Histogram;
use metrics::Key;
use metrics_core::{Drain, Builder, Label, Observe, Observer};
use metrics_runtime::{observers::JsonBuilder, Receiver};
pub use metrics_runtime::Sink as MeasureSink;
use metrics_util::{parse_quantiles, Quantile};
use serde_json::{self as json, Value as Json};
use std::collections::BTreeMap;
use std::fmt::Write as WriteFmt;
use std::slice::Iter;

/// Default quantiles are "min" and "max"
const QUANTILES: &[f64] = &[0., 1.];

pub fn init_measurement(ctx: MmWeak, config: Config) -> Result<Measurer, String> {
    let measurer = Measurer::new(ctx, config)?;
    measurer.spawn();
    Ok(measurer)
}

pub struct Config {
    log_interval: f64
}

pub struct Measurer {
    ctx: MmWeak,
    receiver: Receiver,
    config: Config,
}

impl Measurer {
    pub fn new(ctx: MmWeak, config: Config) -> Result<Self, String> {
        let receiver = try_s!(Receiver::builder().build());
        Ok(Self { ctx, receiver, config })
    }

    pub fn sink(&self) -> MeasureSink {
        self.receiver.sink()
    }

    pub fn spawn(&self) {
        let controller = self.receiver.controller();
        let observer = TagObserver::new(QUANTILES);
        let exporter = TagExporter { ctx: self.ctx.clone(), controller, observer };

        spawn(exporter.run(self.config.log_interval))
    }

    pub fn collect_json(&self) -> Result<Json, String> {
        let controller = self.receiver.controller();

        // pretty_json is false by default
        let builder = JsonBuilder::new().set_quantiles(QUANTILES);
        let mut observer = builder.build();

        controller.observe(&mut observer);

        let string = observer.drain();

        Ok(try_s!(json::from_str(&string)))
    }
}

#[derive(Eq, PartialEq)]
struct OrdKey(Key);

impl Ord for OrdKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.name().cmp(&other.0.name())
    }
}

impl PartialOrd for OrdKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.name().partial_cmp(&other.0.name())
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
            .map(|(OrdKey(key), val)| {
                let mut tags = labels_to_tags(key.labels());
                tags.push(Tag { key: key.name().to_string(), val: None });
                let message = format!("metric={}", val.to_string());

                PreparedMetric { tags, message }
            })
            .collect()
    }

    fn prepare_histograms(&self) -> Vec<PreparedMetric> {
        self.histograms.iter()
            .map(|(OrdKey(key), hist)| {
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

        log!(">>>>>>>>>> DEX metrics");

        // Observe means fill the observer's metrics and histograms with actual values
        self.controller.observe(&mut self.observer);

        for PreparedMetric { tags, message } in self.observer.prepare_metrics() {
            ctx.log.log_deref_tags("", tags, &message);
        }

        for PreparedMetric { tags, message } in self.observer.prepare_histograms() {
            ctx.log.log_deref_tags("", tags, &message);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_on, mm_ctx::MmCtxBuilder};
    use metrics_runtime::Delta;

    #[test]
    #[ignore]
    fn test_measure() {
        let ctx = MmCtxBuilder::new().into_mm_arc();
        let config = Config { log_interval: 5. };

        let measurer = init_measurement(ctx.weak(), config).unwrap();

        let mut sink = measurer.sink();

        sink.increment_counter_with_labels("rpc.traffic.tx", 62, &[("coin", "BTC")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 105, &[("coin", "BTC")]);

        sink.increment_counter_with_labels("rpc.traffic.tx", 54, &[("coin", "KMD")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 158, &[("coin", "KMD")]);

        sink.update_gauge_with_labels("rpc.connection.count", 3, &[("coin", "KMD")]);

        sink.record_timing_with_labels("rpc.query.spent_time",
                                       sink.now(),
                                       sink.now(),
                                       &[("coin", "KMD"), ("method", "blockchain.transaction.get")]);

        block_on(async { Timer::sleep(6.).await });

        sink.increment_counter_with_labels("rpc.traffic.tx", 30, &[("coin", "BTC")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 44, &[("coin", "BTC")]);

        sink.update_gauge_with_labels("rpc.connection.count", 5, &[("coin", "KMD")]);

        sink.record_timing_with_labels("rpc.query.spent_time",
                                       sink.now(),
                                       sink.now(),
                                       &[("coin", "KMD"), ("method", "blockchain.transaction.get")]);

        block_on(async { Timer::sleep(6.).await });
    }

    #[test]
    fn test_collect_json() {
        fn do_query(sink: &MeasureSink, duration: f64) -> (u64, u64) {
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
        let config = Config { log_interval: 5. };

        let measurer = init_measurement(ctx.weak(), config).unwrap();

        let mut sink = measurer.sink();
        sink.increment_counter_with_labels("rpc.traffic.tx", 62, &[("coin", "BTC")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 105, &[("coin", "BTC")]);

        sink.increment_counter_with_labels("rpc.traffic.tx", 30, &[("coin", "BTC")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 44, &[("coin", "BTC")]);

        sink.increment_counter_with_labels("rpc.traffic.tx", 54, &[("coin", "KMD")]);
        sink.increment_counter_with_labels("rpc.traffic.rx", 158, &[("coin", "KMD")]);

        sink.update_gauge_with_labels("rpc.connection.count", 3, &[("coin", "KMD")]);
        sink.update_gauge_with_labels("rpc.connection.count", 5, &[("coin", "KMD")]);

        let mut expected_hist = Histogram::new(3).unwrap();

        let query_time = do_query(&sink, 0.1);
        record_to_hist(&mut expected_hist, query_time);
        sink.record_timing_with_labels("rpc.query.spent_time",
                                       query_time.0,
                                       query_time.1,
                                       &[("coin", "KMD"), ("method", "blockchain.transaction.get")]);

        let query_time = do_query(&sink, 0.2);
        record_to_hist(&mut expected_hist, query_time);
        sink.record_timing_with_labels("rpc.query.spent_time",
                                       query_time.0,
                                       query_time.1,
                                       &[("coin", "KMD"), ("method", "blockchain.transaction.get")]);

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

        let actual = measurer.collect_json().unwrap();
        assert_eq!(actual, expected);
    }
}
