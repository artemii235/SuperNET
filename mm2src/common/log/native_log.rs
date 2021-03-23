use super::{chunk2log, LevelFilter, LogCallback};
use log::Record;
use log4rs::encode::{pattern, writer::simple};
use log4rs::{append, config};
use std::os::raw::c_char;

const MM_FORMAT: &str = "{d(%d %H:%M:%S)(utc)}, {f}:{L}] {l} {m}";
const DEFAULT_FORMAT: &str = "[{d(%Y-%m-%d %H:%M:%S %Z)(utc)} {h({l})} {M}:{f}:{L}] {m}";
const DEFAULT_LEVEL_FILTER: LogLevel = LogLevel::Info;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LogLevel {
    /// A level lower than all log levels.
    Off = 0,
    /// Corresponds to the `ERROR` log level.
    Error = 1,
    /// Corresponds to the `WARN` log level.
    Warn = 2,
    /// Corresponds to the `INFO` log level.
    Info = 3,
    /// Corresponds to the `DEBUG` log level.
    Debug = 4,
    /// Corresponds to the `TRACE` log level.
    Trace = 5,
}

impl LogLevel {
    pub fn from_env() -> Option<LogLevel> {
        match std::env::var("RUST_LOG").ok()?.to_lowercase().as_str() {
            "off" => Some(LogLevel::Off),
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" => Some(LogLevel::Trace),
            _ => None,
        }
    }
}

pub struct FfiCallback {
    cb_f: extern "C" fn(line: *const c_char),
}

impl FfiCallback {
    pub fn with_ffi_function(callback: extern "C" fn(line: *const c_char)) -> FfiCallback {
        FfiCallback { cb_f: callback }
    }
}

impl LogCallback for FfiCallback {
    fn callback(&mut self, _level: LogLevel, mut line: String) {
        line.push('\0');
        (self.cb_f)(line.as_ptr() as *const c_char)
    }
}

pub struct UnifiedLoggerBuilder {
    console_format: String,
    mm_format: String,
    filter: LevelPolicy,
    console: bool,
    mm_log: bool,
}

impl Default for UnifiedLoggerBuilder {
    fn default() -> UnifiedLoggerBuilder {
        UnifiedLoggerBuilder {
            console_format: DEFAULT_FORMAT.to_owned(),
            mm_format: MM_FORMAT.to_owned(),
            filter: LevelPolicy::Exact(DEFAULT_LEVEL_FILTER),
            console: true,
            mm_log: false,
        }
    }
}

impl UnifiedLoggerBuilder {
    pub fn new() -> UnifiedLoggerBuilder { UnifiedLoggerBuilder::default() }

    pub fn console_format(mut self, console_format: &str) -> UnifiedLoggerBuilder {
        self.console_format = console_format.to_owned();
        self
    }

    pub fn mm_format(mut self, mm_format: &str) -> UnifiedLoggerBuilder {
        self.mm_format = mm_format.to_owned();
        self
    }

    pub fn level_filter(mut self, filter: LogLevel) -> UnifiedLoggerBuilder {
        self.filter = LevelPolicy::Exact(filter);
        self
    }

    pub fn level_filter_from_env_or_default(mut self, default: LogLevel) -> UnifiedLoggerBuilder {
        self.filter = LevelPolicy::FromEnvOrDefault(default);
        self
    }

    pub fn console(mut self, console: bool) -> UnifiedLoggerBuilder {
        self.console = console;
        self
    }

    pub fn mm_log(mut self, mm_log: bool) -> UnifiedLoggerBuilder {
        self.mm_log = mm_log;
        self
    }

    pub fn try_init(self) -> Result<(), String> {
        let mut appenders = Vec::new();
        let level_filter = match self.filter {
            LevelPolicy::Exact(l) => l,
            LevelPolicy::FromEnvOrDefault(default) => LogLevel::from_env().unwrap_or(default),
        };

        if self.mm_log {
            let appender = MmLogAppender::new(&self.mm_format);
            appenders.push(config::Appender::builder().build("mm_log", Box::new(appender)));
        }

        // TODO console appender prints without '/n'
        if self.console {
            let encoder = Box::new(pattern::PatternEncoder::new(&self.console_format));
            let appender = append::console::ConsoleAppender::builder()
                .encoder(encoder)
                .target(append::console::Target::Stdout)
                .build();
            appenders.push(config::Appender::builder().build("console", Box::new(appender)));
        }

        let app_names: Vec<_> = appenders.iter().map(|app| app.name()).collect();
        let root = config::Root::builder()
            .appenders(app_names)
            .build(LevelFilter::from(level_filter));
        let config = try_s!(config::Config::builder().appenders(appenders).build(root));

        try_s!(log4rs::init_config(config));
        Ok(())
    }
}

enum LevelPolicy {
    Exact(LogLevel),
    FromEnvOrDefault(LogLevel),
}

#[derive(Debug)]
struct MmLogAppender {
    pattern: Box<dyn log4rs::encode::Encode>,
}

impl MmLogAppender {
    fn new(pattern: &str) -> MmLogAppender {
        MmLogAppender {
            pattern: Box::new(pattern::PatternEncoder::new(pattern)),
        }
    }
}

impl append::Append for MmLogAppender {
    fn append(&self, record: &Record) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
        let mut buf = Vec::new();
        // TODO use `format_record` instead
        self.pattern.encode(&mut simple::SimpleWriter(&mut buf), record)?;
        let as_string = String::from_utf8(buf).map_err(Box::new)?;
        let level = LogLevel::from(record.metadata().level());
        chunk2log(as_string, level);
        Ok(())
    }

    fn flush(&self) {}
}
