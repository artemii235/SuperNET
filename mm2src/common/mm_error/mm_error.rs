use crate::HttpStatusCode;
use derive_more::Display;
use http::StatusCode;
use itertools::Itertools;
use serde::ser;
use serde::{Serialize, Serializer};
use serde_json::{self as json, Value as Json};
use std::fmt;
use std::panic::Location;

pub mod prelude {
    pub use crate::mm_error::into_mm::IntoMmResult;
    pub use crate::mm_error::into_mm_fut::IntoMmFutureExt;
    pub use crate::mm_error::map_mm_error::MapMmError;
    pub use crate::mm_error::or_mm_error::OrMmError;
    pub use crate::mm_error::{MmError, NotMmError, SerializeErrorType};
}

mod into_mm;
mod into_mm_fut;
mod map_mm_error;
mod or_mm_error;

pub auto trait NotSame {}
pub auto trait NotMmError {}

impl<X> !NotSame for (X, X) {}

impl<E> !NotMmError for MmError<E> {}

/// This is required because an auto trait is not automatically implemented for a non-sized types,
/// e.g for Box<dyn Trait>.
impl<T: ?Sized> NotMmError for Box<T> {}

pub trait SerializeErrorType: Serialize + fmt::Display + NotMmError {}

impl<E> SerializeErrorType for E where E: Serialize + fmt::Display + NotMmError {}

/// The unified error representation tracing an error path.
///
/// # Serialization
///
/// The serialized error consists of the following fields:
/// * `error` - the common error description;
/// * `error_path` - the error path consisting of file names separated by a dot similar to JSON path notation;
///   Example: `rpc.lp_coins.utxo`
/// * `error_trace` - it is a more detailed error path consisting of file and line number pairs separated by ']';
///   Example: `rpc:392] lp_coins:1104] lp_coins:245] utxo:778]`
/// * `error_type` - the string error identifier;
/// * `error_data` - an object containing the error data.
///
/// ## Important
///
/// The error type must be [`flattened`](https://serde.rs/attr-flatten.html) into `error_type` and `error_data` fields.
///
/// Example:
///
/// ```rust
/// #[derive(Display, Serialize)]
//  #[serde(tag = "error_type", content = "error_data")]
//  enum RpcError {
//      InternalError,
//  }
/// ```
#[derive(Debug, Display, Eq, PartialEq)]
#[display(fmt = "{} {}", "trace.formatted()", etype)]
pub struct MmError<E: NotMmError> {
    etype: E,
    trace: Vec<TraceLocation>,
}

/// Track the location whenever `MmError<E2>::from(MmError<E1>)` is called.
impl<E1, E2> From<MmError<E1>> for MmError<E2>
where
    E1: NotMmError,
    E2: From<E1> + NotMmError,
    (E1, E2): NotSame,
{
    #[track_caller]
    fn from(orig: MmError<E1>) -> Self {
        let mut trace = orig.trace;
        trace.push(TraceLocation::from(Location::caller()));
        MmError {
            etype: E2::from(orig.etype),
            trace,
        }
    }
}

/// Track the location whenever `MmError<E2>::from(E1)` is called.
impl<E1, E2> From<E1> for MmError<E2>
where
    E1: NotMmError,
    E2: From<E1> + NotMmError,
{
    #[track_caller]
    fn from(e1: E1) -> Self { MmError::new(E2::from(e1)) }
}

impl<E> Serialize for MmError<E>
where
    E: SerializeErrorType,
{
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ErrorHelper<'a, E> {
            error: String,
            error_path: String,
            error_trace: String,
            /// `etype` will be flatten into `error_type` and `error_data`
            #[serde(flatten)]
            etype: &'a E,
        }

        // check if the `etype` flattens into the `error_type` and `error_data` fields only.
        self.check_serialized_etype::<<S as Serializer>::Error>()?;
        let helper = ErrorHelper {
            error: self.etype.to_string(),
            error_path: self.path(),
            error_trace: self.stack_trace(),
            etype: &self.etype,
        };
        helper.serialize(serializer)
    }
}

impl<E> HttpStatusCode for MmError<E>
where
    E: HttpStatusCode + NotMmError,
{
    fn status_code(&self) -> StatusCode { self.etype.status_code() }
}

impl<E: NotMmError> MmError<E> {
    #[track_caller]
    pub fn new(etype: E) -> MmError<E> {
        let location = TraceLocation::from(Location::caller());
        MmError {
            etype,
            trace: vec![location],
        }
    }

    #[track_caller]
    pub fn err<T>(etype: E) -> Result<T, MmError<E>> { Err(MmError::new(etype)) }

    pub fn get_inner(&self) -> &E { &self.etype }

    pub fn into_inner(self) -> E { self.etype }

    /// Format the [`MmError::trace`] similar to JSON path notation: `mm2.lp_swap.utxo.rpc_client`.
    /// The return path is deduplicated.
    pub fn path(&self) -> String {
        self.trace
            .iter()
            .map(|src| src.file)
            .rev()
            .dedup()
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Format the [`MmError::trace`] similar to stack trace: `mm2:379] lp_swap:21] utxo:1105] rpc_client:39]`.
    pub fn stack_trace(&self) -> String {
        self.trace
            .iter()
            .map(|src| src.formatted())
            .rev()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl<E> MmError<E>
where
    E: SerializeErrorType,
{
    /// Check if the [`MmError::etype`] serialized representation flattens into `error_type` tag and `error_data` content.
    fn check_serialized_etype<SerdeError: ser::Error>(&self) -> Result<(), SerdeError> {
        macro_rules! serde_err {
            ($($arg:tt)*) => {
                SerdeError::custom(ERRL!($($arg)*))
            };
        }

        #[derive(Serialize)]
        struct FlattenStruct<'a, E>(&'a E);

        let js_repr = json::to_value(FlattenStruct(&self.etype)).map_err(|e| serde_err!("{}", e))?;
        let fields = js_repr.as_object().ok_or_else(|| {
            serde_err!("Error type is expected to be an object with 'error_type' and 'error_data' fields")
        })?;

        match fields.get("error_type") {
            Some(Json::String(_)) => (),
            Some(value) => return Err(serde_err!("'error_type' is expected to be a string, found {:?}", value)),
            None => return Err(serde_err!("No 'error_type' field")),
        }

        match fields.len() {
            1 => Ok(()), // the serialized object contains only `error_type`
            2 if fields.contains_key("error_data") => Ok(()),
            _ => {
                let found: Vec<_> = fields.iter().map(|(name, _value)| name).collect();
                Err(serde_err!(
                    "Error type is expected to contain 'error_type' and 'error_data' fields only, found: {:?}",
                    found
                ))
            },
        }
    }
}

pub trait FormattedTrace {
    fn formatted(&self) -> String;
}

/// The location where an error was tracked.
/// The location is formatted like this:
/// ```txt
/// location_file:379]
/// ```
#[derive(Debug, Display, Eq, PartialEq)]
#[display(fmt = "{}:{}]", file, line)]
pub struct TraceLocation {
    file: &'static str,
    line: u32,
}

impl From<&'static Location<'static>> for TraceLocation {
    fn from(location: &'static Location<'static>) -> Self {
        TraceLocation {
            file: gstuff::filename(location.file()),
            line: location.line(),
        }
    }
}

impl FormattedTrace for TraceLocation {
    fn formatted(&self) -> String { self.to_string() }
}

impl TraceLocation {
    pub fn new(file: &'static str, line: u32) -> TraceLocation { TraceLocation { file, line } }

    pub fn file(&self) -> &'static str { self.file }

    pub fn line(&self) -> u32 { self.line }
}

impl<T: FormattedTrace> FormattedTrace for Vec<T> {
    fn formatted(&self) -> String {
        self.iter()
            .map(|src| src.formatted())
            .rev()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::prelude::*;
    use super::*;
    use futures01::Future;

    enum ErrorKind {
        NotSufficientBalance { actual: u64, required: u64 },
    }

    #[derive(Display, Serialize)]
    #[serde(tag = "error_type", content = "error_data")]
    enum ForwardedError {
        #[display(fmt = "Not sufficient balance. Top up your balance by {}", missing)]
        NotSufficientBalance { missing: u64 },
    }

    impl From<ErrorKind> for ForwardedError {
        fn from(kind: ErrorKind) -> Self {
            match kind {
                ErrorKind::NotSufficientBalance { actual, required } => ForwardedError::NotSufficientBalance {
                    missing: required - actual,
                },
            }
        }
    }

    #[test]
    fn test_mm_error() {
        const GENERATED_LINE: u32 = line!() + 2;
        fn generate_error(actual: u64, required: u64) -> Result<(), MmError<ErrorKind>> {
            Err(MmError::new(ErrorKind::NotSufficientBalance { actual, required }))
        }

        const FORWARDED_LINE: u32 = line!() + 2;
        fn forward_error(actual: u64, required: u64) -> Result<(), MmError<ForwardedError>> {
            let _ = generate_error(actual, required)?;
            unreachable!("'generate_error' must return an error")
        }

        let actual = 1000;
        let required = 1500;
        let missing = required - actual;
        let error = forward_error(actual, required).expect_err("'forward_error' must return an error");

        let expected_display = format!(
            "mm_error:{}] mm_error:{}] Not sufficient balance. Top up your balance by {}",
            FORWARDED_LINE, GENERATED_LINE, missing
        );
        assert_eq!(error.to_string(), expected_display);

        // the path is deduplicated
        let expected_path = "mm_error";
        assert_eq!(error.path(), expected_path);

        let expected_stack_trace = format!("mm_error:{}] mm_error:{}]", FORWARDED_LINE, GENERATED_LINE);
        assert_eq!(error.stack_trace(), expected_stack_trace);

        let actual_json = json::to_value(error).expect("!json::to_value");
        let expected_json = json!({
            "error": format!("Not sufficient balance. Top up your balance by {}", missing),
            "error_path": expected_path,
            "error_trace":expected_stack_trace,
            "error_type": "NotSufficientBalance",
            "error_data": {
                "missing": missing,
            }
        });
        assert_eq!(actual_json, expected_json);
    }

    #[test]
    fn test_map_error() {
        let res: Result<(), _> = Err("An error".to_string());

        let into_mm_with_line = line!() + 1;
        let mm_res = res.into_mm(|e| e.len()).expect_err("Expected MmError<usize>");
        assert_eq!(mm_res.etype, 8);
        assert_eq!(mm_res.trace, vec![TraceLocation::new("mm_error", into_mm_with_line)]);

        let error_line = line!() + 1;
        let mm_res: Result<(), _> = None.or_mm_err(|| "An error".to_owned());
        let mm_err = mm_res.expect_err("Expected MmError<String>");

        assert_eq!(mm_err.etype, "An error");
        assert_eq!(mm_err.trace, vec![TraceLocation::new("mm_error", error_line)]);
    }

    #[test]
    fn test_map_fut() {
        fn generate_error(desc: &str) -> Box<dyn Future<Item = (), Error = String> + Send> {
            Box::new(futures01::future::err(desc.to_owned()))
        }

        let into_mm_line = line!() + 2;
        let mm_err = generate_error("An error")
            .into_mm_fut(|error| error.len())
            .wait()
            .expect_err("Expected an error");
        assert_eq!(mm_err.etype, 8);
        assert_eq!(mm_err.trace, vec![TraceLocation::new("mm_error", into_mm_line)]);
    }

    #[test]
    fn test_serialization_error() {
        /// Leads to the serialization error.
        #[derive(Display, Serialize)]
        enum UntaggedEnum {
            Inner,
        }

        /// Leads to the serialization error.
        #[derive(Display, Serialize)]
        #[serde(tag = "another_tag", content = "error_data")]
        enum NoErrorType {
            Inner,
        }

        /// Leads to the serialization error.
        #[derive(Default, Display, Serialize)]
        #[display(fmt = "")]
        struct ExtraFields {
            error_type: String,
            extra_field: Vec<u8>,
        }

        /// The valid error type.
        #[derive(Default, Display, Serialize)]
        struct ValidErrorStruct {
            error_type: String,
        }

        /// The valid error type.
        #[derive(Debug, Display, Serialize)]
        #[serde(tag = "error_type", content = "error_data")]
        enum ValidErrorEnum {
            #[display(fmt = "")]
            WithData {
                field1: i32,
                field2: &'static str,
            },
            WithoutData,
        }

        // vvv expect errors vvv
        serde_json::to_string(&MmError::new(UntaggedEnum::Inner))
            .expect_err("Expected an error when trying to serialize an untagged enum");
        serde_json::to_string(&MmError::new(NoErrorType::Inner))
            .expect_err("Expected an error when trying to serialize an error without 'error_type' field");
        serde_json::to_string(&MmError::new(ExtraFields::default()))
            .expect_err("Expected an error when trying to serialize an error with extra fields");

        // vvv expect success vvv
        let _ = serde_json::to_string(&MmError::new(ValidErrorStruct::default())).expect(
            "Unexpected error when trying to serialize an error with 'error_type' and without 'error_data' fields",
        );
        let _ = serde_json::to_string(&MmError::new(ValidErrorEnum::WithData { field1: 0, field2: "" }))
            .expect("Unexpected error when trying to serialize an error with 'error_type' and 'error_data' fields");
        let _ = serde_json::to_string(&MmError::new(ValidErrorEnum::WithoutData)).expect(
            "Unexpected error when trying to serialize an error with 'error_type' and without 'error_data' fields",
        );
    }
}
