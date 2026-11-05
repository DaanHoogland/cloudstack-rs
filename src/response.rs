//! Responses and async job state.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::{ApiError, Error, Result};
use crate::util::{lenient_bool, lenient_i64, lenient_string};

/// The result of an API call, with the `<command>response` envelope removed.
///
/// For async APIs that were waited on, the value is the job's `jobresult`
/// (e.g. `{"virtualmachine": {...}}`) and [`Response::job`] describes the job.
#[derive(Debug, Clone)]
pub struct Response {
    command: String,
    value: Value,
    job: Option<JobInfo>,
}

impl Response {
    pub(crate) fn new(command: String, value: Value, job: Option<JobInfo>) -> Self {
        Self { command, value, job }
    }

    /// The API that was called.
    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }

    /// The async job behind this response, if the API is asynchronous.
    pub fn job(&self) -> Option<&JobInfo> {
        self.job.as_ref()
    }

    /// True when the job was started but not waited for (see [`crate::Request::no_wait`]).
    pub fn is_pending(&self) -> bool {
        self.job.as_ref().is_some_and(|j| j.status == JobStatus::Pending)
    }

    /// `count` of a list response: the total number of matches, not just this page.
    pub fn count(&self) -> Option<u64> {
        self.value.get("count").and_then(lenient_i64).map(|c| c.max(0) as u64)
    }

    /// The items of a list response (`{"count": 2, "zone": [...]}` -> the zones).
    /// Empty when there are none: CloudStack then returns `{}`.
    pub fn items(&self) -> &[Value] {
        list_entry(&self.value).map(|(_, v)| v.as_slice()).unwrap_or(&[])
    }

    /// The key holding the items of a list response (`zone`, `virtualmachine`, ...).
    pub fn items_key(&self) -> Option<&str> {
        list_entry(&self.value).map(|(k, _)| k.as_str())
    }

    pub fn into_items(self) -> Vec<Value> {
        match self.value {
            Value::Object(map) => map
                .into_iter()
                .find_map(|(k, v)| match v {
                    Value::Array(items) if k != "count" => Some(items),
                    _ => None,
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// The single object of a create/update/async response
    /// (`{"virtualmachine": {...}}` -> the VM).
    pub fn entity(&self) -> Option<&Value> {
        let obj = self.value.as_object()?;
        let mut objects = obj.iter().filter(|(k, _)| *k != "count");
        match (objects.next(), objects.next()) {
            (Some((_, v @ Value::Object(_))), None) => Some(v),
            _ => None,
        }
    }

    /// The `success` flag of APIs that only report success (`{"success": "true"}`).
    pub fn success(&self) -> Option<bool> {
        self.value.get("success").and_then(lenient_bool)
    }

    /// Deserializes the whole value.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(T::deserialize(&self.value)?)
    }

    /// Deserializes the items of a list response.
    pub fn deserialize_items<T: DeserializeOwned>(&self) -> Result<Vec<T>> {
        self.items().iter().map(|v| Ok(T::deserialize(v)?)).collect()
    }

    /// Deserializes [`Response::entity`].
    pub fn deserialize_entity<T: DeserializeOwned>(&self) -> Result<T> {
        let entity = self.entity().ok_or_else(|| Error::UnexpectedResponse {
            status: 200,
            message: format!("`{}` response does not contain a single object", self.command),
        })?;
        Ok(T::deserialize(entity)?)
    }
}

fn list_entry(value: &Value) -> Option<(&String, &Vec<Value>)> {
    value.as_object()?.iter().find_map(|(k, v)| match v {
        Value::Array(items) if k != "count" => Some((k, items)),
        _ => None,
    })
}

/// Status of an async job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Succeeded,
    Failed,
    Unknown(i64),
}

impl From<i64> for JobStatus {
    fn from(v: i64) -> Self {
        match v {
            0 => JobStatus::Pending,
            1 => JobStatus::Succeeded,
            2 => JobStatus::Failed,
            other => JobStatus::Unknown(other),
        }
    }
}

/// Metadata of an async job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobInfo {
    pub job_id: String,
    pub status: JobStatus,
    pub result_code: Option<i64>,
    pub result_type: Option<String>,
    /// Kind of resource the job acts on (`VirtualMachine`, `Volume`, ...).
    pub instance_type: Option<String>,
    pub instance_id: Option<String>,
}

impl JobInfo {
    pub(crate) fn pending(job_id: String, instance_id: Option<String>) -> Self {
        Self {
            job_id,
            status: JobStatus::Pending,
            result_code: None,
            result_type: None,
            instance_type: None,
            instance_id,
        }
    }
}

/// A `queryAsyncJobResult` snapshot.
#[derive(Debug, Clone)]
pub struct JobState {
    pub info: JobInfo,
    /// `jobresult`: the result object on success, `{errorcode, errortext}` on failure.
    pub result: Value,
}

impl JobState {
    pub(crate) fn from_query(job_id: &str, mut body: Value) -> Self {
        let get = |k: &str| body.get(k);
        let info = JobInfo {
            job_id: get("jobid")
                .and_then(lenient_string)
                .unwrap_or_else(|| job_id.to_owned()),
            status: get("jobstatus")
                .and_then(lenient_i64)
                .map_or(JobStatus::Unknown(-1), JobStatus::from),
            result_code: get("jobresultcode").and_then(lenient_i64),
            result_type: get("jobresulttype").and_then(lenient_string),
            instance_type: get("jobinstancetype").and_then(lenient_string),
            instance_id: get("jobinstanceid").and_then(lenient_string),
        };
        let result = match body.get_mut("jobresult").map(Value::take) {
            Some(Value::Null) | None => Value::Object(Map::new()),
            Some(v) => v,
        };
        Self { info, result }
    }

    /// The failure of a failed job.
    pub(crate) fn error(&self) -> ApiError {
        ApiError::from_body(200, &self.result).unwrap_or_else(|| ApiError {
            http_status: 200,
            error_code: self.info.result_code,
            cs_error_code: None,
            error_text: match &self.result {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        })
    }
}

/// Parses a raw HTTP response: decodes JSON, strips the envelope, and turns error bodies into
/// [`Error::Api`].
pub(crate) fn parse_body(status: u16, bytes: &[u8]) -> Result<Value> {
    let json: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => {
            let text = String::from_utf8_lossy(bytes);
            let snippet: String = text.trim().chars().take(300).collect();
            return Err(if (200..300).contains(&status) {
                Error::UnexpectedResponse {
                    status,
                    message: format!("not JSON: {snippet}"),
                }
            } else {
                Error::Api(ApiError {
                    http_status: status,
                    error_code: None,
                    cs_error_code: None,
                    error_text: snippet,
                })
            });
        }
    };
    let body = unwrap_envelope(json);
    if let Some(err) = ApiError::from_body(status, &body) {
        return Err(Error::Api(err));
    }
    if !(200..300).contains(&status) {
        return Err(Error::Api(ApiError {
            http_status: status,
            error_code: None,
            cs_error_code: None,
            error_text: body.to_string().chars().take(300).collect(),
        }));
    }
    Ok(body)
}

/// `{"listzonesresponse": {...}}` -> `{...}`; also handles `errorresponse`.
pub(crate) fn unwrap_envelope(value: Value) -> Value {
    match value {
        Value::Object(map) if map.len() == 1 || map.keys().any(|k| k.ends_with("response")) => {
            let key = map.keys().find(|k| k.ends_with("response")).cloned();
            let mut map = map;
            match key {
                Some(k) => map.remove(&k).unwrap_or(Value::Null),
                None => map.into_iter().next().map(|(_, v)| v).unwrap_or(Value::Null),
            }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn list_helpers() {
        let body = parse_body(
            200,
            br#"{"listzonesresponse":{"count":2,"zone":[{"id":"a"},{"id":"b"}]}}"#,
        )
        .unwrap();
        let r = Response::new("listZones".into(), body, None);
        assert_eq!(r.count(), Some(2));
        assert_eq!(r.items_key(), Some("zone"));
        assert_eq!(r.items().len(), 2);
        assert_eq!(r.into_items()[1]["id"], "b");

        let empty = Response::new(
            "listZones".into(),
            parse_body(200, br#"{"listzonesresponse":{}}"#).unwrap(),
            None,
        );
        assert!(empty.items().is_empty());
        assert_eq!(empty.count(), None);
    }

    #[test]
    fn entity_and_success() {
        let r = Response::new("x".into(), json!({"virtualmachine": {"id": "vm"}}), None);
        assert_eq!(r.entity().unwrap()["id"], "vm");
        let r = Response::new("x".into(), json!({"success": "true", "displaytext": "ok"}), None);
        assert_eq!(r.success(), Some(true));
        assert!(r.entity().is_none());
    }

    #[test]
    fn errors() {
        let err = parse_body(
            431,
            br#"{"deployvirtualmachineresponse":{"uuidList":[],"errorcode":431,"cserrorcode":4350,"errortext":"Unable to find zone"}}"#,
        )
        .unwrap_err();
        let api = err.api_error().unwrap();
        assert_eq!(
            (api.http_status, api.error_code, api.cs_error_code),
            (431, Some(431), Some(4350))
        );
        assert_eq!(api.error_text, "Unable to find zone");

        let err = parse_body(
            401,
            br#"{"errorresponse":{"errorcode":401,"errortext":"unable to verify user credentials"}}"#,
        )
        .unwrap_err();
        assert!(err.is_auth_failure());

        let err = parse_body(502, b"<html>Bad gateway</html>").unwrap_err();
        assert_eq!(err.api_error().unwrap().http_status, 502);
    }

    #[test]
    fn job_state() {
        let s = JobState::from_query(
            "j",
            json!({"jobid": "j", "jobstatus": 2, "jobresultcode": 530, "jobresulttype": "object",
                   "jobresult": {"errorcode": 530, "errortext": "Insufficient capacity"}}),
        );
        assert_eq!(s.info.status, JobStatus::Failed);
        assert_eq!(s.error().error_text, "Insufficient capacity");
    }
}
