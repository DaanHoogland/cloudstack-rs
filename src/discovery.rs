//! The API catalog built from `listApis`.
//!
//! `listApis` returns every API the calling account's role may use, with its parameters
//! (name, type, required, max length, related APIs) and response fields. The catalog is what
//! lets the client resolve names, decide whether a call is asynchronous, and validate
//! parameters before anything is sent.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::params::{ParamValue, Params, base_name};
use crate::util::closest;

/// The declared type of an API parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ParamType {
    Boolean,
    Date,
    Integer,
    List,
    Long,
    Map,
    Short,
    String,
    TzDate,
    Uuid,
    /// Anything this crate does not know about yet; kept verbatim.
    Other(std::string::String),
}

impl ParamType {
    pub fn as_str(&self) -> &str {
        match self {
            ParamType::Boolean => "boolean",
            ParamType::Date => "date",
            ParamType::Integer => "integer",
            ParamType::List => "list",
            ParamType::Long => "long",
            ParamType::Map => "map",
            ParamType::Short => "short",
            ParamType::String => "string",
            ParamType::TzDate => "tzdate",
            ParamType::Uuid => "uuid",
            ParamType::Other(s) => s,
        }
    }
}

impl From<String> for ParamType {
    fn from(s: String) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "boolean" => ParamType::Boolean,
            "date" => ParamType::Date,
            "integer" | "int" => ParamType::Integer,
            "list" => ParamType::List,
            "long" => ParamType::Long,
            "map" => ParamType::Map,
            "short" => ParamType::Short,
            "string" => ParamType::String,
            "tzdate" => ParamType::TzDate,
            "uuid" => ParamType::Uuid,
            _ => ParamType::Other(s),
        }
    }
}

impl From<ParamType> for String {
    fn from(t: ParamType) -> Self {
        t.as_str().to_owned()
    }
}

impl fmt::Display for ParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// One parameter of an API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiParam {
    pub name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub description: String,
    #[serde(rename = "type", default = "default_param_type")]
    pub kind: ParamType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub length: Option<u64>,
    #[serde(default)]
    pub since: Option<String>,
    /// APIs whose results can feed this parameter (e.g. `listZones` for `zoneid`).
    #[serde(default, deserialize_with = "comma_list")]
    pub related: Vec<String>,
}

/// One field of an API's response; objects and lists nest further fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseField {
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub description: String,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response: Vec<ResponseField>,
}

/// Metadata of one API as reported by `listApis`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiInfo {
    pub name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub description: String,
    #[serde(rename = "isasync", default)]
    pub is_async: bool,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default, deserialize_with = "comma_list")]
    pub related: Vec<String>,
    #[serde(default)]
    pub params: Vec<ApiParam>,
    #[serde(default)]
    pub response: Vec<ResponseField>,
}

impl ApiInfo {
    /// The leading lowercase part of the name: `list` for `listVirtualMachines`.
    pub fn verb(&self) -> &str {
        split_verb(&self.name).0
    }

    /// The rest of the name, lowercased: `virtualmachines` for `listVirtualMachines`.
    pub fn noun(&self) -> String {
        split_verb(&self.name).1.to_lowercase()
    }

    /// Looks up a parameter by name (case-insensitive).
    pub fn param(&self, name: &str) -> Option<&ApiParam> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    pub fn required_params(&self) -> impl Iterator<Item = &ApiParam> {
        self.params.iter().filter(|p| p.required)
    }

    /// Checks parameters against this API's declaration. An empty result means valid.
    pub fn validate(&self, params: &Params) -> Vec<ParamProblem> {
        let mut problems = Vec::new();
        for p in self.required_params() {
            if !params.keys().any(|k| base_name(k).eq_ignore_ascii_case(&p.name)) {
                problems.push(ParamProblem::Missing { name: p.name.clone() });
            }
        }
        for (key, value) in params.iter() {
            let base = base_name(key);
            match self.param(base) {
                None => problems.push(ParamProblem::Unknown {
                    name: key.to_owned(),
                    suggestions: closest(base, self.params.iter().map(|p| p.name.as_str())),
                }),
                Some(p) => {
                    if let Some(reason) = check_value(p, key != base, value) {
                        problems.push(ParamProblem::Invalid {
                            name: key.to_owned(),
                            reason,
                        });
                    }
                }
            }
        }
        problems
    }

    /// Rewrites parameter names to their declared spelling (`zoneId` -> `zoneid`).
    pub(crate) fn canonicalize(&self, params: &mut Params) {
        let renames: Vec<(String, String)> = params
            .keys()
            .filter_map(|key| {
                let base = base_name(key);
                let p = self.param(base)?;
                (p.name != base).then(|| (key.to_owned(), format!("{}{}", p.name, &key[base.len()..])))
            })
            .collect();
        for (from, to) in renames {
            params.rename(&from, to);
        }
    }
}

fn check_value(p: &ApiParam, indexed: bool, value: &ParamValue) -> Option<String> {
    if indexed {
        // Raw `name[0].key` syntax; only map parameters take it.
        return (p.kind != ParamType::Map).then(|| format!("`{}` is not a map parameter", p.name));
    }
    match (&p.kind, value) {
        (ParamType::Map, ParamValue::Map(_)) => None,
        (ParamType::Map, _) => Some("is a map parameter; pass a ParamValue::Map".to_owned()),
        (_, ParamValue::Map(_)) => Some(format!("is a {} parameter, not a map", p.kind)),
        (ParamType::Boolean, ParamValue::Value(v)) => (!v.eq_ignore_ascii_case("true")
            && !v.eq_ignore_ascii_case("false"))
        .then(|| format!("expected true or false, got `{v}`")),
        (ParamType::Integer | ParamType::Long | ParamType::Short, ParamValue::Value(v)) => v
            .trim()
            .parse::<i64>()
            .is_err()
            .then(|| format!("expected a whole number, got `{v}`")),
        (ParamType::Boolean | ParamType::Integer | ParamType::Long | ParamType::Short, ParamValue::List(_)) => {
            Some(format!("is a {} parameter, not a list", p.kind))
        }
        (ParamType::String, ParamValue::Value(v)) => match p.length {
            Some(max) if v.chars().count() as u64 > max => Some(format!(
                "is {} characters long, the maximum is {max}",
                v.chars().count()
            )),
            _ => None,
        },
        _ => None,
    }
}

/// One reason why a set of parameters does not fit an API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamProblem {
    Missing { name: String },
    Unknown { name: String, suggestions: Vec<String> },
    Invalid { name: String, reason: String },
}

impl fmt::Display for ParamProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamProblem::Missing { name } => write!(f, "missing required parameter `{name}`"),
            ParamProblem::Unknown { name, suggestions } if suggestions.is_empty() => {
                write!(f, "unknown parameter `{name}`")
            }
            ParamProblem::Unknown { name, suggestions } => {
                write!(
                    f,
                    "unknown parameter `{name}` (did you mean {}?)",
                    suggestions.join(", ")
                )
            }
            ParamProblem::Invalid { name, reason } => write!(f, "`{name}` {reason}"),
        }
    }
}

/// All APIs available to the account, keyed case-insensitively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCatalog {
    apis: BTreeMap<String, ApiInfo>,
    fetched_at: DateTime<Utc>,
    #[serde(default)]
    server_version: Option<String>,
}

impl ApiCatalog {
    /// Builds a catalog from APIs you already have.
    pub fn from_apis(apis: impl IntoIterator<Item = ApiInfo>) -> Self {
        Self {
            apis: apis.into_iter().map(|a| (a.name.to_lowercase(), a)).collect(),
            fetched_at: Utc::now(),
            server_version: None,
        }
    }

    /// Builds a catalog from a `listApis` response: either the full envelope
    /// (`{"listapisresponse": {...}}`) or its body (`{"count": n, "api": [...]}`), which is also
    /// the format of CloudMonkey's cache and bundled `apis.json`.
    pub fn from_list_apis(value: &Value) -> Result<Self> {
        let body = value.get("listapisresponse").unwrap_or(value);
        let apis = body.get("api").ok_or_else(|| Error::UnexpectedResponse {
            status: 200,
            message: "listApis response does not contain an `api` list".to_owned(),
        })?;
        let apis: Vec<ApiInfo> = serde_json::from_value(apis.clone())?;
        Ok(Self::from_apis(apis))
    }

    /// [`ApiCatalog::from_list_apis`] from JSON text.
    pub fn from_list_apis_json(json: &str) -> Result<Self> {
        Self::from_list_apis(&serde_json::from_str(json)?)
    }

    /// Looks up an API by its exact name, ignoring case.
    pub fn get(&self, name: &str) -> Option<&ApiInfo> {
        self.apis.get(&name.trim().to_lowercase())
    }

    /// Like [`ApiCatalog::get`], but also accepts CloudMonkey's `verb noun` form
    /// (`"list virtualmachines"`), and returns suggestions when nothing matches.
    pub fn resolve(&self, name: &str) -> Result<&ApiInfo> {
        if let Some(api) = self.get(name) {
            return Ok(api);
        }
        let mut words = name.split_whitespace();
        if let (Some(verb), Some(_)) = (words.next(), words.clone().next()) {
            let noun = words.collect::<String>().to_lowercase();
            if let Some(api) = self
                .apis
                .values()
                .find(|a| a.verb().eq_ignore_ascii_case(verb) && a.noun() == noun)
            {
                return Ok(api);
            }
        }
        let compact: String = name.split_whitespace().collect();
        Err(Error::UnknownApi {
            name: name.to_owned(),
            suggestions: closest(&compact, self.apis.values().map(|a| a.name.as_str())),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &ApiInfo> {
        self.apis.values()
    }

    pub fn len(&self) -> usize {
        self.apis.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apis.is_empty()
    }

    /// All distinct verbs (`list`, `create`, `deploy`, ...).
    pub fn verbs(&self) -> BTreeSet<&str> {
        self.apis.values().map(ApiInfo::verb).collect()
    }

    /// APIs with the given verb.
    pub fn with_verb<'a>(&'a self, verb: &'a str) -> impl Iterator<Item = &'a ApiInfo> + 'a {
        self.apis.values().filter(move |a| a.verb().eq_ignore_ascii_case(verb))
    }

    /// APIs whose name or description contains `needle` (case-insensitive).
    pub fn search(&self, needle: &str) -> Vec<&ApiInfo> {
        let needle = needle.to_lowercase();
        self.apis
            .values()
            .filter(|a| a.name.to_lowercase().contains(&needle) || a.description.to_lowercase().contains(&needle))
            .collect()
    }

    /// When the catalog was fetched from the server.
    pub fn fetched_at(&self) -> DateTime<Utc> {
        self.fetched_at
    }

    /// The CloudStack version reported by `listCapabilities`, when known.
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    pub(crate) fn set_server_version(&mut self, version: Option<String>) {
        self.server_version = version;
    }
}

/// Splits `listVirtualMachines` into (`list`, `VirtualMachines`).
pub(crate) fn split_verb(name: &str) -> (&str, &str) {
    let idx = name.find(|c: char| !c.is_ascii_lowercase()).unwrap_or(name.len());
    name.split_at(idx)
}

fn default_param_type() -> ParamType {
    ParamType::String
}

fn null_as_default<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// `listApis` sends `related` as `"a,b,c"`; the cache stores it as a list. Accept both.
fn comma_list<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Related {
        Text(String),
        List(Vec<String>),
    }
    Ok(match Option::<Related>::deserialize(d)? {
        None => Vec::new(),
        Some(Related::List(v)) => v,
        Some(Related::Text(s)) => {
            let mut v: Vec<String> = s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            v.sort();
            v.dedup();
            v
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> ApiCatalog {
        ApiCatalog::from_list_apis(&json!({"listapisresponse": {"count": 2, "api": [
            {"name": "listVirtualMachines", "isasync": false, "description": "List the VMs",
             "related": "deployVirtualMachine,startVirtualMachine",
             "params": [
                {"name": "state", "type": "string", "required": false, "length": 255},
                {"name": "page", "type": "integer", "required": false},
                {"name": "pagesize", "type": "integer", "required": false},
                {"name": "tags", "type": "map", "required": false}
             ],
             "response": [{"name": "id", "type": "string", "description": "the id"}]},
            {"name": "deployVirtualMachine", "isasync": true, "description": "Creates a VM",
             "params": [
                {"name": "zoneid", "type": "uuid", "required": true, "related": "listZones"},
                {"name": "serviceofferingid", "type": "uuid", "required": true},
                {"name": "startvm", "type": "boolean", "required": false},
                {"name": "details", "type": "map", "required": false},
                {"name": "name", "type": "string", "required": false, "length": 8}
             ]}
        ]}}))
        .unwrap()
    }

    #[test]
    fn parses_and_resolves() {
        let c = catalog();
        assert_eq!(c.len(), 2);
        let vms = c.get("LISTVIRTUALMACHINES").unwrap();
        assert_eq!(vms.verb(), "list");
        assert_eq!(vms.noun(), "virtualmachines");
        assert_eq!(vms.related, vec!["deployVirtualMachine", "startVirtualMachine"]);
        assert!(c.get("deployVirtualMachine").unwrap().is_async);
        assert_eq!(c.resolve("list virtualmachines").unwrap().name, "listVirtualMachines");
        assert_eq!(
            c.resolve("deploy virtual machine").unwrap().name,
            "deployVirtualMachine"
        );
        match c.resolve("listVirtualMachine") {
            Err(Error::UnknownApi { suggestions, .. }) => assert_eq!(suggestions[0], "listVirtualMachines"),
            other => panic!("{other:?}"),
        }
        assert_eq!(c.verbs().into_iter().collect::<Vec<_>>(), vec!["deploy", "list"]);
    }

    #[test]
    fn validates() {
        let c = catalog();
        let deploy = c.get("deployVirtualMachine").unwrap();
        let params = Params::new()
            .with("zoneidd", "x")
            .with("startvm", "maybe")
            .with("details", "cpu=2")
            .with("name", "far-too-long");
        let problems = deploy.validate(&params);
        assert!(problems.contains(&ParamProblem::Missing { name: "zoneid".into() }));
        assert!(problems.contains(&ParamProblem::Missing {
            name: "serviceofferingid".into()
        }));
        assert!(problems.contains(&ParamProblem::Unknown {
            name: "zoneidd".into(),
            suggestions: vec!["zoneid".into()]
        }));
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, ParamProblem::Invalid { name, .. } if name == "startvm"))
        );
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, ParamProblem::Invalid { name, .. } if name == "details"))
        );
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, ParamProblem::Invalid { name, .. } if name == "name"))
        );

        let ok = Params::new()
            .with("zoneid", "z")
            .with("serviceofferingid", "s")
            .with("details[0].cpuNumber", "2")
            .with("startvm", false);
        assert!(deploy.validate(&ok).is_empty());
    }

    #[test]
    fn canonicalizes_names() {
        let c = catalog();
        let deploy = c.get("deployVirtualMachine").unwrap();
        let mut params = Params::new().with("zoneId", "z").with("Details[0].x", "1");
        deploy.canonicalize(&mut params);
        assert_eq!(params.keys().collect::<Vec<_>>(), vec!["details[0].x", "zoneid"]);
    }

    #[test]
    fn cache_round_trip() {
        let c = catalog();
        let json = serde_json::to_string(&c).unwrap();
        let back: ApiCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get("listVirtualMachines"), c.get("listVirtualMachines"));
    }
}
