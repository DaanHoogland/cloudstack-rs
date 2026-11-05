//! Request parameters and their wire encoding.

use std::collections::BTreeMap;

/// The value of a single API parameter.
///
/// CloudStack knows three shapes on the wire:
///
/// * scalars: `name=value`
/// * `list` parameters: `name=a,b,c`
/// * `map` parameters: `name[0].key=value&name[0].other=value&name[1].key=...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    /// A scalar value, sent as-is.
    Value(String),
    /// A `list` parameter; sent comma separated.
    List(Vec<String>),
    /// A `map` parameter; entry `i` is sent as `name[i].<key>=<value>` for each of its keys.
    Map(Vec<BTreeMap<String, String>>),
}

impl ParamValue {
    /// A map parameter with a single entry, e.g. `details[0].cpuNumber=2&details[0].memory=1024`.
    pub fn map<K, V>(entries: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        ParamValue::Map(vec![entries.into_iter().map(|(k, v)| (k.into(), v.into())).collect()])
    }

    /// A map parameter with one `{key, value}` entry per pair, the shape used by `tags`:
    /// `tags[0].key=env&tags[0].value=prod&tags[1].key=...`.
    pub fn key_values<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        ParamValue::Map(
            pairs
                .into_iter()
                .map(|(k, v)| BTreeMap::from([("key".to_owned(), k.into()), ("value".to_owned(), v.into())]))
                .collect(),
        )
    }

    /// A map parameter with arbitrary entries.
    pub fn maps<I, K, V>(entries: impl IntoIterator<Item = I>) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        ParamValue::Map(
            entries
                .into_iter()
                .map(|e| e.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
                .collect(),
        )
    }
}

impl From<String> for ParamValue {
    fn from(v: String) -> Self {
        ParamValue::Value(v)
    }
}

impl From<&str> for ParamValue {
    fn from(v: &str) -> Self {
        ParamValue::Value(v.to_owned())
    }
}

impl From<&String> for ParamValue {
    fn from(v: &String) -> Self {
        ParamValue::Value(v.clone())
    }
}

impl From<bool> for ParamValue {
    fn from(v: bool) -> Self {
        ParamValue::Value(v.to_string())
    }
}

macro_rules! from_number {
    ($($t:ty),*) => {$(
        impl From<$t> for ParamValue {
            fn from(v: $t) -> Self {
                ParamValue::Value(v.to_string())
            }
        }
    )*};
}
from_number!(i8, i16, i32, i64, u8, u16, u32, u64, usize, f32, f64);

impl From<Vec<String>> for ParamValue {
    fn from(v: Vec<String>) -> Self {
        ParamValue::List(v)
    }
}

impl From<Vec<&str>> for ParamValue {
    fn from(v: Vec<&str>) -> Self {
        ParamValue::List(v.into_iter().map(str::to_owned).collect())
    }
}

impl From<&[&str]> for ParamValue {
    fn from(v: &[&str]) -> Self {
        ParamValue::List(v.iter().map(|s| (*s).to_owned()).collect())
    }
}

impl<const N: usize> From<[&str; N]> for ParamValue {
    fn from(v: [&str; N]) -> Self {
        ParamValue::List(v.iter().map(|s| (*s).to_owned()).collect())
    }
}

/// The parameters of one API call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params(BTreeMap<String, ParamValue>);

impl Params {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a parameter, replacing any previous value.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<ParamValue>) -> &mut Self {
        self.0.insert(name.into(), value.into());
        self
    }

    /// Builder-style [`Params::set`].
    pub fn with(mut self, name: impl Into<String>, value: impl Into<ParamValue>) -> Self {
        self.set(name, value);
        self
    }

    pub fn get(&self, name: &str) -> Option<&ParamValue> {
        self.0.get(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<ParamValue> {
        self.0.remove(name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ParamValue)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn rename(&mut self, from: &str, to: String) {
        if let Some(v) = self.0.remove(from) {
            self.0.insert(to, v);
        }
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.0.retain(|k, _| keep(k));
    }

    /// The flat `name=value` pairs as they go on the wire.
    pub(crate) fn flatten(&self) -> Vec<(String, String)> {
        let mut out = Vec::with_capacity(self.0.len());
        for (name, value) in &self.0 {
            match value {
                ParamValue::Value(v) => out.push((name.clone(), v.clone())),
                ParamValue::List(items) => out.push((name.clone(), items.join(","))),
                ParamValue::Map(entries) => {
                    for (i, entry) in entries.iter().enumerate() {
                        for (k, v) in entry {
                            out.push((format!("{name}[{i}].{k}"), v.clone()));
                        }
                    }
                }
            }
        }
        out
    }
}

impl<K: Into<String>, V: Into<ParamValue>> FromIterator<(K, V)> for Params {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Params(iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }
}

impl IntoIterator for Params {
    type Item = (String, ParamValue);
    type IntoIter = std::collections::btree_map::IntoIter<String, ParamValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<K: Into<String>, V: Into<ParamValue>> Extend<(K, V)> for Params {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.set(k, v);
        }
    }
}

/// `details[0].key` -> `details`
pub(crate) fn base_name(key: &str) -> &str {
    key.split('[').next().unwrap_or(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattening() {
        let p = Params::new()
            .with("name", "web 1")
            .with("ids", vec!["a", "b"])
            .with("details", ParamValue::map([("cpuNumber", "2"), ("memory", "1024")]))
            .with("tags", ParamValue::key_values([("env", "prod"), ("team", "ops")]));
        assert_eq!(
            p.flatten(),
            vec![
                ("details[0].cpuNumber".into(), "2".into()),
                ("details[0].memory".into(), "1024".into()),
                ("ids".into(), "a,b".into()),
                ("name".into(), "web 1".into()),
                ("tags[0].key".into(), "env".into()),
                ("tags[0].value".into(), "prod".into()),
                ("tags[1].key".into(), "team".into()),
                ("tags[1].value".into(), "ops".into()),
            ]
        );
    }

    #[test]
    fn base_names() {
        assert_eq!(base_name("details[0].key"), "details");
        assert_eq!(base_name("zoneid"), "zoneid");
    }
}
