//! Small helpers shared across modules.

use serde_json::Value;

/// CloudStack is inconsistent about numbers: some arrive as JSON numbers, some as strings.
pub(crate) fn lenient_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Booleans also show up as `"true"` / `"false"` strings.
pub(crate) fn lenient_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_i64().map(|i| i != 0),
        _ => None,
    }
}

pub(crate) fn lenient_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Up to three candidates that look like what the user meant ("did you mean ...?").
pub(crate) fn closest<'a>(needle: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let needle = needle.to_lowercase();
    let limit = (needle.chars().count() / 3).max(2);
    let mut scored: Vec<(usize, &str)> = candidates
        .into_iter()
        .filter_map(|c| {
            let lc = c.to_lowercase();
            let distance = levenshtein(&needle, &lc);
            let contains = needle.len() >= 4 && lc.contains(&needle);
            if distance <= limit {
                Some((distance, c))
            } else if contains {
                Some((limit, c))
            } else {
                None
            }
        })
        .collect();
    scored.sort();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(3).map(|(_, c)| c.to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lenient_parsing() {
        assert_eq!(lenient_i64(&json!(3)), Some(3));
        assert_eq!(lenient_i64(&json!("42")), Some(42));
        assert_eq!(lenient_bool(&json!("TRUE")), Some(true));
        assert_eq!(lenient_bool(&json!(false)), Some(false));
        assert_eq!(lenient_bool(&json!("nope")), None);
    }

    #[test]
    fn suggestions() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        let names = ["listZones", "listPods", "listVirtualMachines", "deployVirtualMachine"];
        assert_eq!(closest("listzone", names), vec!["listZones"]);
        assert_eq!(closest("virtualmachine", names)[0], "deployVirtualMachine");
        assert!(closest("zzzzzzzzzz", names).is_empty());
    }
}
