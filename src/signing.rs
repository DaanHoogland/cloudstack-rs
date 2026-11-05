//! API key request signing.
//!
//! The management server (`ApiServer.verifyRequest`) rebuilds the string to sign like this:
//!
//! 1. take every request parameter except `signature`, sorted by name (case-sensitive),
//! 2. join them as `name=URLEncoder.encode(value).replace("+", "%20")` with `&`,
//! 3. lowercase the whole string,
//! 4. HMAC it with the secret key and base64 the digest.
//!
//! Step 2 uses Java's `URLEncoder`, which only leaves `A-Z a-z 0-9 . - * _` unescaped. The Go
//! clients use `url.QueryEscape` plus fix-ups, which differs for `~` (Go leaves it, Java escapes
//! it), so values containing `~` fail verification there. This module mirrors Java exactly.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};

/// Which HMAC to sign API-key requests with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    /// HMAC-SHA1: what every released management server verifies.
    #[default]
    HmacSha1,
    /// HMAC-SHA512, for servers that support it.
    HmacSha512,
    /// Try HMAC-SHA512 first and fall back to HMAC-SHA1 when the server rejects the signature.
    /// The outcome is remembered for the lifetime of the client.
    Auto,
}

/// A concrete algorithm (never `Auto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Digest {
    Sha1,
    Sha512,
}

/// Percent-encodes like `java.net.URLEncoder.encode(s, UTF_8).replaceAll("\\+", "%20")`.
pub(crate) fn java_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Sorts parameters the way the server does (Java `Collections.sort` on the names).
pub(crate) fn sort_params(pairs: &mut [(String, String)]) {
    // Java compares UTF-16 code units; for the BMP that equals Rust's byte-wise str ordering.
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
}

/// The string the server will sign (before lowercasing). Expects sorted pairs.
pub(crate) fn string_to_sign(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", java_url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Base64 HMAC of the lowercased string to sign.
pub(crate) fn sign(string_to_sign: &str, secret_key: &str, digest: Digest) -> String {
    let data = string_to_sign.to_lowercase();
    let bytes = match digest {
        Digest::Sha1 => {
            let mut mac =
                Hmac::<sha1::Sha1>::new_from_slice(secret_key.as_bytes()).expect("HMAC accepts keys of any length");
            mac.update(data.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        Digest::Sha512 => {
            let mut mac =
                Hmac::<sha2::Sha512>::new_from_slice(secret_key.as_bytes()).expect("HMAC accepts keys of any length");
            mac.update(data.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
    };
    BASE64.encode(bytes)
}

/// A URL query string with both names and values escaped (the server decodes both before it
/// verifies, so escaping names like `details[0].key` is safe and keeps proxies happy).
pub(crate) fn query_string(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", java_url_encode(k), java_url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "VDaACYb0LV9eNjTetIOElcVQkvJck_J_QljX_FcHRj87ZKiy0z0ty0ZsYBkoXkY9b7eq1EhwJaw7FF3akA3KBQ";

    fn sample() -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = [
            (
                "apiKey",
                "plgWJfZK4gyS3mOMTVmjUVg-X-jlWlnfaUJ9GAbBbf9EdM-kAYMmAiLqzzq1ElZLYq_u38zCm0bewzGUdP66mg",
            ),
            ("command", "deployVirtualMachine"),
            ("response", "json"),
            ("displayname", "web 01~test"),
            ("details[0].cpuNumber", "2"),
            ("expires", "2026-11-05T12:00:00Z"),
            ("signatureversion", "3"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        sort_params(&mut pairs);
        pairs
    }

    #[test]
    fn encodes_like_java() {
        assert_eq!(java_url_encode("a b+c~d*e_f.g-h"), "a%20b%2Bc%7Ed*e_f.g-h");
        assert_eq!(java_url_encode("é/:"), "%C3%A9%2F%3A");
    }

    // Reference values computed independently with Python's hmac module.
    #[test]
    fn signs_like_the_server() {
        let s = string_to_sign(&sample());
        assert_eq!(
            s,
            "apiKey=plgWJfZK4gyS3mOMTVmjUVg-X-jlWlnfaUJ9GAbBbf9EdM-kAYMmAiLqzzq1ElZLYq_u38zCm0bewzGUdP66mg\
             &command=deployVirtualMachine&details[0].cpuNumber=2&displayname=web%2001%7Etest\
             &expires=2026-11-05T12%3A00%3A00Z&response=json&signatureversion=3"
        );
        assert_eq!(sign(&s, SECRET, Digest::Sha1), "v6itTY567StljWM4BWsVrRztUII=");
        assert_eq!(
            sign(&s, SECRET, Digest::Sha512),
            "vbelURqIgZ7tHxYVuHqaj1XF4uY5BUQ8ZZpuT/3F3p+BlFkAC01r4diuncrfNML8tj8VSI0nCOEPewe/4R3LUw=="
        );
    }

    #[test]
    fn query_escapes_names() {
        let q = query_string(&[("details[0].key".into(), "a b".into())]);
        assert_eq!(q, "details%5B0%5D.key=a%20b");
    }
}
