//! Request and response values independent of tiny_http.
use serde_json::{Value, json};

pub(crate) struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn query(&self, key: &str) -> Option<String> {
        params(&self.query)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub(crate) fn form(&self, key: &str) -> Option<String> {
        params(std::str::from_utf8(&self.body).ok()?)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub(crate) fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

pub(crate) fn params(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((unescape(k)?, unescape(v)?))
        })
        .collect()
}

fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

pub(crate) fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub(crate) fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }

    pub(crate) fn problem(status: u16, code: &str, issuer: &str, cid: &str) -> Self {
        let mut r = Self::json(
            status,
            &json!({
                "type": format!("{issuer}/problems/{code}"),
                "title": code.replace('_', " "),
                "status": status,
                "code": code,
                "correlation_id": cid,
            }),
        );
        r.headers[0].1 = "application/problem+json".into();
        if status == 401 {
            r = r.with_header("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        }
        r
    }

    pub(crate) fn oauth_error(status: u16, error: &str) -> Self {
        Self::json(status, &json!({ "error": error }))
    }

    pub(crate) fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            headers: vec![("Location".into(), location.into())],
            body: Vec::new(),
        }
    }

    pub(crate) fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    pub(crate) fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub(crate) fn has_header(&self, k: &str) -> bool {
        self.headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(k))
    }
}
