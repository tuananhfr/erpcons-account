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

    /// PI's success envelope `{ok: true, ...}` (`ApiResponse::ok`).
    pub(crate) fn pi_ok(status: u16, mut data: Value) -> Self {
        if let Value::Object(map) = &mut data {
            map.insert("ok".into(), true.into());
        }
        Self::json(status, &data)
    }

    /// PI's error envelope `{ok: false, message, code?}` (`ApiResponse::error`).
    pub(crate) fn pi_error(status: u16, message: &str, code: Option<&str>) -> Self {
        let mut body = json!({ "ok": false, "message": message });
        if let Some(code) = code.filter(|c| !c.is_empty()) {
            body["code"] = code.into();
        }
        Self::json(status, &body)
    }

    /// PI's 422 (`ApiException::validation`): per-field `errors`, no `code`.
    pub(crate) fn pi_invalid(errors: Value) -> Self {
        let mut body = json!({ "ok": false, "message": "Dữ liệu chưa hợp lệ." });
        body["errors"] = errors;
        Self::json(422, &body)
    }

    /// `ApiExceptionSubscriber`'s message for a status without a business message.
    pub(crate) fn pi_status(status: u16) -> Self {
        let message = match status {
            401 => "Bạn chưa đăng nhập hoặc phiên đã hết hạn.",
            403 => "Bạn không có quyền thực hiện thao tác này.",
            404 => "Không tìm thấy tài nguyên.",
            405 => "Phương thức không được hỗ trợ cho đường dẫn này.",
            429 => "Bạn thao tác quá nhanh, vui lòng thử lại sau.",
            s if s >= 500 => "Lỗi hệ thống.",
            _ => "Yêu cầu không hợp lệ.",
        };
        Self::pi_error(status, message, None)
    }

    /// OAuth error body of `/id/token` (`{error, error_description}`).
    pub(crate) fn oauth(status: u16, error: &str, description: &str) -> Self {
        Self::json(
            status,
            &json!({ "error": error, "error_description": description }),
        )
    }

    /// PI's login page (`LoginPage::render`), reduced to its message.
    pub(crate) fn html(status: u16, title: &str, message: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
            body: format!("<!doctype html><title>{title}</title><p>{message}</p>").into_bytes(),
        }
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
