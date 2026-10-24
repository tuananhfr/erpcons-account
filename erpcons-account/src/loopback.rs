//! One-shot loopback redirect listener on `127.0.0.1` (RFC 8252, contract §1).
use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::{Error, http::query_unescape};

const MAX_HEAD: usize = 8192;

pub(crate) struct Loopback {
    listener: TcpListener,
    port: u16,
}

pub(crate) struct Callback {
    pub code: String,
    pub iss: Option<String>,
}

pub(crate) struct Pages<'a> {
    pub success: &'a str,
    pub failure: &'a str,
}

enum Outcome {
    Ignored,
    Done(Result<Callback, Error>),
}

impl Loopback {
    pub(crate) fn bind() -> Result<Self, Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| Error::Network(format!("loopback listener: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::Network(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| Error::Network(e.to_string()))?
            .port();
        Ok(Self { listener, port })
    }

    pub(crate) fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    /// Serves requests until the `/callback` request arrives, `cancel` is set or `deadline` passes.
    pub(crate) fn wait(
        &self,
        cancel: &AtomicBool,
        deadline: Instant,
        state: &str,
        pages: &Pages,
    ) -> Result<Callback, Error> {
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::SignInTimedOut);
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Outcome::Done(result) = handle(stream, state, pages) {
                        return result;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::Network(e.to_string())),
            }
        }
    }
}

fn handle(mut stream: TcpStream, state: &str, pages: &Pages) -> Outcome {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Some(target) = read_target(&mut stream) else {
        respond(&mut stream, "400 Bad Request", "");
        return Outcome::Ignored;
    };
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    if path != "/callback" {
        respond(&mut stream, "404 Not Found", "");
        return Outcome::Ignored;
    }
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) {
            params.entry(k).or_insert(v);
        }
    }
    let result = if params.get("state").map(String::as_str) != Some(state) {
        Err(Error::StateMismatch)
    } else if let Some(error) = params.get("error") {
        Err(Error::AuthorizationDenied(error.clone()))
    } else if let Some(code) = params.get("code").filter(|c| !c.is_empty()) {
        Ok(Callback {
            code: code.clone(),
            iss: params.get("iss").cloned(),
        })
    } else {
        Err(Error::BadResponse("callback without code".into()))
    };
    let page = if result.is_ok() {
        pages.success
    } else {
        pages.failure
    };
    respond(&mut stream, "200 OK", page);
    Outcome::Done(result)
}

/// Request target of a `GET` request line.
fn read_target(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 || head.len() + n > MAX_HEAD {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let line = std::str::from_utf8(&head).ok()?.lines().next()?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(target), Some(v)) if v.starts_with("HTTP/") => Some(target.into()),
        _ => None,
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}
