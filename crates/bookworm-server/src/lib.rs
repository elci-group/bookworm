//! Loopback HTTP service (directive §24).
//!
//! The listener refuses any bind address that is not a loopback address.
//! Requests are synchronous: the handler's JSON body is the evidence
//! package, and `GET /v1/jobs/{id}` reads that package back from the
//! handler-supplied store. There is no streaming investigation.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub enum ServeError {
    Bind(std::io::Error),
    NotLoopback(SocketAddr),
    Io(std::io::Error),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Bind(e) => write!(f, "bind failed: {e}"),
            ServeError::NotLoopback(addr) => {
                write!(f, "refusing non-loopback bind address {addr}")
            }
            ServeError::Io(e) => write!(f, "server I/O: {e}"),
        }
    }
}

impl std::error::Error for ServeError {}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub authorization: Option<String>,
}

pub type HandlerResponse = (u16, Value);

/// Bind `addr` only when it is loopback. Port 0 is allowed and the bound
/// address is returned.
pub fn bind(addr: SocketAddr) -> Result<(TcpListener, SocketAddr), ServeError> {
    if !is_loopback(addr.ip()) {
        return Err(ServeError::NotLoopback(addr));
    }
    let listener = TcpListener::bind(addr).map_err(ServeError::Bind)?;
    listener.set_nonblocking(false).map_err(ServeError::Bind)?;
    let bound = listener.local_addr().map_err(ServeError::Bind)?;
    Ok((listener, bound))
}

/// Serve until `shutdown` is set. Each request is handled on the accept
/// thread; Bookworm acquisitions are already synchronous.
pub fn serve<F>(
    listener: TcpListener,
    token: Option<String>,
    shutdown: Arc<AtomicBool>,
    mut handler: F,
) -> Result<(), ServeError>
where
    F: FnMut(&HttpRequest) -> HandlerResponse,
{
    listener
        .set_nonblocking(true)
        .map_err(ServeError::Io)?;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_one(stream, token.as_deref(), &mut handler);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(ServeError::Io(e)),
        }
    }
    Ok(())
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn handle_one<F>(mut stream: TcpStream, token: Option<&str>, handler: &mut F) -> std::io::Result<()>
where
    F: FnMut(&HttpRequest) -> HandlerResponse,
{
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 1024 * 1024 {
                    return write_raw(&mut stream, 413, br#"{"error":"headers too large"}"#);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(header_end) = header_end else {
        return write_raw(&mut stream, 400, br#"{"error":"incomplete request"}"#);
    };
    let header_bytes = &buf[..header_end];
    let header = String::from_utf8_lossy(header_bytes);
    let mut lines = header.split("\r\n");
    let Some(start) = lines.next() else {
        return write_raw(&mut stream, 400, br#"{"error":"missing request line"}"#);
    };
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_string());
            }
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(content_length);

    if let Some(expected) = token {
        let presented = authorization
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        if presented != expected {
            return write_json(&mut stream, 401, &serde_json::json!({"error":"unauthorized"}));
        }
    }

    let request = HttpRequest {
        method,
        path,
        body,
        authorization,
    };
    let (status, value) = handler(&request);
    write_json(&mut stream, status, &value)
}

fn write_json(stream: &mut TcpStream, status: u16, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    write_raw(stream, status, &body)
}

fn write_raw(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    let _ = stream.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn refuses_non_loopback() {
        let addr = "0.0.0.0:9".parse().unwrap();
        let err = bind(addr).unwrap_err();
        assert!(matches!(err, ServeError::NotLoopback(_)));
    }

    #[test]
    fn health_roundtrip_on_loopback() {
        let (listener, addr) = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let handle = thread::spawn(move || {
            serve(listener, Some("secret".into()), flag, |req| {
                if req.path == "/v1/health" {
                    (200, serde_json::json!({"ok": true}))
                } else {
                    (404, serde_json::json!({"error":"not found"}))
                }
            })
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("200"));
        assert!(text.contains("\"ok\":true"));
        shutdown.store(true, Ordering::SeqCst);
        let _ = handle.join();
    }
}
