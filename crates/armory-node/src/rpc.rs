//! Minimal blocking JSON-RPC client for Bitcoin Core (HTTP/1.1 over TCP, Basic auth).
//!
//! Core's RPC server speaks plain HTTP and is meant for localhost; reach a remote node through an
//! SSH tunnel or similar rather than exposing it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(
        "cannot connect to Bitcoin Core at {addr} (is bitcoind running, with server=1, on this network?)"
    )]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Bitcoin Core rejected the RPC credentials (HTTP 401); check the cookie file or user/password")]
    Unauthorized,
    #[error(
        "cannot read the RPC cookie {path}: {source} (is bitcoind running with this datadir and network?)"
    )]
    Cookie { path: PathBuf, source: std::io::Error },
    #[error("HTTP error {0}")]
    Http(u16),
    #[error("Bitcoin Core error {code}: {message}")]
    Core { code: i64, message: String },
    #[error("malformed RPC response: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Largest RPC response accepted; far above anything this wallet's calls return.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub type Result<T> = std::result::Result<T, RpcError>;

/// How to authenticate.
#[derive(Debug, Clone)]
pub enum Auth {
    /// Read `user:password` from Core's `.cookie` file on every connection (it changes on restart).
    Cookie(PathBuf),
    UserPass(String, String),
}

#[derive(Debug, Clone)]
pub struct RpcClient {
    /// `host:port`.
    pub addr: String,
    pub auth: Auth,
    pub timeout: Duration,
}

impl RpcClient {
    pub fn new(addr: impl Into<String>, auth: Auth) -> Self {
        Self { addr: addr.into(), auth, timeout: Duration::from_secs(300) }
    }

    fn credentials(&self) -> Result<String> {
        let raw = match &self.auth {
            Auth::Cookie(p) => std::fs::read_to_string(p)
                .map_err(|e| RpcError::Cookie { path: p.clone(), source: e })?
                .trim()
                .to_string(),
            Auth::UserPass(u, p) => format!("{u}:{p}"),
        };
        Ok(base64::engine::general_purpose::STANDARD.encode(raw))
    }

    /// Call a method on the node (`wallet = None`) or on a loaded wallet (`/wallet/<name>`).
    pub fn call(&self, wallet: Option<&str>, method: &str, params: Value) -> Result<Value> {
        let path = match wallet {
            Some(w) => format!("/wallet/{w}"),
            None => "/".to_string(),
        };
        let body =
            json!({ "jsonrpc": "1.0", "id": "armory", "method": method, "params": params }).to_string();
        // Read credentials first: a missing cookie is the most common (and most useful) diagnosis.
        let credentials = self.credentials()?;
        let sock = self
            .addr
            .to_socket_addrs()
            .map_err(|e| RpcError::Connect { addr: self.addr.clone(), source: e })?
            .next()
            .ok_or_else(|| RpcError::Malformed("no address".into()))?;
        let mut stream = TcpStream::connect_timeout(&sock, Duration::from_secs(10))
            .map_err(|e| RpcError::Connect { addr: self.addr.clone(), source: e })?;
        stream.set_read_timeout(Some(self.timeout))?;
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            credentials,
            body.len()
        );
        stream.write_all(req.as_bytes())?;
        let (status, payload) = read_response(stream)?;
        if status == 401 {
            return Err(RpcError::Unauthorized);
        }
        // Core returns 404/500 with a JSON-RPC error body for RPC-level errors.
        let v: Value = serde_json::from_slice(&payload).map_err(|_| {
            if status != 200 {
                RpcError::Http(status)
            } else {
                RpcError::Malformed(String::from_utf8_lossy(&payload).into())
            }
        })?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Core {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err.get("message").and_then(Value::as_str).unwrap_or("").to_string(),
            });
        }
        if status != 200 {
            return Err(RpcError::Http(status));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn read_response(stream: TcpStream) -> Result<(u16, Vec<u8>)> {
    // Headroom over the body cap for headers and chunk framing; bounds every read below.
    let mut r = BufReader::new(stream.take(MAX_RESPONSE_BYTES as u64 + 64 * 1024));
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RpcError::Malformed(format!("status line {line:?}")))?;
    let mut length = None;
    let mut chunked = false;
    loop {
        line.clear();
        r.read_line(&mut line)?;
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse::<usize>().ok(),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                _ => {}
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            line.clear();
            r.read_line(&mut line)?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| RpcError::Malformed("chunk size".into()))?;
            if n == 0 {
                break;
            }
            if n > MAX_RESPONSE_BYTES - body.len() {
                return Err(too_large());
            }
            let mut chunk = vec![0u8; n + 2];
            r.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(n) = length {
        if n > MAX_RESPONSE_BYTES {
            return Err(too_large());
        }
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    } else {
        (&mut r).take(MAX_RESPONSE_BYTES as u64 + 1).read_to_end(&mut body)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(too_large());
        }
    }
    Ok((status, body))
}

fn too_large() -> RpcError {
    RpcError::Malformed(format!("response larger than {MAX_RESPONSE_BYTES} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve `reply` verbatim to one request and return a client pointed at it.
    fn client_for(reply: &'static str) -> RpcClient {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(reply.as_bytes());
        });
        RpcClient::new(addr, Auth::UserPass("u".into(), "p".into()))
    }

    #[test]
    fn hostile_sizes_are_errors_not_panics() {
        for reply in [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n",
        ] {
            let e = client_for(reply).call(None, "x", json!([])).unwrap_err().to_string();
            assert!(e.contains("larger than"), "{e}");
        }
    }
}
