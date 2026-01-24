use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::Duration;
use serde::{Serialize, de::DeserializeOwned};
use windows::core::{PCWSTR, HSTRING};
use windows::Win32::Foundation::{GetLastError, NO_ERROR, ERROR_INSUFFICIENT_BUFFER};
use windows::Win32::Networking::WinHttp::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WinHttp error: {0}")]
    WinHttp(u32),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Status code: {0}")]
    Status(u32),
    #[error("Url parse error")]
    UrlParse,
}

#[derive(Clone, Debug)]
pub struct Client {
    proxy: Option<String>,
    user_agent: String,
}

impl Client {
    pub fn new() -> Self {
        Self::builder().build().unwrap()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Post, url)
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), Method::Get, url)
    }
}

#[derive(Default)]
pub struct ClientBuilder {
    proxy: Option<String>,
    user_agent: Option<String>,
}

impl ClientBuilder {
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy.url);
        self
    }

    pub fn user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn timeout(self, _duration: Duration) -> Self {
        self
    }

    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        if let Some(ua) = headers.get("User-Agent") {
            self.user_agent = Some(ua.to_string());
        }
        self
    }

    pub fn build(self) -> Result<Client, Error> {
        Ok(Client {
            proxy: self.proxy,
            user_agent: self.user_agent.unwrap_or_else(|| "Mozilla/5.0".to_string()),
        })
    }
}

pub struct Proxy {
    url: String,
}

impl Proxy {
    pub fn all(url: impl Into<String>) -> Result<Self, Error> {
        Ok(Self { url: url.into() })
    }
}

pub struct HeaderMap {
    headers: std::collections::HashMap<String, String>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self { headers: std::collections::HashMap::new() }
    }
    
    pub fn insert(&mut self, key: &str, value: HeaderValue) {
        self.headers.insert(key.to_string(), value.0);
    }
    
    pub fn get(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }
}

pub struct HeaderValue(String);
impl HeaderValue {
    pub fn from_static(s: &str) -> Self {
        Self(s.to_string())
    }
}

pub const USER_AGENT: &str = "User-Agent";

#[derive(Debug, Clone, Copy)]
pub enum Method {
    Get,
    Post,
}

pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: String,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

impl RequestBuilder {
    pub fn new(client: Client, method: Method, url: &str) -> Self {
        Self {
            client,
            method,
            url: url.to_string(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn json<T: Serialize>(mut self, json: &T) -> Self {
        if let Ok(body) = serde_json::to_vec(json) {
            self.body = body;
            self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        }
        self
    }

    pub fn multipart(mut self, form: Form) -> Self {
        self.body = form.body;
        let closing = format!("--{}--\r\n", form.boundary);
        self.body.extend_from_slice(closing.as_bytes());
        self.headers.insert("Content-Type".to_string(), format!("multipart/form-data; boundary={}", form.boundary));
        self
    }

    pub async fn send(self) -> Result<Response, Error> {
        let client = self.client.clone();
        let method = self.method;
        let url = self.url.clone();
        let headers = self.headers.clone();
        let body = self.body.clone();

        tokio::task::spawn_blocking(move || {
            send_request_sync(client, method, url, headers, body)
        }).await.map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    }
}

pub struct Response {
    status: u32,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        StatusCode(self.status)
    }

    pub async fn json<T: DeserializeOwned>(self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(Error::Json)
    }
    
    pub async fn text(self) -> Result<String, Error> {
        String::from_utf8(self.body).map_err(Error::Utf8)
    }

    pub async fn bytes(self) -> Result<Vec<u8>, Error> {
        Ok(self.body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u32);
impl StatusCode {
    pub const OK: StatusCode = StatusCode(200);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);

    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Form {
    boundary: String,
    body: Vec<u8>,
}

impl Form {
    pub fn new() -> Self {
        let boundary = format!("------------------------{}", uuid::Uuid::new_v4().simple());
        Self {
            boundary,
            body: Vec::new(),
        }
    }

    pub fn text(mut self, key: &str, value: String) -> Self {
        let part = format!(
            "--{{}}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{{}}\r\n",
            self.boundary, key, value
        );
        self.body.extend_from_slice(part.as_bytes());
        self
    }

    pub fn part(mut self, key: &str, part: Part) -> Self {
        let head = format!(
            "--{{}}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{{}}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            self.boundary, key, part.file_name
        );
        self.body.extend_from_slice(head.as_bytes());
        self.body.extend_from_slice(&part.bytes);
        self.body.extend_from_slice(b"\r\n");
        self
    }
    
    // Finalize needed? We'll just append the closing boundary when sending or here?
    // reqwest likely does it at the end. We should ensure the body is valid.
    // My multipart implementation in RequestBuilder uses raw body.
    // I need to make sure the closing boundary is added.
    // The safest way is to add it in RequestBuilder or ensure `Form` adds it.
    // But `Form` is builder-like.
    // Let's make `part` and `text` not consume self but return self, and have a `finish` logic?
    // Or just append "--boundary--" when converting to bytes?
    // But `RequestBuilder` takes `Form` and extracts `body`.
    // I'll add a helper `finish()` to Form or just append it in `multipart()`.
    // Wait, `multipart()` takes `Form`. I can append the closing boundary inside `multipart()`.
}

pub struct Part {
    bytes: Vec<u8>,
    file_name: String,
}

impl Part {
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            file_name: "file".to_string(),
        }
    }

    pub fn file_name(mut self, name: String) -> Self {
        self.file_name = name;
        self
    }
}

// Low-level WinHTTP Wrapper
fn send_request_sync(
    client: Client,
    method: Method,
    url_str: String,
    headers: std::collections::HashMap<String, String>,
    mut body: Vec<u8>,
) -> Result<Response, Error> {
    unsafe {
        // Parse URL
        // WinHttp requires hostname and path separately.
        // Simple parsing:
        let url_parts = url_str.splitn(4, '/').collect::<Vec<&str>>(); 
        // http://host/path -> ["http:", "", "host", "path"]
        // https://host/path -> ["https:", "", "host", "path"]
        
        if url_parts.len() < 3 {
            return Err(Error::UrlParse);
        }
        
        let scheme = url_parts[0];
        let host_port = url_parts[2];
        let path = if url_parts.len() > 3 {
            format!("/{}", url_parts[3..].join("/"))
        } else {
            "/".to_string()
        };

        // Handle Port
        let (host, port) = if let Some(idx) = host_port.find(':') {
            (&host_port[..idx], host_port[idx+1..].parse::<u16>().unwrap_or(if scheme == "https:" { 443 } else { 80 }))
        } else {
            (host_port, if scheme == "https:" { 443 } else { 80 })
        };
        
        let user_agent = HSTRING::from(&client.user_agent);
        let proxy_type = if client.proxy.is_some() { WINHTTP_ACCESS_TYPE_NAMED_PROXY } else { WINHTTP_ACCESS_TYPE_DEFAULT_PROXY };
        let proxy_name = client.proxy.as_ref().map(|s| HSTRING::from(s)).unwrap_or_default();
        let proxy_bypass = HSTRING::new();

        let h_session = WinHttpOpen(
            PCWSTR::from_raw(user_agent.as_ptr()),
            proxy_type,
            if client.proxy.is_some() { PCWSTR::from_raw(proxy_name.as_ptr()) } else { PCWSTR::null() },
            if client.proxy.is_some() { PCWSTR::from_raw(proxy_bypass.as_ptr()) } else { PCWSTR::null() },
            0,
        );

        if h_session.is_invalid() {
            return Err(Error::WinHttp(GetLastError().0));
        }

        let h_connect = WinHttpConnect(
            h_session,
            PCWSTR::from_raw(HSTRING::from(host).as_ptr()),
            port,
            0,
        );

        if h_connect.is_invalid() {
            WinHttpCloseHandle(h_session);
            return Err(Error::WinHttp(GetLastError().0));
        }

        let method_str = match method {
            Method::Get => "GET",
            Method::Post => "POST",
        };

        let flags = if scheme == "https:" { WINHTTP_FLAG_SECURE } else { 0 };

        let h_request = WinHttpOpenRequest(
            h_connect,
            PCWSTR::from_raw(HSTRING::from(method_str).as_ptr()),
            PCWSTR::from_raw(HSTRING::from(path).as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            flags,
        );

        if h_request.is_invalid() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(Error::WinHttp(GetLastError().0));
        }

        // Add Headers
        for (k, v) in headers {
            let header_str = format!("{}: {}", k, v);
            let h_header = HSTRING::from(header_str);
            if WinHttpAddRequestHeaders(
                h_request,
                PCWSTR::from_raw(h_header.as_ptr()),
                h_header.len() as u32,
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
            ).as_bool() == false {
                 // Ignore header errors?
            }
        }

        // Send Request
        let mut total_bytes = body.len() as u32;
        let p_data = if total_bytes > 0 { body.as_mut_ptr() as *mut c_void } else { null_mut() };
        
        if WinHttpSendRequest(
            h_request,
            PCWSTR::null(),
            0,
            p_data,
            total_bytes,
            total_bytes,
            0,
        ).as_bool() == false {
            let err = GetLastError().0;
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(Error::WinHttp(err));
        }

        if WinHttpReceiveResponse(h_request, null_mut()).as_bool() == false {
            let err = GetLastError().0;
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(Error::WinHttp(err));
        }

        // Get Status Code
        let mut status_code: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(
            h_request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            &mut status_code as *mut _ as *mut c_void,
            &mut size,
            null_mut(),
        );

        // Read Body
        let mut response_body = Vec::new();
        loop {
            let mut dw_size: u32 = 0;
            if WinHttpQueryDataAvailable(h_request, &mut dw_size).as_bool() == false {
                break;
            }
            if dw_size == 0 {
                break;
            }

            let mut buffer = vec![0u8; dw_size as usize];
            let mut downloaded: u32 = 0;
            if WinHttpReadData(
                h_request,
                buffer.as_mut_ptr() as *mut c_void,
                dw_size,
                &mut downloaded,
            ).as_bool() == true {
                buffer.truncate(downloaded as usize);
                response_body.extend(buffer);
            } else {
                break;
            }
        }

        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);

        Ok(Response {
            status: status_code,
            body: response_body,
        })
    }
}
