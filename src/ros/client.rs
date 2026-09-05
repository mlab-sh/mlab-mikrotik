//! HTTP handler for the RouterOS REST API.
//!
//! One base URL, `<scheme>://<host>/rest`, and HTTP Basic auth on every
//! request — RouterOS issues no token, so the password itself travels with
//! each call and the client holds it for the length of the run.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::ros::config::Profile;

/// Cap on a response body, so a misbehaving router cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 32 << 20;

/// A non-2xx response from the REST API.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub detail: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API error {}", self.status.as_u16())?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if !self.detail.is_empty() {
            write!(f, " ({})", self.detail)?;
        }
        if self.status == StatusCode::UNAUTHORIZED {
            write!(
                f,
                "\nhint: check the user and password, and that the user's group has the `rest-api` policy"
            )?;
        }
        if self.status == StatusCode::NOT_FOUND {
            write!(
                f,
                "\nhint: /rest needs RouterOS 7.1+ with the www-ssl (or www) service enabled"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A configured connection to one RouterOS instance.
pub struct Client {
    http: reqwest::Client,
    base: String,
    user: String,
    password: String,
}

impl Client {
    /// Build a client from a validated profile.
    pub fn new(profile: &Profile, timeout: Duration) -> Result<Self> {
        profile.validate()?;

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .danger_accept_invalid_certs(profile.insecure())
            // Basic credentials are attached per request, but a redirect would
            // replay them at whatever host the router names; refuse instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the HTTP client")?;

        Ok(Client {
            http,
            base: format!("{}/rest", profile.root()?),
            user: profile.user.clone(),
            password: profile.password.clone(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// The core handler: one request, one parsed JSON body.
    ///
    /// `path` is relative to `/rest` and starts with `/`; it is sent as given
    /// (RouterOS menu paths legitimately contain slashes), so callers escape
    /// their own path segments with [`esc`].
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self
            .http
            .request(method.clone(), &url)
            .basic_auth(&self.user, Some(&self.password));
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.header(CONTENT_TYPE, "application/json").json(b);
        }

        let resp = req.send().await.map_err(|e| {
            // reqwest hides the interesting part (certificate, DNS, refused) in
            // the source chain, so flatten it before adding a hint.
            let cause = error_chain(&e);
            let mut msg = format!("{method} {url}: {cause}");
            let lower = cause.to_lowercase();
            if lower.contains("certificate") || lower.contains("unknownissuer") || lower.contains("tls") {
                msg.push_str(
                    "\nhint: routers serve a self-signed certificate; drop --secure, or pass --insecure",
                );
            } else if e.is_timeout() {
                msg.push_str("\nhint: raise --timeout");
            } else if e.is_connect() {
                // Which service to name depends on the one being dialled: a
                // router with only `www` on refuses 443, and the reverse.
                msg.push_str(if self.base.starts_with("https://") {
                    "\nhint: is the router reachable, and is the www-ssl service enabled? (--scheme http for plain www)"
                } else {
                    "\nhint: is the router reachable, and is the www service enabled? (--scheme https for www-ssl)"
                });
            }
            anyhow!(msg)
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(anyhow!(
                "{method} {url} redirected to {to}; not following it, the credentials would leak to the new host"
            ));
        }

        let bytes = resp.bytes().await.context("reading the response body")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!("response body over {MAX_RESPONSE_BYTES} bytes"));
        }

        if !status.is_success() {
            return Err(parse_error(status, &bytes).into());
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).with_context(|| {
            let preview: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
            format!("decoding the response of {method} {url}: {preview}")
        })
    }

    /// A GET returning a single object, such as `/system/resource`.
    pub async fn get_one(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, &[], None).await
    }

    /// A GET returning a menu's rows. RouterOS has no paging: a menu answers
    /// with the whole collection in one array.
    pub async fn list(&self, path: &str) -> Result<Vec<Value>> {
        let v = self.request(Method::GET, path, &[], None).await?;
        Ok(array_of(&v))
    }

    /// The same, restricted to named properties.
    ///
    /// `.proplist` is the only defence against a menu that answers with tens of
    /// thousands of rows, so every wide collection goes through here.
    pub async fn list_props(&self, path: &str, props: &[&str]) -> Result<Vec<Value>> {
        let q = [(".proplist".to_string(), props.join(","))];
        let v = self.request(Method::GET, path, &q, None).await?;
        Ok(array_of(&v))
    }
}

/// A JSON value as a vector of rows: arrays pass through, `null` is empty, and
/// a lone object counts as one row — a menu with a single entry answers with
/// the object itself on some versions.
fn array_of(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// Turn a REST error body into a typed error.
///
/// RouterOS answers `{"error":401,"message":"Unauthorized","detail":"..."}`,
/// but the web server in front of it can refuse first with an HTML page.
fn parse_error(status: StatusCode, body: &[u8]) -> ApiError {
    let text = summarize(&String::from_utf8_lossy(body));

    let (message, detail) = match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let message = v
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| text.clone());
            let detail = v
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            (message, detail)
        }
        Err(_) => (text, String::new()),
    };

    ApiError {
        status,
        message,
        detail,
    }
}

/// Reduce a response body to one readable line: markup stripped, whitespace
/// collapsed, truncated. A v6 router answers a REST call with its whole login
/// page, which would otherwise bury the status code under a stylesheet.
fn summarize(body: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut tag = String::new();
    let mut in_opaque = false;
    let mut last_space = true;

    for ch in body.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let name = tag.trim().to_ascii_lowercase();
                if name.starts_with("style") || name.starts_with("script") {
                    in_opaque = true;
                } else if name.starts_with("/style") || name.starts_with("/script") {
                    in_opaque = false;
                }
                // A tag is a word boundary: without this a title and the
                // heading after it run together into one word.
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c if in_tag => tag.push(c),
            _ if in_opaque => {}
            c if c.is_whitespace() => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c => {
                out.push(c);
                last_space = false;
                if out.chars().count() >= 160 {
                    out.push('…');
                    break;
                }
            }
        }
    }

    let trimmed = out.trim();
    if trimmed.is_empty() && !body.is_empty() {
        return format!("non-JSON body, {} bytes", body.len());
    }
    trimmed.to_string()
}

/// Flatten an error and its sources into one line.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_menu_with_one_entry_still_counts_as_one_row() {
        assert_eq!(array_of(&json!([1, 2])).len(), 2);
        assert!(array_of(&Value::Null).is_empty());
        assert_eq!(array_of(&json!({"name": "ether1"})).len(), 1);
    }

    #[test]
    fn parse_error_reads_the_routeros_error_shape() {
        let e = parse_error(
            StatusCode::UNAUTHORIZED,
            br#"{"error":401,"message":"Unauthorized","detail":"not permitted"}"#,
        );
        assert_eq!(e.message, "Unauthorized");
        assert_eq!(e.detail, "not permitted");
        assert!(e.to_string().contains("rest-api"), "the hint is attached");
    }

    #[test]
    fn a_login_page_is_reduced_to_a_line() {
        let page = "<!doctype html><html><head><title>RouterOS</title>\
                    <style>body {font-family:Tahoma;}</style></head>\
                    <body><h1>404 Not Found</h1></body></html>";
        let e = parse_error(StatusCode::NOT_FOUND, page.as_bytes());
        assert_eq!(
            e.message, "RouterOS 404 Not Found",
            "a tag is a word boundary, not a join"
        );
        assert!(!e.message.contains('<'), "no markup survives");
        assert!(!e.message.contains("Tahoma"), "the stylesheet goes too");
        assert!(e.to_string().contains("RouterOS 7.1+"));
    }

    #[test]
    fn a_body_with_no_text_at_all_is_described_rather_than_echoed() {
        assert_eq!(
            summarize("<html><body></body></html>"),
            "non-JSON body, 26 bytes"
        );
        assert_eq!(summarize(""), "");
    }
}
