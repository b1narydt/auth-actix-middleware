//! Request and response payload serialization for BRC-31 authentication.
//!
//! Provides a two-layer API:
//! - **Pure layer:** Generic functions accepting `&str`, `&[u8]`, `&[(String, String)]`
//!   for testability without Actix dependencies.
//! - **Actix wrapper layer:** Thin wrappers that extract data from `HttpRequest`
//!   and `HttpResponse` and delegate to the pure functions.
//!
//! Payload byte layout must be identical to the TypeScript implementation
//! (`auth-express-middleware`) for cross-language signature verification.

use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use actix_web::http::header::HeaderMap;

// ---------------------------------------------------------------------------
// Varint encoding (matching bsv-rust-sdk auth_fetch.rs exactly)
// ---------------------------------------------------------------------------

/// Write a signed Bitcoin-style varint.
///
/// Negative values write a single `0x00` byte (sentinel for "absent/none"),
/// matching the TS SDK `writeVarIntNum(-1)` behavior.
pub(crate) fn write_varint_num(buf: &mut Vec<u8>, val: i64) {
    if val < 0 {
        buf.push(0);
        return;
    }
    let val = val as u64;
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Header filtering (pure layer)
// ---------------------------------------------------------------------------

/// Filter and sort request headers according to BRC-31 signing rules.
///
/// Includes:
/// - Headers starting with `x-bsv-` (excluding `x-bsv-auth*`)
/// - `content-type` (normalized: split on `;`, take first part, trimmed)
/// - `authorization`
///
/// Output is sorted alphabetically by key.
pub fn filter_and_sort_request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut included: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.to_lowercase();
            if key.starts_with("x-bsv-auth") {
                return None;
            }
            if key.starts_with("x-bsv-") || key == "content-type" || key == "authorization" {
                let value = if key == "content-type" {
                    v.split(';').next().unwrap_or("").trim().to_string()
                } else {
                    v.clone()
                };
                Some((key, value))
            } else {
                None
            }
        })
        .collect();
    included.sort_by(|(a, _), (b, _)| a.cmp(b));
    included
}

/// Filter and sort response headers according to BRC-31 signing rules.
///
/// Includes:
/// - Headers starting with `x-bsv-` (excluding `x-bsv-auth*`)
/// - `authorization`
///
/// Note: `content-type` is NOT included for responses (unlike requests).
/// Output is sorted alphabetically by key.
pub fn filter_and_sort_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut included: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.to_lowercase();
            if key.starts_with("x-bsv-auth") {
                return None;
            }
            if key.starts_with("x-bsv-") || key == "authorization" {
                Some((key, v.clone()))
            } else {
                None
            }
        })
        .collect();
    included.sort_by(|(a, _), (b, _)| a.cmp(b));
    included
}

// ---------------------------------------------------------------------------
// Payload serialization (pure layer)
// ---------------------------------------------------------------------------

/// Serialize a request payload for BRC-31 signature verification.
///
/// Layout (matching TS `buildAuthMessageFromRequest`):
/// - `request_nonce` bytes (raw, no varint prefix)
/// - varint(method.len()) + method bytes
/// - varint(path.len()) + path bytes  (varint(-1) if empty)
/// - varint(query.len()) + query bytes (varint(-1) if empty)
/// - varint(headers.len()) then for each: varint(key.len()) + key + varint(val.len()) + val
/// - varint(body.len()) + body bytes   (varint(-1) if body is None)
pub fn serialize_request_payload(
    request_nonce: &[u8],
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Request nonce (raw bytes)
    buf.extend_from_slice(request_nonce);

    // Method
    let method_bytes = method.as_bytes();
    write_varint_num(&mut buf, method_bytes.len() as i64);
    buf.extend_from_slice(method_bytes);

    // Path
    if !path.is_empty() {
        let path_bytes = path.as_bytes();
        write_varint_num(&mut buf, path_bytes.len() as i64);
        buf.extend_from_slice(path_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Query
    if !query.is_empty() {
        let query_bytes = query.as_bytes();
        write_varint_num(&mut buf, query_bytes.len() as i64);
        buf.extend_from_slice(query_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Headers
    write_varint_num(&mut buf, headers.len() as i64);
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);

        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    // Body
    match body {
        Some(b) if !b.is_empty() => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        _ => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

/// Serialize a response payload for BRC-31 signature verification.
///
/// Layout (matching TS `buildResponsePayload`):
/// - `request_nonce` bytes (raw, no varint prefix)
/// - varint(status_code)
/// - varint(headers.len()) then for each: varint(key.len()) + key + varint(val.len()) + val
/// - varint(body.len()) + body bytes (varint(-1) if body is None or empty)
pub fn serialize_response_payload(
    request_nonce: &[u8],
    status_code: u16,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Request nonce (raw bytes)
    buf.extend_from_slice(request_nonce);

    // Status code
    write_varint_num(&mut buf, status_code as i64);

    // Headers
    write_varint_num(&mut buf, headers.len() as i64);
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);

        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    // Body
    match body {
        Some(b) if !b.is_empty() => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        _ => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

// ---------------------------------------------------------------------------
// Actix wrapper layer
// ---------------------------------------------------------------------------

/// Extract headers from an Actix `HttpRequest` as `(String, String)` pairs.
fn headers_from_request(req: &HttpRequest) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Extract headers from an Actix `HeaderMap` as `(String, String)` pairs.
fn headers_from_map(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Serialize a request payload from an Actix `HttpRequest` and body bytes.
///
/// Extracts method, path, query string, and headers from the request,
/// filters/sorts headers per BRC-31 rules, then delegates to
/// `serialize_request_payload`.
pub fn serialize_from_http_request(
    request_nonce: &[u8],
    req: &HttpRequest,
    body: &[u8],
) -> Vec<u8> {
    let raw_headers = headers_from_request(req);
    let filtered_headers = filter_and_sort_request_headers(&raw_headers);
    // Actix's query_string() returns the query WITHOUT the leading '?',
    // but the BRC-31 protocol (and TS SDK) includes the '?' prefix in the
    // serialized payload. Prepend '?' when the query is non-empty.
    let raw_query = req.query_string();
    let query = if raw_query.is_empty() {
        String::new()
    } else {
        format!("?{}", raw_query)
    };

    serialize_request_payload(
        request_nonce,
        req.method().as_str(),
        req.path(),
        &query,
        &filtered_headers,
        if body.is_empty() { None } else { Some(body) },
    )
}

/// Serialize a response payload from status code, headers, and body bytes.
///
/// Filters/sorts headers per BRC-31 response rules, then delegates to
/// `serialize_response_payload`.
pub fn serialize_from_http_response(
    request_nonce: &[u8],
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Vec<u8> {
    let raw_headers = headers_from_map(headers);
    let filtered_headers = filter_and_sort_response_headers(&raw_headers);
    serialize_response_payload(
        request_nonce,
        status.as_u16(),
        &filtered_headers,
        if body.is_empty() { None } else { Some(body) },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Varint encoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_varint_negative_writes_zero() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, -1);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn test_varint_zero_writes_zero() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn test_varint_252_writes_single_byte() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, 252);
        assert_eq!(buf, vec![0xFC]);
    }

    #[test]
    fn test_varint_253_writes_fd_prefix() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, 253);
        // 0xFD followed by 253 as u16 LE = [0xFD, 0x00]
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);
    }

    #[test]
    fn test_varint_65535_writes_fd_prefix() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_varint_65536_writes_fe_prefix() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    // -----------------------------------------------------------------------
    // Request header filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_headers_include_x_bsv_topic() {
        let headers = vec![
            ("X-Bsv-Topic".to_string(), "hello".to_string()),
            ("Other-Header".to_string(), "ignored".to_string()),
        ];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("x-bsv-topic".to_string(), "hello".to_string()));
    }

    #[test]
    fn test_request_headers_exclude_x_bsv_auth() {
        let headers = vec![
            ("x-bsv-auth-version".to_string(), "0.1".to_string()),
            ("x-bsv-auth-nonce".to_string(), "abc".to_string()),
            ("x-bsv-topic".to_string(), "hello".to_string()),
        ];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-topic");
    }

    #[test]
    fn test_request_headers_include_content_type_normalized() {
        let headers = vec![(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        )];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "content-type");
        assert_eq!(result[0].1, "application/json");
    }

    #[test]
    fn test_request_headers_include_authorization() {
        let headers = vec![("Authorization".to_string(), "Bearer abc".to_string())];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "authorization");
    }

    #[test]
    fn test_request_headers_sorted_alphabetically() {
        let headers = vec![
            ("x-bsv-topic".to_string(), "t".to_string()),
            ("authorization".to_string(), "a".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "authorization");
        assert_eq!(result[1].0, "content-type");
        assert_eq!(result[2].0, "x-bsv-topic");
    }

    // -----------------------------------------------------------------------
    // Response header filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_headers_include_x_bsv_topic() {
        let headers = vec![("x-bsv-topic".to_string(), "hello".to_string())];
        let result = filter_and_sort_response_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-topic");
    }

    #[test]
    fn test_response_headers_exclude_x_bsv_auth() {
        let headers = vec![
            ("x-bsv-auth-version".to_string(), "0.1".to_string()),
            ("x-bsv-topic".to_string(), "hello".to_string()),
        ];
        let result = filter_and_sort_response_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-topic");
    }

    #[test]
    fn test_response_headers_include_authorization() {
        let headers = vec![("authorization".to_string(), "Bearer abc".to_string())];
        let result = filter_and_sort_response_headers(&headers);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_response_headers_exclude_content_type() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-bsv-topic".to_string(), "hello".to_string()),
        ];
        let result = filter_and_sort_response_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-topic");
    }

    #[test]
    fn test_response_headers_sorted_alphabetically() {
        let headers = vec![
            ("x-bsv-topic".to_string(), "t".to_string()),
            ("authorization".to_string(), "a".to_string()),
            ("x-bsv-data".to_string(), "d".to_string()),
        ];
        let result = filter_and_sort_response_headers(&headers);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "authorization");
        assert_eq!(result[1].0, "x-bsv-data");
        assert_eq!(result[2].0, "x-bsv-topic");
    }

    // -----------------------------------------------------------------------
    // Fixture-based payload serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_serialize_request_payload_fixture() {
        // Fixture: GET /test, no query, no body, one x-bsv-topic header
        let nonce = [0x01, 0x02, 0x03, 0x04]; // 4-byte nonce for test simplicity
        let method = "GET";
        let path = "/test";
        let query = "";
        let headers = vec![("x-bsv-topic".to_string(), "hello".to_string())];

        let result = serialize_request_payload(&nonce, method, path, query, &headers, None);

        // Expected bytes:
        // [0x01, 0x02, 0x03, 0x04]  -- nonce (4 bytes)
        // [0x03]                     -- varint(3) for "GET"
        // [0x47, 0x45, 0x54]        -- "GET"
        // [0x05]                     -- varint(5) for "/test"
        // [0x2F, 0x74, 0x65, 0x73, 0x74] -- "/test"
        // [0x00]                     -- varint(-1) for empty query
        // [0x01]                     -- varint(1) for 1 header
        // [0x0B]                     -- varint(11) for "x-bsv-topic"
        // b"x-bsv-topic"            -- 11 bytes
        // [0x05]                     -- varint(5) for "hello"
        // b"hello"                   -- 5 bytes
        // [0x00]                     -- varint(-1) for no body

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // nonce
        expected.push(0x03); // varint(3)
        expected.extend_from_slice(b"GET");
        expected.push(0x05); // varint(5)
        expected.extend_from_slice(b"/test");
        expected.push(0x00); // varint(-1) for empty query
        expected.push(0x01); // varint(1) header count
        expected.push(0x0B); // varint(11) for "x-bsv-topic"
        expected.extend_from_slice(b"x-bsv-topic");
        expected.push(0x05); // varint(5) for "hello"
        expected.extend_from_slice(b"hello");
        expected.push(0x00); // varint(-1) for no body

        assert_eq!(
            result, expected,
            "Request payload bytes mismatch.\nGot:      {:02X?}\nExpected: {:02X?}",
            result, expected
        );
    }

    #[test]
    fn test_serialize_response_payload_fixture() {
        // Fixture: 200 OK, one x-bsv-topic header, body "ok"
        let nonce = [0x01, 0x02, 0x03, 0x04];
        let headers = vec![("x-bsv-topic".to_string(), "hello".to_string())];
        let body = b"ok";

        let result = serialize_response_payload(&nonce, 200, &headers, Some(body));

        // Expected bytes:
        // [0x01, 0x02, 0x03, 0x04]  -- nonce
        // [0xC8]                     -- varint(200)
        // [0x01]                     -- 1 header
        // [0x0B] b"x-bsv-topic"     -- header key
        // [0x05] b"hello"            -- header value
        // [0x02] b"ok"              -- body

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.push(0xC8); // varint(200)
        expected.push(0x01); // 1 header
        expected.push(0x0B);
        expected.extend_from_slice(b"x-bsv-topic");
        expected.push(0x05);
        expected.extend_from_slice(b"hello");
        expected.push(0x02); // body length
        expected.extend_from_slice(b"ok");

        assert_eq!(
            result, expected,
            "Response payload bytes mismatch.\nGot:      {:02X?}\nExpected: {:02X?}",
            result, expected
        );
    }

    #[test]
    fn test_serialize_request_payload_with_query_and_body() {
        let nonce = [0xAA];
        let method = "POST";
        let path = "/api";
        let query = "?key=val";
        let headers: Vec<(String, String)> = vec![];
        let body = b"data";

        let result = serialize_request_payload(&nonce, method, path, query, &headers, Some(body));

        let mut expected = Vec::new();
        expected.push(0xAA); // nonce
        expected.push(0x04); // varint(4) for "POST"
        expected.extend_from_slice(b"POST");
        expected.push(0x04); // varint(4) for "/api"
        expected.extend_from_slice(b"/api");
        expected.push(0x08); // varint(8) for "?key=val"
        expected.extend_from_slice(b"?key=val");
        expected.push(0x00); // varint(0) for 0 headers
        expected.push(0x04); // varint(4) for body
        expected.extend_from_slice(b"data");

        assert_eq!(
            result, expected,
            "Request with query+body mismatch.\nGot:      {:02X?}\nExpected: {:02X?}",
            result, expected
        );
    }

    #[test]
    fn test_serialize_response_payload_no_body() {
        let nonce = [0xBB];
        let headers: Vec<(String, String)> = vec![];

        let result = serialize_response_payload(&nonce, 404, &headers, None);

        let mut expected = Vec::new();
        expected.push(0xBB);
        expected.push(0xFD); // varint(404) = 0xFD + 0x94, 0x01
        expected.extend_from_slice(&(404u16).to_le_bytes());
        expected.push(0x00); // 0 headers
        expected.push(0x00); // varint(-1) for no body

        assert_eq!(
            result, expected,
            "Response no-body mismatch.\nGot:      {:02X?}\nExpected: {:02X?}",
            result, expected
        );
    }
}
