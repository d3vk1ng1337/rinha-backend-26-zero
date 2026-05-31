//! HTTP/1.1 mínimo: parse de request e as 6 respostas pré-renderizadas
//! (keep-alive). Portável — testado no Mac; usado pelos workers no Linux.

/// Respostas keep-alive por fraud_count (0..5). Content-Length pré-calculado.
/// Corpo "true" = 39 bytes, "false" = 40 bytes.
pub static SCORE_RESP: [&[u8]; 6] = [
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 39\r\n\r\n{\"approved\": true, \"fraud_score\": 0.00}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 39\r\n\r\n{\"approved\": true, \"fraud_score\": 0.20}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 39\r\n\r\n{\"approved\": true, \"fraud_score\": 0.40}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 40\r\n\r\n{\"approved\": false, \"fraud_score\": 0.60}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 40\r\n\r\n{\"approved\": false, \"fraud_score\": 0.80}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 40\r\n\r\n{\"approved\": false, \"fraud_score\": 1.00}",
];

pub static READY_RESP: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";

pub static BAD_RESP: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[inline]
pub fn score_resp(count: u8) -> &'static [u8] {
    SCORE_RESP[(count as usize).min(5)]
}

/// Resultado do parse de um request no início do buffer.
#[derive(Debug, PartialEq)]
pub enum Parsed {
    /// Faltam bytes; espere mais recv.
    Incomplete,
    /// GET /ready — sem corpo.
    Ready { consumed: usize },
    /// POST /fraud-score — corpo em buf[body_start..body_start+body_len].
    Fraud {
        body_start: usize,
        body_len: usize,
        consumed: usize,
    },
    /// Request inválido.
    Bad { consumed: usize },
}

#[inline]
fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> usize {
    // procura "Content-Length:" case-insensitive na primeira ocorrência
    let n = headers.len();
    let mut i = 0;
    while i + 15 <= n {
        if (headers[i] == b'C' || headers[i] == b'c')
            && headers[i..i + 15].eq_ignore_ascii_case(b"Content-Length:")
        {
            let mut p = i + 15;
            while p < n && headers[p] == b' ' {
                p += 1;
            }
            let mut v = 0usize;
            while p < n && headers[p].is_ascii_digit() {
                v = v * 10 + (headers[p] - b'0') as usize;
                p += 1;
            }
            return v;
        }
        i += 1;
    }
    0
}

/// Faz o parse de UM request no início de `buf`.
pub fn parse(buf: &[u8]) -> Parsed {
    let hdr_end = match find_crlfcrlf(buf) {
        Some(p) => p,
        None => return Parsed::Incomplete,
    };
    let headers = &buf[..hdr_end + 4];
    if headers.starts_with(b"POST") {
        let clen = content_length(headers);
        let total = hdr_end + 4 + clen;
        if buf.len() < total {
            return Parsed::Incomplete;
        }
        Parsed::Fraud {
            body_start: hdr_end + 4,
            body_len: clen,
            consumed: total,
        }
    } else if headers.starts_with(b"GET") {
        Parsed::Ready {
            consumed: hdr_end + 4,
        }
    } else {
        Parsed::Bad {
            consumed: hdr_end + 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_lengths_match_content_length() {
        // corpo após \r\n\r\n deve ter 39 (true) / 40 (false) bytes
        for (i, r) in SCORE_RESP.iter().enumerate() {
            let pos = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let body = &r[pos + 4..];
            let expected = if i <= 2 { 39 } else { 40 };
            assert_eq!(body.len(), expected, "resp {i} body len");
        }
    }

    #[test]
    fn parse_post() {
        let req = b"POST /fraud-score HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        match parse(req) {
            Parsed::Fraud {
                body_start,
                body_len,
                consumed,
            } => {
                assert_eq!(body_len, 5);
                assert_eq!(&req[body_start..body_start + body_len], b"hello");
                assert_eq!(consumed, req.len());
            }
            other => panic!("esperava Fraud, veio {other:?}"),
        }
    }

    #[test]
    fn parse_post_incomplete_body() {
        let req = b"POST /fraud-score HTTP/1.1\r\nContent-Length: 10\r\n\r\nhi";
        assert_eq!(parse(req), Parsed::Incomplete);
    }

    #[test]
    fn parse_incomplete_headers() {
        assert_eq!(parse(b"POST /fraud-score HTTP/1.1\r\nHost: x"), Parsed::Incomplete);
    }

    #[test]
    fn parse_ready() {
        let req = b"GET /ready HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse(req) {
            Parsed::Ready { consumed } => assert_eq!(consumed, req.len()),
            other => panic!("esperava Ready, veio {other:?}"),
        }
    }

    #[test]
    fn score_mapping() {
        assert!(score_resp(0).ends_with(b"0.00}"));
        assert!(score_resp(2).ends_with(b"0.40}"));
        assert!(score_resp(3).ends_with(b"0.60}"));
        assert!(score_resp(5).ends_with(b"1.00}"));
        assert!(score_resp(9).ends_with(b"1.00}")); // clamp
    }
}
