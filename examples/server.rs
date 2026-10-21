//! A complete adapter, end to end, with no dependencies: a tiny HTTP/1.1
//! server that renders a form, checks its posts with csrf-sec, and serves an
//! "attacker" page from a second origin that tries to post to it.
//!
//! ```text
//! cargo run --example server
//! ```
//!
//! Then open <http://localhost:7878/> and submit the form (allowed), and open
//! <http://127.0.0.1:7879/> (another site to the browser) and press its button
//! (refused as cross-site). Every decision is logged on the console.
//!
//! This is a demonstration, not a web server: it reads one request per
//! connection, trusts nothing it reads, and handles errors by closing the
//! connection.

use std::{
    fmt::Write as _,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use csrf_sec::{Csrf, FIELD_NAME, OsPads, PadSource, RequestFacts};

/// This site's origin, as the browser addresses it.
const SITE: &str = "http://localhost:7878";
/// Largest request head or body this demo reads.
const LIMIT: usize = 16 * 1024;

/// What the adapter extracts from one HTTP request.
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }

    /// The session id from the `__Host-`-style cookie (plain `sid` here: the
    /// demo runs on http, and browsers only accept `__Host-` on https).
    fn session(&self) -> Option<&str> {
        self.header("cookie")
            .split(';')
            .map(str::trim)
            .find_map(|c| c.strip_prefix("sid="))
            .filter(|s| !s.is_empty())
    }

    /// A field from an `application/x-www-form-urlencoded` body. The token
    /// alphabet needs no percent-decoding.
    fn form_field(&self, name: &str) -> &[u8] {
        self.body
            .split(|&b| b == b'&')
            .find_map(|pair| pair.strip_prefix(name.as_bytes())?.strip_prefix(b"="))
            .unwrap_or(&[])
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.take(LIMIT as u64));
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).ok()?;
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        let (k, v) = header.split_once(':')?;
        headers.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    let mut request = Request {
        method,
        path,
        headers,
        body: Vec::new(),
    };
    let length: usize = request.header("content-length").parse().unwrap_or(0);
    request.body.resize(length.min(LIMIT), 0);
    reader.read_exact(&mut request.body).ok()?;
    Some(request)
}

fn respond(stream: &mut TcpStream, status: &str, extra: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
}

fn new_session_id() -> String {
    let mut seed = [0u8; 16];
    let _ = OsPads.fill(&mut seed);
    seed.iter().fold(String::with_capacity(32), |mut id, b| {
        let _ = write!(id, "{b:02x}");
        id
    })
}

/// The bank: renders the form and checks its posts.
fn site(csrf: &Csrf, mut stream: TcpStream) {
    let Some(req) = read_request(&mut stream) else {
        return;
    };
    let (session, set_cookie) = match req.session() {
        Some(s) => (s.to_owned(), String::new()),
        None => {
            let s = new_session_id();
            let cookie = format!("Set-Cookie: sid={s}; HttpOnly; SameSite=Lax; Path=/\r\n");
            (s, cookie)
        }
    };

    // The adapter's whole job: hand csrf-sec the facts as plain values.
    let facts = RequestFacts::new(&req.method)
        .fetch_site(req.header("sec-fetch-site"))
        .origin(req.header("origin"))
        .referer(req.header("referer"))
        .own_origin(SITE);

    if req.method == "POST" {
        let token = req.form_field(FIELD_NAME);
        let verdict = csrf.check(&facts, &session, token);
        println!(
            "POST {} sec-fetch-site={:?} origin={:?} -> {}",
            req.path,
            req.header("sec-fetch-site"),
            req.header("origin"),
            match &verdict {
                Ok(v) => format!("allowed ({:?})", v.origin_check()),
                Err(r) => format!("refused: {} (severity {})", r.reason(), r.severity()),
            }
        );
        match verdict {
            Ok(_) => respond(
                &mut stream,
                "200 OK",
                &set_cookie,
                "<h1>Saved.</h1><a href=\"/\">Back</a>",
            ),
            // Generic refusal for the client; the reason stays in the log.
            Err(_) => respond(
                &mut stream,
                "403 Forbidden",
                &set_cookie,
                "<h1>Forbidden</h1>",
            ),
        }
        return;
    }

    let token = match csrf.issue(&session) {
        Ok(t) => t,
        Err(e) => {
            println!("issue failed: {e}");
            respond(&mut stream, "500 Internal Server Error", "", "");
            return;
        }
    };
    let page = format!(
        "<!doctype html><title>Bank</title><h1>Change email</h1>\
         <form method=\"post\" action=\"/email\">\
         <input type=\"hidden\" name=\"{FIELD_NAME}\" value=\"{token}\">\
         <input name=\"email\" value=\"me@example.com\"> <button>Save</button></form>"
    );
    respond(&mut stream, "200 OK", &set_cookie, &page);
}

/// The attacker: another site that posts to the bank.
fn attacker(mut stream: TcpStream) {
    let Some(_) = read_request(&mut stream) else {
        return;
    };
    let page = format!(
        "<!doctype html><title>Win a prize</title><h1>Claim your prize</h1>\
         <form method=\"post\" action=\"{SITE}/email\">\
         <input type=\"hidden\" name=\"email\" value=\"attacker@evil.example\">\
         <input type=\"hidden\" name=\"{FIELD_NAME}\" value=\"\">\
         <button>Claim</button></form>"
    );
    respond(&mut stream, "200 OK", "", &page);
}

fn main() -> std::io::Result<()> {
    // A real service loads a persisted key; the demo makes one per run.
    let mut key = [0u8; 32];
    OsPads
        .fill(&mut key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let csrf = Arc::new(Csrf::new(key).map_err(|e| std::io::Error::other(e.to_string()))?);

    let bank = TcpListener::bind("127.0.0.1:7878")?;
    let evil = TcpListener::bind("127.0.0.1:7879")?;
    println!("site:     {SITE}/");
    println!("attacker: http://127.0.0.1:7879/ (another site to the browser)");

    thread::spawn(move || {
        for stream in evil.incoming().flatten() {
            attacker(stream);
        }
    });
    for stream in bank.incoming().flatten() {
        let csrf = Arc::clone(&csrf);
        thread::spawn(move || site(&csrf, stream));
    }
    Ok(())
}
