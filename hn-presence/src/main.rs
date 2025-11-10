//=====================================================================
// HelloNivaan — Presence Chamber (VAYU)
// phase: MVP-1 | Essence: Breath-of-Identity (Sigil w/o PII)
//---------------------------------------------------------------------
// PURPOSE
// Vayu issues a light, privacy-safe Presence ID ("sigil") WITHOUT storing PII.
// Deterministic: same (alias, client_salt, server PEPPER) → same presence_id.
//
// Endpoints:
//   GET  /health            -> 200 {"ok":true}
//   POST /sigil/derive      -> 200 {presence_id, algo, created_at}
//      Body: { "alias": "raven42", "client_salt": "deviceA-001" }
//
// Security headers (dev-friendly):
//   Set ENABLE_SEC_HEADERS=1 to enable CSP/XFO/nosniff middleware.
//   Keep PRESENCE_PEPPER secret in prod (env var).
//=====================================================================

use actix_web::{web, middleware, App, HttpResponse, HttpServer, Responder};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use actix_web::middleware::Condition;

//---------------------------
// [A] Config & constants
//---------------------------
// Server-side secret that never leaves the box (set in environment).
// Dev default is safe for testing; DO NOT use in production.
static PEPPER: Lazy<String> = Lazy::new(|| {
    std::env::var("PRESENCE_PEPPER").unwrap_or_else(|_| "dev-pepper-change-me".into())
});

fn headers_enabled() -> bool {
    matches!(
        std::env::var("ENABLE_SEC_HEADERS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn security_headers() -> middleware::DefaultHeaders {
    middleware::DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "SAMEORIGIN"))
        .add((
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        ))
}

//---------------------------
// [B] Models
//---------------------------
#[derive(Serialize)]
struct Health { ok: bool }

#[derive(Deserialize)]
struct DeriveReq {
    // Pseudonym only — never real name/email.
    alias: String,
    // Client-side random salt (per device/app).
    client_salt: String,
}

#[derive(Serialize)]
struct DeriveResp {
    presence_id: String,       // 24-hex sigil (96 bits)
    algo: &'static str,        // "sha256(hex)[first_24]"
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

// [B+] Verify models
#[derive(Deserialize)]
struct VerifyReq {
    alias: String,
    client_salt: String,
    presence_id: String,
}
#[derive(Serialize)]
struct VerifyResp {
    ok: bool,
    expected: String,
}


//---------------------------
/* [C] Utilities */
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}
//timing safe compare
fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq; // add dep: subtle = "2"
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// [C+] Deterministic presence id (must mirror derive_sigil)
fn compute_presence_id(alias: &str, salt: &str) -> String {
    let material = format!("{}:{}:{}", alias.trim(), salt.trim(), &*PEPPER);
    let hex = sha256_hex(material.as_bytes());
    hex[..24.min(hex.len())].to_string()
}

// [C+] Minimal input validation (ASCII, length bounds)
fn valid_alias(a: &str) -> bool {
    let t = a.trim();
    (3..=48).contains(&t.len()) && t.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}
fn valid_salt(s: &str) -> bool {
    let t = s.trim();
    (3..=64).contains(&t.len()) && t.chars().all(|c| c.is_ascii_alphanumeric() || "_-.#@/+".contains(c))
}

//---------------------------
// [D] Endpoints
//---------------------------
async fn health() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .json(Health { ok: true })
}

/// POST /sigil/derive
/// Body: { "alias":"raven42", "client_salt":"deviceA-001" }
/// Rule: presence_id = sha256( alias ":" client_salt ":" PEPPER )[0..24]
async fn derive_sigil(body: web::Json<DeriveReq>) -> impl Responder {
    if !valid_alias(&body.alias) || !valid_salt(&body.client_salt) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code":"bad_input",
            "message":"alias/salt invalid (len or charset)"
        }));
    }

    let presence_id = compute_presence_id(&body.alias, &body.client_salt);
    let resp = DeriveResp {
        presence_id,
        algo: "sha256(hex)[first_24]",
        created_at: OffsetDateTime::now_utc(),
    };
    HttpResponse::Ok().json(resp)
}
/// POST /sigil/verify
/// Body: { alias, client_salt, presence_id }
async fn sigil_verify(body: web::Json<VerifyReq>) -> impl Responder {
    if !valid_alias(&body.alias) || !valid_salt(&body.client_salt) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code":"bad_input",
            "message":"alias/salt invalid (len or charset)"
        }));
    }
    let expected = compute_presence_id(&body.alias, &body.client_salt);
    HttpResponse::Ok().json(VerifyResp {
        ok: ct_eq(&expected, &body.presence_id),
        expected,
    })
}
//add a global JSON extractor config later;

//---------------------------
// [E] Bootstrap
//---------------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Presence (Vayu) @ http://127.0.0.1:8082");
    println!("  ENABLE_SEC_HEADERS={}", std::env::var("ENABLE_SEC_HEADERS").unwrap_or_else(|_| "false".into()));
    println!("  PRESENCE_PEPPER    ={}", if std::env::var("PRESENCE_PEPPER").is_ok() { "(set)" } else { "(default dev pepper!)" });

    env_logger::init();

    HttpServer::new(|| {
        App::new()
            .wrap(Condition::new(headers_enabled(), security_headers()))
            .route("/health", web::get().to(health))
            .route("/sigil/derive", web::post().to(derive_sigil))
            .route("/sigil/verify", web::post().to(sigil_verify))

    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}

