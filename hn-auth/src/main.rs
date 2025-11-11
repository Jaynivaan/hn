//! VARUNA (hn-auth) — Auth chamber
//! - Validates INDRA proof on registration
//! - Registers device public keys to presence_id
//! - Issues signed Varuna tickets (Ed25519)
//! - Exposes /health, /auth/begin, /auth/complete, /auth/me, /auth/register_key

use actix_web::{web, App, HttpServer};
use once_cell::sync::Lazy;
use std::{collections::HashMap, env};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::RwLock;

// ---------- Modules (alphabetical by top-level name) ----------
mod middleware; // pop, ticket
mod routes;     // health, login, me, register

// ---------- Public imports from modules (alphabetical by route module) ----------
use middleware::ticket::VarunaSigner;
use routes::health::health;
use routes::login::{begin, complete};
use routes::me::me;
use routes::register::register_key;

// ---------- Config ----------
#[derive(Clone)]
pub struct Config {
    /// Listener port for VARUNA
    pub port: u16,
    /// Base URL for INDRA (Challenge chamber)
    pub chal_base: String,
    /// Ticket Time-To-Live in seconds (default 15m)
    pub ticket_ttl_secs: i64,
    /// Enable DPoP-lite checks on /auth/me
    pub require_pop: bool,
}

impl Default for Config {
    fn default() -> Self {
        let port = env::var("AUTH_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8083);
        let chal_base = env::var("CHALLENGE_BASE").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
        let ttl = env::var("VARUNA_TTL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(900);
        let require_pop = env::var("REQUIRE_POP").map(|v| v == "true").unwrap_or(false);
        Self { port, chal_base, ticket_ttl_secs: ttl, require_pop }
    }
}

// ---------- In-memory state ----------
/**
 * presence_id -> device_pub (base64, 32 bytes)
 * - Bound on /auth/register_key after INDRA proof
 */
pub type Registry = RwLock<HashMap<String, String>>;

/**
 * Login nonces:
 * - For MVP we store as: nonce -> (nonce, exp)
 * - Single-use: removed after /auth/complete
 */
pub type Nonces = RwLock<HashMap<String, (String, OffsetDateTime)>>;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub http: reqwest::Client,
    pub registry: web::Data<Registry>,
    pub nonces: web::Data<Nonces>,
    pub signer: VarunaSigner,
}

// ---------- Startup meta ----------
pub static STARTED_AT: Lazy<String> = Lazy::new(|| OffsetDateTime::now_utc().format(&Rfc3339).unwrap());

// ---------- Main ----------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Log init
    env_logger::init();

    // Load config + HTTP client
    let cfg = Config::default();
    let http = reqwest::Client::builder().build().unwrap();

    // Load or generate Ed25519 signing key for Varuna tickets
    let signer = VarunaSigner::from_env_or_random();

    // Shared app state
    let state = AppState {
        cfg: cfg.clone(),
        http,
        registry: web::Data::new(Registry::default()),
        nonces: web::Data::new(Nonces::default()),
        signer,
    };

    println!("VARUNA (hn-auth) listening on :{}", cfg.port);
    println!("INDRA base   = {}", cfg.chal_base);
    println!("Require DPoP = {}", cfg.require_pop);

    // HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            // ---------- Routes (alphabetical by module) ----------
            .service(health)        // GET  /health
            .service(begin)         // POST /auth/begin
            .service(complete)      // POST /auth/complete
            .service(me)            // GET  /auth/me
            .service(register_key)  // POST /auth/register_key
    })
    .bind(("0.0.0.0", cfg.port))?
    .run()
    .await
}
