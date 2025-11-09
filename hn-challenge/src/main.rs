//===========================================================

#![cfg_attr(debug_assertions, allow(unused_imports, dead_code))]

//HelloNivaan -Challenge Chamber(INDRA)
//phase:MVP-1 | Essence : Proof-through-Awareness
//----------------------------------------------------------------
//PURPOSE:
//Indra  is the vigilant sentinel of Awareness.
//This chamber verifies sincere presence before permitting protected actions.
//
//Proof-Of-Awareness(PoA) flow: 

//1) POST /challenge/issue  -> {nonce, difficulty, expires_at}
//2) Client finds  `answer` s.t. sha 256 (nonce || answer) has N leading zeros
//3) POST /challenge/verify  -> returns short lived proof token.
//4) GET  /protected/ping    -> requires header X-proof: <token>
//
//Design values:
//-Light + eco-conscious (low-difficulty),human-timed, vendor-free
//-Transparent comments that teach teh *why* , no t just *how *
//- the system runs safely behind an **nginx edge firewall** that 
//applies universal HTTPS and securitys headers.
//---------------------------------------------------------------------
//SYSTEM - TOPOLOGY : COSMIC FIREWALL CHAIN.
//===================================================
//[user] -> [Nginx Edge (cosmic Armor)] => [Gateway Chamber (Agni)] -> [Challenge Chamber (Indra)]
//
//-Nginx = universal protector - TLS, HSTS, master CSP policy.
//-Gateway = purifier -filters, rate limits, request firewalls.
//-Challenge = verifier - ensures conscious intent via Proof-of-Awareness.
//
//=======================================================================
// MVP-1 Enhancements (Beyond a naive PoW)
//-----------------------------------------------------------------------
// -concurrency: RwLock + HashMap (many readers; one writer).
// - Nonce burn: Remove nonce immediately after successful verification.
// -single-use tokens: Remove proof token after first successful use.
// - Background GC: Periodic cleanup of expired Nonces/tokens via actix_rt.
// - Time Precision: always compare expiry < now_utc() using time  crate.
// - Rigorous Errors: clear separation of nonce_unknown / nonce_expired / proof_invalid.
// - Graceful Headers: never panic on missing X-Proof; respond with proof_required.
//
// Spiritual Echo of design(gam)
// - a challenge dissolves when awareness dawns (nonce burning )
// - proof of presence cannot be replayed live in now (single use token)
// - Indras thunder clears stale clouds (garbage collections functionality)
//===============================================================================
//Nginx Coordination Notes:
//--------------------------------------
//-All strict headers(CSP, HSTS, XFO) are ideally handled by NGINX.
//-The App still includes *optional local headers* (for dev or isolation).
//-Toggle with ENV var `ENABLE_SEC_HEADERS=true|false`.
//-This prevents duplicate CSPs or conflicts while retaining safety.
//--------------------------------------------------------------------------

//--------------------------------------------
// SECTION MAP (Implementation Path)
//--------------------------------------------
//[A] Imports and constants
//[B] Data Models (Req/Resp)
//[C] In-Memory stores with RwLock
//[D] Utility functions
//[E] Security Headers Toggle (Enabele and align with gateway)
//[F] Endpoints:
//  F1: GET /health
//  F2: POST /challenge/issue
//  F3: POST /challenge/verify
//  F4: GET /protected/ping
// [G] Background Garbage Collector
// [H] Server Bootstrap
// [I] Unit and integration tests (incl. PoA brute-force Helper)
//-----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// [A] Imports and constants (Step1)
//-----------------------------------------------------------------------------
//crates:
//actix_web, serde, sha2, rand, once_cell, time, std::sync::RwLock,
//std::collections::HashMap, actix_rt(for GC).
// constants: 
//Difficulty = 3 (low difficulty of PoA)
//NONCE_TTL_SECS = 60
//TOKEN_TTL_SECS = 120
//GC_INTERVAL_SECS = 30
//
//TIME PRECISION:
//-Use offsetDateTime::now_utc().
//-Always compare expiry < now_utc().
//============================================================
use actix_web::{ web, middleware, App, HttpResponse,  HttpServer, Responder};
use once_cell::sync::Lazy;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use time::{Duration, OffsetDateTime};
// use Actix's built-in runtime (no external actix_rt crate needed)
use actix_web::rt::time::sleep;

//constants
pub const DIFFICULTY: usize = 3;
pub const NONCE_TTL_SECS: i64 = 60;
pub const TOKEN_TTL_SECS: i64 = 120;
pub const GC_INTERVAL_SECS: u64 = 30; 
//----------------------------------------------------------------------------
// [B] Data Models (Req/Resp) (Step2)
//-----------------------------------------------------------------------------
mod b_data_models {
    use super::*;
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct IssueRequest {
        pub nonce_len: Option<usize>,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct IssueResponse {
        pub nonce: String,
        pub difficulty: usize,
        #[serde(with = "time::serde::rfc3339")]   // <-- this line
        pub expires_at: OffsetDateTime,
    }

        // Client -> /challenge/verify
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct VerifyRequest {
        pub nonce: String,
        pub answer: String, // arbitrary user-provided string
    }

    // Server -> /challenge/verify
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct VerifyResponse {
        pub token: String,
        #[serde(with = "time::serde::rfc3339")]
        pub expires_at: OffsetDateTime,
    }

    // Server -> /protected/ping (success)
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ProofOk {
        pub pong: bool,
        pub single_use_consumed: bool,
    }

    // Rigorous error shapes for clarity
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ErrorResponse {
        pub code: &'static str,
        pub message: &'static str,
    }

}


//----------------------------------------------------------------------------
// [C] In-Memory stores with RwLock (Step3)
//-----------------------------------------------------------------------------
mod c_stores {
    use super::*;
    pub static NONCES: Lazy<RwLock<HashMap<String, OffsetDateTime>>> =
        Lazy::new(|| RwLock::new(HashMap::new()));

    pub static TOKENS: Lazy<RwLock<HashMap<String, OffsetDateTime>>> =
        Lazy::new(|| RwLock::new(HashMap::new()));
}

//----------------------------------------------------------------------------
// [D] Utility functions (Step4)
//-----------------------------------------------------------------------------
mod d_utils {
    use super::*;

    // ---- Time helpers ----
    pub fn now_utc() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
    pub fn expires_in_secs(secs: i64) -> OffsetDateTime {
        now_utc() + Duration::seconds(secs)
    }

    // ---- Randoms ----
    pub fn random_string(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    // ---- Hashing ----
    pub fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // ---- PoA condition: check N leading *hex* zeros ----
    pub fn has_leading_hex_zeros(hex: &str, n: usize) -> bool {
        hex.chars().take(n).all(|c| c == '0')
    }

    // Keep your original “touch” if you like
    pub fn scaffold_touch() {
        let _digest = sha2::Sha256::digest(b"seed");
        let _rand: String = random_string(8);
        let _ = (Duration::seconds(1), now_utc());
    }
}

//----------------------------------------------------------------------------
// [E] Default security Headers(align with gateway) (Step5)
//-----------------------------------------------------------------------------
mod e_headers {
    use super::*;
    //toggle service level headers (edge Nginx can own CSP/HSTS/etc.)
    pub fn enabled() -> bool {
        matches!(
            std::env::var("ENABLE_SEC_HEADERS").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE")
        )
    }

    // always build the header set (we’ll conditionally apply it in H)
    pub fn sec_headers() -> middleware::DefaultHeaders {
        middleware::DefaultHeaders::new()
            .add(("X-Content-Type-Options", "nosniff"))
            .add(("X-Frame-Options", "SAMEORIGIN"))
            .add((
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            ))
    }

    // keep your original API around if you want it later
    pub fn maybe_headers() -> Option<middleware::DefaultHeaders> {
        if enabled() { Some(sec_headers()) } else { None }
    }
}

//----------------------------------------------------------------------------
// [F] Endpoints: (Step6)
//-----------------------------------------------------------------------------
mod f_endpoints {
    use super::*;
    use crate::b_data_models::*;
    use crate::c_stores::*;
    use crate::d_utils::*;

    //Minimal health so the server is testable immediately.
    pub async fn health() -> impl Responder {
        HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"ok": true}"#)
    }

    // ---------------------------
    // F2: POST /challenge/issue
    // Body: IssueRequest { nonce_len?: usize }
    // Resp: IssueResponse { nonce, difficulty, expires_at }
    // ---------------------------
    pub async fn issue(req: web::Json<IssueRequest>) -> impl Responder {
        let nonce_len = req.nonce_len.unwrap_or(16).clamp(8, 64);
        let nonce = d_utils::random_string(nonce_len);
        let expiry = d_utils::expires_in_secs(super::NONCE_TTL_SECS);

        // store nonce -> expiry
        {
            let mut map = NONCES.write().expect("NONCES write poisoned");
            map.insert(nonce.clone(), expiry);
        }

        let resp = IssueResponse {
            nonce,
            difficulty: super::DIFFICULTY,
            expires_at: expiry,
        };
        HttpResponse::Ok().json(resp)
    }

    // ---------------------------
    // F3: POST /challenge/verify
    // Body: VerifyRequest { nonce, answer }
    // Resp: VerifyResponse { token, expires_at }  OR ErrorResponse
    // ---------------------------
    pub async fn verify(req: web::Json<VerifyRequest>) -> impl Responder {
        use crate::b_data_models::{ErrorResponse, VerifyResponse};

        // 1) Do the (cheap) PoA work outside locks
        let payload = format!("{}{}", req.nonce, req.answer);
        let hex = crate::d_utils::sha256_hex(payload.as_bytes());
        if !crate::d_utils::has_leading_hex_zeros(&hex, super::DIFFICULTY) {
            let err = ErrorResponse { code: "proof_invalid", message: "insufficient leading zeros" };
            return HttpResponse::BadRequest().json(err);
        }

        // 2) Atomically validate + burn the nonce
        let now = crate::d_utils::now_utc();
        {
            let mut nonces = crate::c_stores::NONCES.write().expect("NONCES write poisoned");
            match nonces.get(&req.nonce).copied() {
                None => {
                    let err = ErrorResponse { code: "nonce_unknown", message: "nonce not found" };
                    return HttpResponse::BadRequest().json(err);
                }
                Some(exp) if exp < now => {
                    nonces.remove(&req.nonce); // clean expired
                    let err = ErrorResponse { code: "nonce_expired", message: "nonce expired" };
                    return HttpResponse::BadRequest().json(err);
                }
                Some(_) => {
                    nonces.remove(&req.nonce); // burn single-use
                }
            }
        }

        // 3) Mint single-use token
        let token = crate::d_utils::random_string(32);
        let token_expiry = crate::d_utils::expires_in_secs(super::TOKEN_TTL_SECS);
        {
            let mut tokens = crate::c_stores::TOKENS.write().expect("TOKENS write poisoned");
            tokens.insert(token.clone(), token_expiry);
        }

        let resp = VerifyResponse { token, expires_at: token_expiry };
        HttpResponse::Ok().json(resp)
    }


    // ---------------------------
    // F4: GET /protected/ping
    // Header: X-Proof: <token>
    // Resp: ProofOk OR ErrorResponse
    // ---------------------------
    pub async fn protected(req: actix_web::HttpRequest) -> impl Responder {
        use crate::b_data_models::{ErrorResponse, ProofOk};

        // 1) Extract token
        let Some(token) = req.headers()
            .get("X-Proof")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
        else {
            let err = ErrorResponse { code: "proof_required", message: "missing X-Proof header" };
            return HttpResponse::TooManyRequests().json(err);
        };

        // 2) Atomically validate + consume the token
        let now = crate::d_utils::now_utc();
        {
            let mut tokens = crate::c_stores::TOKENS.write().expect("TOKENS write poisoned");
            match tokens.get(&token).copied() {
                None => {
                    let err = ErrorResponse { code: "proof_unknown", message: "token not found" };
                    return HttpResponse::Unauthorized().json(err);
                }
                Some(exp) if exp < now => {
                    tokens.remove(&token); // clean expired
                    let err = ErrorResponse { code: "proof_expired", message: "token expired" };
                    return HttpResponse::Unauthorized().json(err);
                }
                Some(_) => {
                    tokens.remove(&token); // single-use consume
                }
            }
        } // lock released

        // 3) Success
        let ok = ProofOk { pong: true, single_use_consumed: true };
        HttpResponse::Ok().json(ok)
    }

}

    
//----------------------------------------------------------------------------
// [G] Background Garbage Collector (Step7)
//-----------------------------------------------------------------------------
mod g_gc {
    use super::*;
    use crate::c_stores::*;
    use crate::d_utils::*;

    pub async fn gc_loop() {
        loop {
            sleep(std::time::Duration::from_secs(super::GC_INTERVAL_SECS)).await;
            let now = now_utc();

            // Nonces
            {
                let mut map = NONCES.write().expect("NONCES write poisoned");
                map.retain(|_, &mut exp| exp >= now);
            }
            // Tokens
            {
                let mut map = TOKENS.write().expect("TOKENS write poisoned");
                map.retain(|_, &mut exp| exp >= now);
            }
        }
    }
}


//----------------------------------------------------------------------------
// [H] Server Bootstrap (Step8)
//-----------------------------------------------------------------------------
mod h_bootstrap {
    use super::*;
    use actix_web::middleware::Condition;
    use crate::e_headers::{enabled, sec_headers};
    use crate::f_endpoints::health;

    // keep bootstrap runner separate; the crate entrypoint is at the bottom
    pub async fn run() -> std::io::Result<()> {
        println!("Challenge (indra) at http://127.0.0.1:8081");
        println!(
            "   ENABLE_SEC_HEADERS={}",
            std::env::var("ENABLE_SEC_HEADERS").unwrap_or_else(|_| "false".into())
        );

         // GC loop
        actix_web::rt::spawn(crate::g_gc::gc_loop());

        

        HttpServer::new(|| {
            let _ = crate::d_utils::scaffold_touch();
            let enable = enabled();              // bool
            let headers = sec_headers();         // DefaultHeaders

            App::new()
                .wrap(Condition::new(enable, headers))
                // F1
                .route("/health", web::get().to(health))
                // F2
                .route("/challenge/issue", web::post().to(crate::f_endpoints::issue))
                // F3
                .route("/challenge/verify", web::post().to(crate::f_endpoints::verify))
                // F4
                .route("/protected/ping", web::get().to(crate::f_endpoints::protected))
        })

                
        .bind(("127.0.0.1", 8081))?
        .run()
        .await
    }
}

// ----------------------------------------------------------------------------
// [I] Unit and integration tests (incl. PoA brute-force Helper) (Step9)
#[cfg(test)]
mod i_tests {


}
// --------------------------------------------------------------------------//
//delegate to bootstrap main
//--------------------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    h_bootstrap::run().await
}
