//=====================================================================
// Hellonivaan — Gateway Chamber (Agni)
// Phase: MVP-2  |  Essence: Purification through protection
//---------------------------------------------------------------------
// Agni stands at the threshold. Every response leaving this service
// passes through the "flame" of DefaultHeaders — a practical firewall
// that teaches browsers how to behave and reduces attack surface.
//
// What's here:
//  1) /health — minimal truthful heartbeat { "ok": true }.
//  2) DefaultHeaders — security principles as HTTP headers.
//  3) Small, readable test to prove headers exist on /health.
//
// Notes:
//  - HSTS is meaningful only over HTTPS in production (browsers ignore
//    it on http:// during local dev). We keep it here to document intent.
//  - X-Frame-Options is kept alongside CSP frame-ancestors; redundancy
//    is okay and often seen in hardening guides.
//=====================================================================

use actix_web::{
    get,
    middleware,
    App,
    HttpResponse,
    HttpServer,
    Responder,
};
use serde::Serialize;

//---------------------------------------------------------------------
// Data: /health payload — the breath check of the gateway
//---------------------------------------------------------------------
#[derive(Serialize)]
struct Health { ok: bool }

//---------------------------------------------------------------------
// Route: GET /health
// -> Purpose: Truthful liveness signal for Orchestrator and LB checks.
// -> Returns: 200 OK + application/json { "ok": true }
//---------------------------------------------------------------------
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .json(Health { ok: true })
}

//---------------------------------------------------------------------
// Function: security_headers()
// -> Agni's flame. Applied to *every* response via DefaultHeaders.
// -> Each header is annotated with its intent.
//---------------------------------------------------------------------
fn security_headers() -> middleware::DefaultHeaders {
    middleware::DefaultHeaders::new()

        // Transport discipline (effective over HTTPS in prod):
        // Instructs browsers to *only* use HTTPS for this host for 1 year
        // (and all subdomains). Prevents protocol downgrades.
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))

        // Framing discipline:
        // Blocks clickjacking by disallowing <iframe> from other origins.
        .add(("X-Frame-Options", "SAMEORIGIN"))

        // MIME discipline:
        // Prevents content-type “sniffing” — accept types as declared.
        .add(("X-Content-Type-Options", "nosniff"))

        // Content governance (CSP):
        // Reduce sources to self, disallow plugins/objects, block hostile
        // framing, disallow mixed content upgrades.
        .add((
            "Content-Security-Policy",
            "default-src 'self'; \
             script-src 'self'; \
             object-src 'none'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'none'; \
             upgrade-insecure-requests"
        ))

        // Privacy: do not forward referrers (leaks paths/tokens).
        .add(("Referrer-Policy", "no-referrer"))

        // Capability minimization: deny high-risk hardware APIs by default.
        .add(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))

        // Legacy plugin isolation (e.g., Flash) — fully disallow.
        .add(("X-Permitted-Cross-Domain-Policies", "none"))
}

//---------------------------------------------------------------------
// Main: bind, ignite, and serve
//---------------------------------------------------------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("\nGateway (Agni) ignited → http://127.0.0.1:8080");
    println!("Phase: MVP-2  |  Purpose: Purify every response with security headers.\n");

    HttpServer::new(|| {
        App::new()
            // Wrap all responses with Agni's flame
            .wrap(security_headers())
            // Minimal truth endpoint
            .service(health)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

//=====================================================================
// Tests — MVP-2 proof: /health returns 200 and required headers
// Run: cargo test --quiet
//=====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::header::HeaderName, test, App};

    #[actix_web::test]
    async fn health_has_core_security_headers() {
        // Build a test app with the same headers + endpoint
        let app = test::init_service(
            App::new()
                .wrap(security_headers())
                .service(health)
        ).await;

        // Call /health
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;

        // Assert 2xx
        assert!(resp.status().is_success(), "health should be 200 OK");

        // Assert presence of our hardening headers (lowercase names)
        let must = [
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
            "referrer-policy",
            "permissions-policy",
            "x-permitted-cross-domain-policies",
        ];

        for h in must {
            let name = HeaderName::from_lowercase(h.as_bytes()).unwrap();
            assert!(
                resp.headers().get(&name).is_some(),
                "missing header: {}", h
            );
        }
    }
}
