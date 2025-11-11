use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use time::OffsetDateTime;

use crate::AppState;
use crate::middleware::ticket::verify_authorization_bearer;
// 👇 We explicitly use the lightweight header check helper so pop.rs is “used”.
use crate::middleware::pop::check_pop_headers;

#[derive(Serialize)]
pub struct MeResp {
    pub presence_id: String,
    pub godname: String,
    pub issued_at: String,
    pub exp: String,
}

/// GET /auth/me
/// - Verifies the Varuna ticket in Authorization: Bearer <ticket>
/// - If DPoP-lite is enabled, it ALSO verifies a per-request signature bound to the registered device key.
///   Message format for PoP: "<METHOD>\n<PATH_AND_QUERY>\n<X-Req-Ts>"
#[get("/auth/me")]
pub async fn me(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // 1) Verify Bearer ticket (Varuna). Reject early if missing/invalid.
    let Some(authz) = req.headers().get("Authorization").and_then(|v| v.to_str().ok()) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"auth_required"}));
    };
    let claims = match verify_authorization_bearer(authz, &state.signer) {
        Ok(c) => c,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": e})),
    };

    // 2) Optional DPoP-lite. When enabled, we require AND verify:
    //    - X-Req-Ts (fresh timestamp)
    //    - X-Req-Signature = Ed25519_sign("<METHOD>\n<PATH>\n<X-Req-Ts>")
    //    using the device_pub bound earlier to this presence_id.
    if state.cfg.require_pop {
        // 2a) Lightweight header presence check (keeps pop.rs in use; good early error messages).
        if let Err(err) = check_pop_headers(&req) {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": err}));
        }

        // 2b) Extract values (safe unwraps now that we passed header check).
        let ts = req.headers().get("X-Req-Ts").and_then(|v| v.to_str().ok()).unwrap();
        let sig_b64 = req.headers().get("X-Req-Signature").and_then(|v| v.to_str().ok()).unwrap();

        // 2c) Build the signed message exactly as the client should sign.
        //     NOTE: include query string if present (path_and_query); fall back to path.
        let method = req.method().as_str();
        let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(req.uri().path());
        let msg = format!("{method}\n{path}\n{ts}");

        // 2d) Lookup device_pub (base64) bound to this presence_id during /auth/register_key.
        let device_pub_b64 = {
            let reg = state.registry.read().await;
            match reg.get(&claims.sub) {
                Some(p) => p.clone(),
                None => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"presence_unknown"})),
            }
        };

        // 2e) Parse device_pub (must be 32 bytes), then build verifying key.
        let pub_bytes = match STANDARD.decode(device_pub_b64) {
            Ok(v) => v,
            Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"device_pub_b64"})),
        };
        if pub_bytes.len() != 32 {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error":"device_pub_len"}));
        }
        let pub_arr: [u8; 32] = match pub_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"device_pub_array"})),
        };
        let vk = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"device_pub_invalid"})),
        };

        // 2f) Parse signature (64 bytes).
        let sig_bytes = match STANDARD.decode(sig_b64) {
            Ok(v) => v,
            Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"sig_b64"})),
        };
        if sig_bytes.len() != 64 {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error":"sig_len"}));
        }
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"sig_array"})),
        };
        let sig = Signature::from_bytes(&sig_arr);

        // 2g) Verify PoP signature over the exact message bytes.
        if vk.verify(msg.as_bytes(), &sig).is_err() {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error":"pop_verify_failed"}));
        }

        // 2h) (Optional) Basic freshness check (±60s). Adjust window if needed.
        if let Ok(ts_i) = ts.parse::<i64>() {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if (now - ts_i).abs() > 60 {
                return HttpResponse::Unauthorized().json(serde_json::json!({"error":"pop_ts_skew"}));
            }
        }
    }

    // 3) Success: return claims view.
    HttpResponse::Ok().json(MeResp {
        presence_id: claims.sub,
        godname: "Varuna".into(),
        issued_at: claims.iat_rfc3339,
        exp: claims.exp_rfc3339,
    })
}
