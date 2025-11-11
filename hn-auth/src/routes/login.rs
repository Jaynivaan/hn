use actix_web::{post, web, HttpResponse, Responder};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// Bring base64 Engine into scope (0.22 API)
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::AppState;

#[derive(Serialize)]
pub struct BeginResp {
    pub nonce: String,
    pub exp: String,
}

#[derive(Deserialize)]
pub struct CompleteBody {
    pub presence_id: String,
    pub nonce: String,
    pub signature: String, // base64 of 64 bytes
}

#[derive(Serialize)]
pub struct CompleteResp {
    pub varuna_ticket: String,
    pub exp: String,
}

#[post("/auth/begin")]
pub async fn begin(state: web::Data<AppState>) -> impl Responder {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();

    let exp = OffsetDateTime::now_utc() + Duration::minutes(5);

    {
        // MVP: store by nonce -> (nonce, exp)
        let mut nonces = state.nonces.write().await;
        nonces.insert(nonce.clone(), (nonce.clone(), exp));
    }

    HttpResponse::Ok().json(BeginResp {
        nonce,
        exp: exp.format(&Rfc3339).unwrap(),
    })
}

#[post("/auth/complete")]
pub async fn complete(body: web::Json<CompleteBody>, state: web::Data<AppState>) -> impl Responder {
    // 1) Validate nonce exists and not expired
    {
        let map = state.nonces.read().await;
        match map.get(&body.nonce) {
            Some((_, exp)) if OffsetDateTime::now_utc() <= *exp => {},
            _ => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"nonce_invalid_or_expired"})),
        }
    }

    // 2) Lookup device_pub (base64 32 bytes) for presence
    let device_pub_b64 = {
        let reg = state.registry.read().await;
        match reg.get(&body.presence_id) {
            Some(p) => p.clone(),
            None => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"presence_unknown"})),
        }
    };
    let pub_bytes = match STANDARD.decode(device_pub_b64) {
        Ok(v) => v,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"device_pub_corrupt"})),
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

    // 3) Verify signature over nonce
    let sig_bytes = match STANDARD.decode(&body.signature) {
        Ok(v) => v,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"signature_invalid_b64"})),
    };
    if sig_bytes.len() != 64 {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"signature_len"}));
    }
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error":"signature_array"})),
    };
    let sig = Signature::from_bytes(&sig_arr);
    if vk.verify(body.nonce.as_bytes(), &sig).is_err() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"signature_verify_failed"}));
    }

    // 4) Issue Varuna ticket
    let now = OffsetDateTime::now_utc();
    let exp = now + time::Duration::seconds(state.cfg.ticket_ttl_secs);
    let ticket = state.signer.issue_ticket(&body.presence_id, exp);

    // 5) Invalidate nonce (single-use)
    {
        let mut map = state.nonces.write().await;
        map.remove(&body.nonce);
    }

    HttpResponse::Ok().json(CompleteResp {
        varuna_ticket: ticket,
        exp: exp.format(&Rfc3339).unwrap(),
    })
}
