use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::AppState;

// Bring base64 Engine into scope (0.22 API)
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")] // or "camelCase" if your client sends camel
pub struct RegisterBody {
    pub presence_id: String,
    pub device_pub: String, // base64 (32 bytes)
    #[serde(default)]
    #[allow(dead_code)]
    pub vows: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResp {
    pub auth_id: String,
    pub registered_at: String,
}

async fn verify_indra_proof(http: &reqwest::Client, chal_base: &str, token: &str) -> Result<(), ()> {
    let url = format!("{}/protected/ping", chal_base);
    let res = http.get(&url).header("X-Proof", token).send().await.map_err(|_| ())?;
    if res.status().is_success() { Ok(()) } else { Err(()) }
}

#[post("/auth/register_key")]
pub async fn register_key(req: HttpRequest, body: web::Json<RegisterBody>, state: web::Data<AppState>) -> impl Responder {
    // Require INDRA PoA
    let Some(tok) = req.headers().get("X-Proof").and_then(|v| v.to_str().ok()) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"proof_required"}));
    };
    if verify_indra_proof(&state.http, &state.cfg.chal_base, tok).await.is_err() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error":"proof_unknown"}));
    }

    // Validate device_pub (base64 of 32 bytes)
    let Ok(bytes) = STANDARD.decode(&body.device_pub) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error":"device_pub_invalid_b64"}));
    };
    if bytes.len() != 32 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error":"device_pub_len"}));
    }

    {
        let mut map = state.registry.write().await;
        map.insert(body.presence_id.clone(), body.device_pub.clone());
    }

    let auth_id = nanoid::nanoid!(16);
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    HttpResponse::Ok().json(RegisterResp { auth_id, registered_at: now })
}
