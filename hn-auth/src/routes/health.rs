use actix_web::{get, web, Responder};
use serde::Serialize;

use crate::STARTED_AT;

#[derive(Serialize)]
pub struct Health {
    pub ok: bool,
    pub chamber: &'static str,
    pub started_at: &'static str,
}

#[get("/health")]
pub async fn health() -> impl Responder {
    web::Json(Health {
        ok: true,
        chamber: "auth/VARUNA",
        started_at: &STARTED_AT,
    })
}
