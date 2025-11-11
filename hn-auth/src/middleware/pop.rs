
use actix_web::HttpRequest;

/// MVP DPoP-lite: require both headers when enabled
pub fn check_pop_headers(req: &HttpRequest) -> Result<(), &'static str> {
    let ts_ok = req.headers().get("X-Req-Ts").and_then(|v| v.to_str().ok()).is_some();
    let sig_ok = req.headers().get("X-Req-Signature").and_then(|v| v.to_str().ok()).is_some();
    if ts_ok && sig_ok { Ok(()) } else { Err("pop_required") }
}
