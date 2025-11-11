use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use rand::RngCore;

// Bring base64 Engine into scope (0.22 API)
use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::alphabet::URL_SAFE;

static B64URL_ENGINE: Lazy<GeneralPurpose> = Lazy::new(|| {
    GeneralPurpose::new(&URL_SAFE, GeneralPurposeConfig::new())
});

#[derive(Clone)]
pub struct VarunaSigner {
    sk: SigningKey,
    vk: VerifyingKey,
    kid: String,
    #[allow(dead_code)]
    ttl_secs: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // presence_id
    pub iat: i64,
    pub exp: i64,
    pub kid: String,
    // helpers (not signed)
    #[serde(skip)]
    pub iat_rfc3339: String,
    #[serde(skip)]
    pub exp_rfc3339: String,
}

impl VarunaSigner {
    pub fn from_env_or_random() -> Self {
        let kid = std::env::var("VARUNA_SIGN_KID").unwrap_or_else(|_| "key1".into());
        let ttl = std::env::var("VARUNA_TTL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(900);

        // Expect URL-safe base64 for the secret (base64url). Change engine if you want STANDARD b64.
        let sk: SigningKey = if let Ok(b64url) = std::env::var("VARUNA_SIGN_SK_B64") {
            let bytes_vec = B64URL_ENGINE
                .decode(b64url)
                .expect("VARUNA_SIGN_SK_B64 invalid base64url");
            assert_eq!(bytes_vec.len(), 32, "VARUNA_SIGN_SK_B64 must be 32 bytes");

            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes_vec); // <-- avoids try_into panics
            SigningKey::from_bytes(&seed)
        } else {
            // Dev key: new each boot (tickets die on restart)
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            SigningKey::from_bytes(&seed)
        };

        let vk: VerifyingKey = sk.verifying_key();
        Self { sk, vk, kid, ttl_secs: ttl }
    }

    pub fn issue_ticket(&self, presence_id: &str, exp: OffsetDateTime) -> String {
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        let exp_i = exp.unix_timestamp();

        let claims = Claims {
            sub: presence_id.to_string(),
            iat,
            exp: exp_i,
            kid: self.kid.clone(),
            iat_rfc3339: OffsetDateTime::from_unix_timestamp(iat).unwrap().format(&Rfc3339).unwrap(),
            exp_rfc3339: exp.format(&Rfc3339).unwrap(),
        };

        let payload = serde_json::to_vec(&claims).unwrap();
        let payload_b64 = B64URL_ENGINE.encode(&payload);

        let sig: Signature = self.sk.sign(payload_b64.as_bytes());
        let sig_b64 = B64URL_ENGINE.encode(sig.to_bytes());

        format!("{}.{}", payload_b64, sig_b64)
    }

    pub fn verify_ticket(&self, token: &str) -> Result<Claims, &'static str> {
        let mut parts = token.split('.');
        let payload_b64 = parts.next().ok_or("token_format")?;
        let sig_b64 = parts.next().ok_or("token_format")?;
        if parts.next().is_some() { return Err("token_format"); }

        let payload = B64URL_ENGINE.decode(payload_b64).map_err(|_| "payload_b64")?;
        let sig_bytes = B64URL_ENGINE.decode(sig_b64).map_err(|_| "sig_b64")?;
        if sig_bytes.len() != 64 { return Err("sig_len"); }

        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "sig_array")?;
        let sig = Signature::from_bytes(&sig_arr);

        // Verify signature over the BASE64URL payload (not raw JSON)
        self.vk.verify(payload_b64.as_bytes(), &sig).map_err(|_| "sig_verify")?;

        let mut claims: Claims = serde_json::from_slice(&payload).map_err(|_| "claims_parse")?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now > claims.exp { return Err("token_expired"); }

        claims.iat_rfc3339 = OffsetDateTime::from_unix_timestamp(claims.iat).unwrap().format(&Rfc3339).unwrap();
        claims.exp_rfc3339 = OffsetDateTime::from_unix_timestamp(claims.exp).unwrap().format(&Rfc3339).unwrap();
        Ok(claims)
    }
}

pub fn verify_authorization_bearer(header: &str, signer: &VarunaSigner) -> Result<Claims, &'static str> {
    let pref = "Bearer ";
    if !header.starts_with(pref) { return Err("bearer_required"); }
    let token = &header[pref.len()..];
    signer.verify_ticket(token)
}
