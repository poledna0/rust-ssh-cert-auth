use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use std::time::SystemTime;
use koibumi_base32 as base32;
use rand::Rng;
use koibumi_base32::encode;

pub fn valida_codigo_autenticador(codigo: &str) -> String {
    let seconds: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp_custom::<Sha1>(
        DEFAULT_STEP,
        6,
        &base32::decode(&codigo.trim().to_lowercase()).unwrap(),
        seconds,
    )
}

pub fn gerar_segredo() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    encode(&bytes)
}