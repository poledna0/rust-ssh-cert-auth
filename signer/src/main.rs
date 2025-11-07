use actix_web::{post, web, App, HttpResponse, HttpServer, Responder, get};
use serde::Deserialize;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use std::time::SystemTime;
use koibumi_base32 as base32;

mod db;

// #[derive(Deserialize)]  == essa struct pode ser convertida de JSON para Rust, Actix automaticamente converte isso num CreateUser
#[derive(Deserialize)]
struct CreateUser {
    username: String,
    password_hash: String,
    pubkey: String,
    mfa_secret: String,
}


#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct MfaRequest {
    username: String,
    code: String,
}






#[post("/create_user")]
// info: web::Json<CreateUser> >>> Actix recebe o corpo JSON da requisição e faz o parse direto pra struct CreateUser
async fn create_user(info: web::Json<CreateUser>) -> impl Responder {

    if let Err(e) = db::inicializar_db() {
        eprintln!("Erro inicializando DB: {}", e);
        // retorna 500 Internal Server Error
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::criar_usuario(&info.username, &info.password_hash, &info.pubkey, &info.mfa_secret) {
        Ok(_) => HttpResponse::Ok().body("Usuário criado"),
        Err(e) => {
            eprintln!("Erro ao criar usuário: {}", e);
            HttpResponse::InternalServerError().body(format!("Erro: {}", e))
        }
    }
}


#[post("/login")]
async fn login(info: web::Json<LoginRequest>) -> impl Responder {
    if let Err(e) = db::inicializar_db() {
        eprintln!("Erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            if u.senha_hash == info.password_hash {
                HttpResponse::Ok().body("OK")
            } else {
                HttpResponse::Unauthorized().body("invalid")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("invalid"),
    }
}


#[post("/verify_mfa")]
async fn verify_mfa(info: web::Json<MfaRequest>) -> impl Responder {
    if let Err(e) = db::inicializar_db() {
        eprintln!("Erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            let seconds: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let secret_bytes = base32::decode(&u.mfa_secret).unwrap();
            let expected = totp_custom::<Sha1>(DEFAULT_STEP, 6, &secret_bytes, seconds);
            if expected == info.code.trim() {
                HttpResponse::Ok().body("OK")
            } else {
                HttpResponse::Unauthorized().body("invalid_mfa")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("invalid"),
    }
}

// rota padrao para saber se esta rodando o servidor web
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Servidor rodando na porta 8080");
    HttpServer::new(|| App::new().service(create_user).service(login).service(verify_mfa).service(health))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}



