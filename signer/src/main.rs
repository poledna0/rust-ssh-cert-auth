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
    println!("[http] POST /create_user payload: username='{}' pubkey='{}' mfa_secret='{}'", info.username, info.pubkey, info.mfa_secret);
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] create_user: erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::criar_usuario(&info.username, &info.password_hash, &info.pubkey, &info.mfa_secret) {
        Ok(_) => {
            println!("[http] create_user: usuário '{}' criado com sucesso", info.username);
            HttpResponse::Ok().body("Usuário criado")
        }
        Err(e) => {
            eprintln!("[http] create_user: erro ao criar usuário: {}", e);
            HttpResponse::InternalServerError().body(format!("Erro: {}", e))
        }
    }
}


#[post("/login")]
async fn login(info: web::Json<LoginRequest>) -> impl Responder {
    println!("[http] POST /login payload: username='{}'", info.username);
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] login: erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            println!("[http] login: usuário encontrado, comparando hashes");
            if u.senha_hash == info.password_hash {
                println!("[http] login: senha correta para user={}", info.username);
                HttpResponse::Ok().body("OK")
            } else {
                println!("[http] login: senha incorreta para user={}", info.username);
                HttpResponse::Unauthorized().body("invalid")
            }
        }
        Err(e) => {
            eprintln!("[http] login: erro ao buscar usuario '{}': {}", info.username, e);
            HttpResponse::Unauthorized().body("invalid")
        }
    }
}


#[post("/verify_mfa")]
async fn verify_mfa(info: web::Json<MfaRequest>) -> impl Responder {
    println!("[http] POST /verify_mfa payload: username='{}', code='{}'", info.username, info.code);
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] verify_mfa: erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            println!("[http] verify_mfa: encontrado user='{}', gerando código esperado", u.nome_usuario);
            let seconds: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let secret_bytes = base32::decode(&u.mfa_secret).unwrap();
            let expected = totp_custom::<Sha1>(DEFAULT_STEP, 6, &secret_bytes, seconds);
            println!("[http] verify_mfa: expected='{}' received='{}'", expected, info.code.trim());
            if expected == info.code.trim() {
                println!("[http] verify_mfa: código válido para user={}", info.username);
                HttpResponse::Ok().body("OK")
            } else {
                println!("[http] verify_mfa: código inválido para user={}", info.username);
                HttpResponse::Unauthorized().body("invalid_mfa")
            }
        }
        Err(e) => {
            eprintln!("[http] verify_mfa: erro ao buscar usuario '{}': {}", info.username, e);
            HttpResponse::Unauthorized().body("invalid")
        }
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



