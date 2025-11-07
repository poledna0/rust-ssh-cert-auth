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



fn valida_codigo_autenticador(codigo: &str) -> String {
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

// rota padrao para saber se esta rodando o servidor web
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Servidor rodando na porta 8080");
    HttpServer::new(|| App::new().service(create_user).service(health))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
