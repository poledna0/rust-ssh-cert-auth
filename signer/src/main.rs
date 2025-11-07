use actix_web::{post, web, App, HttpResponse, HttpServer, Responder, get};
use serde::Deserialize;

mod db;

#[derive(Deserialize)]
struct CreateUser {
    username: String,
    password_hash: String,
    pubkey: String,
}

#[post("/create_user")]
async fn create_user(info: web::Json<CreateUser>) -> impl Responder {
    if let Err(e) = db::inicializar_db() {
        eprintln!("Erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB init error: {}", e));
    }

    match db::criar_usuario(&info.username, &info.password_hash, &info.pubkey) {
        Ok(_) => HttpResponse::Ok().body("Usuário criado"),
        Err(e) => {
            eprintln!("Erro ao criar usuário: {}", e);
            HttpResponse::InternalServerError().body(format!("Erro: {}", e))
        }
    }
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Signer server iniciando em 0.0.0.0:8080");
    HttpServer::new(|| App::new().service(create_user).service(health))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
