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
    code: String, // codigo do autenticador
}

#[derive(Deserialize)]
struct ChavePublicaRequest {
    username: String,
    pubkey: String, // a chave publica ssh do usuario
}

#[post("/create_user")]
async fn create_user(info: web::Json<CreateUser>) -> impl Responder {
    println!("[http] POST /create_user payload: username='{}' mfa_secret='{}'", info.username, info.mfa_secret);
    // tratar erro caso nao consiga inicializar o banco de dados
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] create_user: erro inicializando DB: {}", e);
        // e dai ele retorna um erro http p cliente
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    // instancia um objeto Usuario e tenta salvar no banco de dados
    match db::criar_usuario(&info.username, &info.password_hash, &info.mfa_secret) {
        Ok(_) => {
            println!("[http] create_user: usuário '{}' criado com sucesso", info.username);
            HttpResponse::Ok().body("Usuário criado")
        }
        // caso n consiga manda o msm erro de inicializacao do db
        Err(e) => {
            eprintln!("[http] create_user: erro ao criar usuário: {}", e);
            HttpResponse::InternalServerError().body(format!("Erro: {}", e))
        }
    }
}

// end point para login
#[post("/login")]
async fn login(info: web::Json<LoginRequest>) -> impl Responder {
    println!("[http] POST /login payload: username='{}'", info.username);
    // tentando inicializar o banco de dados dnv
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] login: erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("DB error: {}", e));
    }

    // procura o usuario no banco de dados
    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            println!("[http] login: usuário encontrado, comparando hashes");
            // compara o hash da senha do banco com o recebido se der certo responde OK 
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
    // mesma lore do db
    println!("[http] POST /verify_mfa recebido: usuario='{}', codigo='{}'", info.username, info.code);
    if let Err(e) = db::inicializar_db() {
        eprintln!("[http] verify_mfa: erro inicializando DB: {}", e);
        return HttpResponse::InternalServerError().body(format!("Erro no DB: {}", e));
    }

    match db::buscar_usuario_para_login(&info.username) {
        Ok(u) => {
            println!("[http] verify_mfa: usuario '{}' encontrado, gerando código esperado", u.nome_usuario);

            // aqui gera o codigo TOTP esperado e compara com o recebido, tipo do meu codigo de experiencia criativa do semestre passado, na vdd literalmente crnl c -- v
            let segundos: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let bytes_secretos = base32::decode(&u.mfa_secret).unwrap(); // pega na estrutura do usuario o mfa_secret para gerar os 6 digitos
            let codigo_esperado = totp_custom::<Sha1>(DEFAULT_STEP, 6, &bytes_secretos, segundos);

            println!("[http] verify_mfa: esperado='{}' recebido='{}'", codigo_esperado, info.code.trim());

            // compara os codigos
            if codigo_esperado == info.code.trim() {
                println!("[http] verify_mfa: código válido para usuario={}", info.username);
                HttpResponse::Ok().body("aguardando_chave_publica")
            } else {
                println!("[http] verify_mfa: código inválido para usuario={}", info.username);
                HttpResponse::Unauthorized().body("mfa_invalido")
            }
        }
        Err(e) => {
            eprintln!("[http] verify_mfa: erro ao buscar usuario '{}': {}", info.username, e);
            HttpResponse::Unauthorized().body("invalido")
        }
    }
}

#[post("/submit_pubkey")]
async fn enviar_chave_publica(info: web::Json<ChavePublicaRequest>) -> impl Responder {
    println!("[http] POST /submit_pubkey");

    // aq esta o valor da chave publica recebida do cliente, dps vou mandar isso para uma Vault
    println!("[http] Chave pública recebida do usuário '{}': {}", info.username, info.pubkey);
    HttpResponse::Ok().body("Chave pública recebida")
}

// rota padrao para saber se esta rodando o servidor web
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Servidor rodando na porta 8080");
    HttpServer::new(|| App::new()
            .service(create_user)
            .service(login)
            .service(verify_mfa)
            .service(enviar_chave_publica)
            .service(health))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
