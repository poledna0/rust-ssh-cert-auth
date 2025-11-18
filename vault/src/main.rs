use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fs,path::{PathBuf},process::Command,sync::Once,};
use tempfile::tempdir;
use std::io;

// diretorio base do executável (onde ficam as chaves CA)
fn base_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}

// caminho para a chave da CA
fn ca_key_path() -> PathBuf {
    base_dir().join("ca_key")
}



// garante que a CA seja gerada apenas uma vez
static INIT_CA: Once = Once::new();

// gera a chave da CA caso ela não exist

fn setup_ca() {
    INIT_CA.call_once(|| {
        let ca_key = ca_key_path();

        if !ca_key.exists() {
            println!("[CA] Gerando chave da CA...");

            Command::new("ssh-keygen")
                .args([
                    "-t", "ed25519",                // tipo da chave
                    "-f", ca_key.to_str().unwrap(), // caminho do arquivo
                    "-C", "ssh-ca@batata",          // comentário
                    "-N", "",                       // sem senha
                ])
                .status()
                .expect("[CA] Erro ao gerar chave da CA");

            println!("[CA] Nova chave gerada: {:?}", ca_key);
        }
    });
}


#[derive(Deserialize)]
struct SignRequest {
    public_key: String,
    username: String,
}

#[derive(Serialize)]
struct SignResponse {
    username: String,
    certificate: String,
}


// valida o formato SSH tipo base64 comentario
fn validate_ssh_public_key(key: &str) -> bool {
    let pattern = r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/]+={0,3}(\s+[^\n]+)?$";
    Regex::new(pattern).unwrap().is_match(key.trim())
}


#[post("/sign")]
async fn sign_key(info: web::Json<SignRequest>) -> impl Responder {
    setup_ca(); // garante que a CA existe

    // validação dos campos obrigatórios
    if info.public_key.trim().is_empty() || info.username.trim().is_empty() {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": "Campos obrigatórios: public_key e username"}),
        );
    }

    let ssh_key = info.public_key.trim();
    let username = info.username.trim();

    // valida formato da chave SSH
    if !validate_ssh_public_key(ssh_key) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Formato de chave SSH inválido"}));
    }

    // lista de arquivos/diretórios temporários a serem apagados
    let mut cleanup_paths: Vec<PathBuf> = Vec::new();

    // cria diretório temporário
    let temp_dir = match tempdir() {
        Ok(dir) => {
            cleanup_paths.push(dir.path().to_path_buf());
            dir
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("Erro criando tempdir: {}", e)}));
        }
    };

    // arquivo key.pub dentro do dir temporário
    let pub_path = temp_dir.path().join("key.pub");
    if let Err(e) = fs::write(&pub_path, ssh_key.to_owned() + "\n") {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": format!("Erro criando key.pub: {}", e)}));
    }
    cleanup_paths.push(pub_path.clone());

    // caminho de saida: key-cert.pub
    let cert_path = temp_dir.path().join("key-cert.pub");
    cleanup_paths.push(cert_path.clone());

    // executa ssh-keygen
    let output = Command::new("ssh-keygen")
        .args([
            "-s", ca_key_path().to_str().unwrap(), // chave CA
            "-I", &format!("{}-cert", username),   // identificador
            "-n", username,                         // principal
            "-V", "+10m",                           // validade
            "-z", &std::process::id().to_string(),  // serial único
            pub_path.to_str().unwrap(),             // arquivo .pub
        ])
        .output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"error": "Erro ao assinar chave SSH", "details": err}),
                );
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    }

    // checa se o certificado foi gerado
    if !cert_path.exists() {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "Certificado não foi gerado"}));
    }

    // lê o conteúdo do certificado
    let cert_data = match fs::read_to_string(&cert_path) {
        Ok(data) => data,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("{}", e)}));
        }
    };

    // limpeza dos arquivos temporários
    for path in cleanup_paths {
        let _ = if path.is_file() {
            fs::remove_file(&path)
        } else if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            Ok(())
        };
    }

    // resposta
    HttpResponse::Ok().json(SignResponse {
        username: username.to_string(),
        certificate: cert_data,
    })
}


#[actix_web::main]
async fn main() -> io::Result<()> {
    println!("Vault CA (Rust) rodando em http://0.0.0.0:5000");

    setup_ca();

    HttpServer::new(|| App::new().service(sign_key))
        .bind(("0.0.0.0", 5000))?
        .run()
        .await
}

