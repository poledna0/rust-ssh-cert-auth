use std::io::{self, Write};
use rpassword::read_password;
use sha2::{Sha256, Digest};
use serde::Serialize;
use rand::Rng;
use koibumi_base32::encode;
use std::fs::File;
use std::process::Command;

// structs que vao ser enviadas pro servidor em formato JSON
#[derive(Serialize)]
struct CreateUser {
    username: String,      // nome do usuario
    password_hash: String, // hash da senha
    mfa_secret: String,    // segredo do autenticador
}

#[derive(Serialize)]
struct EnviarChaveRequest {
    username: String, // nome do usuario
    pubkey: String,    // chave publica ssh do usuario
}

// caminho para onde vai salvar os certificados retornados pelo signer
static CAMINHO: &str = "client/certificado-client";

// gera um segredo aleatório pra usar no autenticador 2FA
fn gerar_segredo() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen(); // 16 bytes aleatorios
    encode(&bytes) // converte pra base32 pq é o formato q o autenticador aceita
}


fn ssh_para_servidor(usuario: &str, host: &str, chave_privada: &str, caminho_cert: &str) {
    let status = Command::new("ssh")
        .arg("-i")
        .arg(chave_privada)
        .arg("-o")
        .arg(format!("CertificateFile={}", caminho_cert))
        .arg(format!("{}@{}", usuario, host))
        .status()
        .expect("Falha ao executar ssh");

    if status.success() {
        println!("Conexão SSH encerrada normalmente.");
    } else {
        eprintln!("SSH retornou um erro.");
    }
}

fn chamar_ssh_com_inputs() {
    // pedir usuario
    print!("Usuário SSH: ");
    io::stdout().flush().unwrap();
    let mut usuario = String::new();
    io::stdin().read_line(&mut usuario).unwrap();
    let usuario = usuario.trim().to_string();

    // pedir host
    print!("Host (ex: localhost ou 192.168.1.10): ");
    io::stdout().flush().unwrap();
    let mut host = String::new();
    io::stdin().read_line(&mut host).unwrap();
    let host = host.trim().to_string();

    // pedir caminho da chave privada
    print!("Caminho da chave privada (ex: ~/.ssh/id_ed25519): ");
    io::stdout().flush().unwrap();
    let mut chave = String::new();
    io::stdin().read_line(&mut chave).unwrap();
    let chave = chave.trim().to_string();

    // pedir caminho do certificado
    print!("Caminho do certificado (ex: certificado_henrique.pem): ");
    io::stdout().flush().unwrap();
    let mut cert = String::new();
    io::stdin().read_line(&mut cert).unwrap();
    let cert = cert.trim().to_string();

    println!("\nConectando via SSH...\n");

    ssh_para_servidor(&usuario, &host, &chave, &cert);
}

fn interface() {

    loop {
        println!("---------------------------------------------------------");
        println!("                  PAM Segurança de sistemas               ");
        println!("---------------------------------------------------------");
        println!("Escolha uma opção:\n");
        println!(" (1) - Fazer login");
        println!(" (2) - Criar conta");
        println!(" (3) - Acessar servidor SSH");
        println!(" (0) - Sair");

        print!("\n>>> ");
        io::stdout().flush().expect("Falha ao dar flush no stdout");

        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).expect("erro a ler a linha1");

        let entrada = buffer.trim().parse::<u8>();

        match entrada {
            // depois de saber se deu certo e a pessoa colocou um numero e nao uma coisa que não pode ser convertida
        // temos q tratar as opcoes para qual func vai ser levada
        
            Ok(valor) => {
                match valor {
                    1 => login_conta(),
                    2 => criar_nova_conta(),
                    3 => chamar_ssh_com_inputs(),
                    0 => {
                        println!("Saindo...");
                        return;
                    }
                    _ => println!("Valor inválido. Tente novamente.\n"),
                }
            }
            Err(_) => {
                println!("Entrada inválida. Digite apenas números.\n");
            }
        }
    }
}


fn criar_nova_conta() {

    print!("Digite um nome de usuário --> ");
    io::stdout().flush().expect("Erro a dar flush no print criar conta1");

    let mut nome_usuario = String::new();
    io::stdin().read_line(&mut nome_usuario).expect("erro a ler a linha2");
    let nome_usuario = nome_usuario.trim().to_string();

    loop {
        print!("\nDigite uma senha --> ");
        io::stdout().flush().expect("erro ao dar flush");

        let senha = read_password().expect("erro lendo senha");

        print!("\nConfirme sua senha --> ");
        io::stdout().flush().expect("erro ao dar flush");

        let csenha = read_password().expect("erro lendo senha");

        if senha == csenha && !senha.is_empty() {

            // cria o objeto que faz o hash da senha
            let mut hasher = Sha256::new();
            // alimenta o hasher com a senha em &[u8]
            hasher.update(senha.as_bytes());
            // finaliza o objeto haser e obtém o resultado

            let result = hasher.finalize();
            // converte o resultado para uma string hexadecimal
            let hash_hex = format!("{:x}", result);

            // gera codigo secreto da mfa
            let mfa_secret = gerar_segredo();

            println!("\nMFA secret (cole no autenticador): {}", mfa_secret);

            // instanciar o struct CreateUser com os valores
            let user = CreateUser { 
                username: nome_usuario.clone(), 
                password_hash: hash_hex,
                mfa_secret,
            };

            // transformar em JSON
            let body = serde_json::to_string(&user).expect("erro serializando JSON");

            // enviar para o signer (inclui mfa_secret)
            match ureq::post("http://127.0.0.1:8080/create_user")
                .set("Content-Type", "application/json")
                .send_string(&body)
            {
                Ok(resp) => {
                    if resp.status() == 200 {
                        println!("\nUsuário criado com sucesso!");
                    } else {
                        eprintln!("Erro: servidor retornou código {}", resp.status());
                    }
                }
                Err(e) => eprintln!("Erro ao contactar o servidor: {}", e),
            }

            break;
        } else {
            println!("\nERRO! As senhas não são iguais ou vazias. Tente novamente.\n");
        }
    }
}


fn login_conta() {
    // enviar username e hash para o signer (/login)
    #[derive(serde::Serialize)]
    struct LoginReq<'a> {
        username: &'a str,
        password_hash: &'a str,
    }

    loop {
        println!("\n--- LOGIN ---");

        print!("Digite o nome de usuário --> ");
        io::stdout().flush().expect("Erro a dar flush");
        let mut username = String::new();
        io::stdin().read_line(&mut username).expect("erro a ler a linha");
        let username = username.trim().to_string();

        print!("Digite a senha --> ");
        io::stdout().flush().expect("Erro a dar flush");
        let senha = read_password().expect("erro lendo senha");

        let mut hasher = Sha256::new();
        hasher.update(senha.as_bytes());
        let result = hasher.finalize();
        let hash_hex = format!("{:x}", result);

        let req = LoginReq { username: &username, password_hash: &hash_hex };
        let body = serde_json::to_string(&req).expect("erro serializando JSON");

        match ureq::post("http://127.0.0.1:8080/login")
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(resp) => {
                if resp.status() == 200 {
                    println!("Usuário e senha OK.");
                    
                    verificar_mfa(&username);
                    return;
                } else {
                    println!("\nUsuário ou senha incorretos. Tente novamente!\n");
                }
            }
            Err(e) => {
                println!("Erro ao contactar o servidor: {}", e);
            }
        }
    }
}


fn verificar_mfa(username: &str) {

    #[derive(serde::Serialize)]
    struct MfaReq<'a> {
        username: &'a str,
        code: &'a str,
    }

    loop {
        print!("Código MFA (6 dígitos) --> ");
        io::stdout().flush().expect("Erro a dar flush");

        let mut codigo = String::new();
        io::stdin().read_line(&mut codigo).expect("erro a ler codigo");
        let codigo = codigo.trim().to_string();

        let mfa = MfaReq { username, code: &codigo };
        let mfa_body = serde_json::to_string(&mfa).expect("erro serializando mfa");

        match ureq::post("http://127.0.0.1:8080/verify_mfa")
            .set("Content-Type", "application/json")
            .send_string(&mfa_body)
        {
            Ok(resp) => {
                if resp.status() == 200 {
                    println!("MFA OK!");
                    inserir_chave_ssh(username);
                    return;
                } else {
                    println!("Código inválido ou expirado. Tente novamente.\n");
                }
            }
            Err(e) => println!("Erro ao contactar servidor: {}", e),
        }
    }
}


fn inserir_chave_ssh(username: &str) {

    println!("Agora cole sua chave pública SSH:");

    print!("Chave pública --> ");
    io::stdout().flush().expect("Erro a dar flush");

    let mut pubkey = String::new();
    io::stdin().read_line(&mut pubkey).expect("erro lendo chave");
    let pubkey = pubkey.trim().to_string();

    if pubkey.is_empty() {
        println!("Nenhuma chave inserida. Cancelando operação.");
        return;
    }

    let envio = EnviarChaveRequest {
        username: username.to_string(),
        pubkey: pubkey.clone(),
    };

    let json = serde_json::to_string(&envio).expect("erro convertendo chave pra JSON");

    match ureq::post("http://127.0.0.1:8080/submit_pubkey")
        .set("Content-Type", "application/json")
        .send_string(&json)
    {
        Ok(resp) => {
            match resp.into_string() {
                Ok(json_resp) => {

                    #[derive(serde::Deserialize)]
                    struct CertResp {
                        certificate: String,
                        username: String,
                    }

                    // tenta converter o JSON retornado
                    let dados: CertResp = match serde_json::from_str(&json_resp) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Erro ao decodificar JSON do certificado: {}", e);
                            return;
                        }
                    };

                    
                    let caminho = format!("{}/certificado_{}.pem", CAMINHO, username);

                    match File::create(&caminho) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(dados.certificate.as_bytes()) {
                                eprintln!("Erro ao salvar certificado: {}", e);
                            } else {
                                println!("\nCertificado do usuario {} salvo em: {}", dados.username, caminho);
                            }
                        }
                        Err(e) => eprintln!("Erro criando arquivo: {}", e),
                    }
                }
                Err(e) => eprintln!("Erro lendo resposta do servidor: {}", e),
            }
        }
        Err(e) => eprintln!("Erro ao enviar chave SSH: {}", e),
    }
}




fn main() {
    interface();
}
