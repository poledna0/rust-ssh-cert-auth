use std::io::{self, Write};
use rpassword::read_password;
use sha2::{Sha256, Digest};
use serde::Serialize;
use rand::Rng;
use koibumi_base32::encode;

// para colocar no db
#[derive(Serialize)]
struct CreateUser {
    username: String,
    password_hash: String,
    pubkey: String,
    mfa_secret: String,
}

fn gerar_segredo() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    encode(&bytes)
}
fn interface(){

    let mut buffer: String = String::new();

    println!("---------------------------------------------------------");
    print!("Escolha uma opção:\n
    (1) - fazer login;\n
    (2) - criar conta;\n
    (3) - acessar servidor ssh ( é necessario já ter feito login );\n

->>> ");
    io::stdout().flush().expect("Falha ao dar flush no stdout");

    std::io::stdin().read_line(&mut buffer).expect("erro a ler a linha1");

    let entrada = buffer.trim().parse::<u8>();

    //try
    match entrada {

        // depois de saber se deu certo e a pessoa colocou um numero e nao uma coisa que não pode ser convertida
        // temos q tratar as opcoes para qual func vai ser levada
        
        Ok(valor_convertido) => {

            match valor_convertido {
                1 => {
                    login_conta();

                },

                2 => criar_nova_conta(),

                3 => {
                        println!("3");
                },

                _=>{
                    println!("Valor invalido")
                },
            }
        }
        Err(e) => {
            // aqui 'e' é um std::num::ParseIntError
            eprintln!("Erro ao converter o valor para u8: {}", e);
        }
    }

}
fn criar_nova_conta(){

    print!("Digite um usuario nome de usuario --> ");
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

            print!("\nCole sua chave pública --> ");
            io::stdout().flush().expect("erro ao dar flush");

            let mut pubkey = String::new();
            io::stdin().read_line(&mut pubkey).expect("erro ao ler a linha");
            let pubkey = pubkey.trim().to_string();

            if !pubkey.is_empty() {
                // gera codigo secreto da mfa
                let mfa_secret = gerar_segredo();
                //let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                println!("\nMFA secret (cole no autenticador): {}", mfa_secret);
                //println!("Código atual (para adicionar agora): {}", mfa_code);

                // instanciar o struct CreateUser com os valores
                let user = CreateUser { username: nome_usuario.clone(), password_hash: hash_hex, pubkey, mfa_secret };

                // transformar em JSON
                let body = serde_json::to_string(&user).expect("erro serializando JSON");

                // enviar para o signer (inclui mfa_secret)
                match ureq::post("http://127.0.0.1:8080/create_user").set("Content-Type", "application/json").send_string(&body) {
                    Ok(resp) => {
                        if resp.status() == 200 {
                            println!("\nSenha, Chave Pública e MFA enviada. Usuário criado no signer.");
                        } else {
                            eprintln!("Erro do servidor");
                        }
                    }
                    Err(e) => eprintln!("Erro ao contactar o signer: {}", e),
                }

                break;
            } else {
                println!("ERRO! A chave pública está vazia. Por favor, cole uma chave válida.");
            }
        } else {
            println!("ERRO! As senhas não são iguais ou uma delas está vazia.");
        }
    }
}

fn login_conta() {
    print!("Digite o nome de usuário --> ");
    io::stdout().flush().expect("Erro a dar flush");
    let mut username = String::new();
    io::stdin().read_line(&mut username).expect("erro a ler a linha");
    let username = username.trim().to_string();

    print!("Digite a senha --> ");
    io::stdout().flush().expect("Erro a dar flush");
    let senha = read_password().expect("erro lendo senha");

    // Hash da senha
    let mut hasher = Sha256::new();
    hasher.update(senha.as_bytes());
    let result = hasher.finalize();
    let hash_hex = format!("{:x}", result);

    // enviar username e hash para o signer (/login)
    #[derive(serde::Serialize)]
    struct LoginReq<'a> {
        username: &'a str,
        password_hash: &'a str,
    }

    let req = LoginReq { username: &username, password_hash: &hash_hex };
    let body = serde_json::to_string(&req).expect("erro serializando JSON");

    match ureq::post("http://127.0.0.1:8080/login").set("Content-Type", "application/json").send_string(&body) {
        Ok(resp) => {
            if resp.status() == 200 {
                println!("Usuário e senha OK. Agora insira o código MFA do seu autenticador.");
                print!("Código MFA (6 dígitos) --> ");
                io::stdout().flush().expect("Erro a dar flush");
                let mut codigo = String::new();
                io::stdin().read_line(&mut codigo).expect("erro a ler codigo");
                let codigo = codigo.trim().to_string();

                #[derive(serde::Serialize)]
                struct MfaReq<'a> {
                    username: &'a str,
                    code: &'a str,
                }

                let mfa = MfaReq { username: &username, code: &codigo };
                let mfa_body = serde_json::to_string(&mfa).expect("erro serializando mfa");

                match ureq::post("http://127.0.0.1:8080/verify_mfa").set("Content-Type", "application/json").send_string(&mfa_body) {
                    Ok(mresp) => {
                        if mresp.status() == 200 {
                            println!("Login completo: MFA verificado.");
                        } else {
                            println!("MFA inválido ou expirado.");
                        }
                    }
                    Err(e) => eprintln!("Erro ao contactar o signer para MFA: {}", e),
                }
            } else {
                println!("Usuário ou senha inválidos.");
            }
        }
        Err(e) => eprintln!("Erro ao contactar o signer para login: {}", e),
    }
}

fn main() {
    interface();
}
