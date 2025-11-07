use std::{io::{self, Write}, u8};
use rpassword::read_password;
use sha2::{Sha256, Digest};

use crate::db;


pub fn interface(){
    let logado: bool = false;

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

    // um try em rust :o 
    match entrada {


        // depois de saber se deu certo e a pessoa colocou um numero e nao uma coisa que não pode ser convertida
        // temos q tratar as opcoes para qual func vai ser levada
        
        Ok(valor_convertido) => {


            match valor_convertido {
                1 => {
                    if logado{
                        println!("Você ja fez o login");
                    }

                },

                2 => {
                
                    criar_nova_conta();
                },

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
    
    print!("\nDigite um usuario nome de usuario --> ");
    io::stdout().flush().expect("Erro a dar flush no print criar conta1");

    let mut nome_usuario = String::new();

    std::io::stdin().read_line(&mut nome_usuario).expect("erro a ler a linha2");

    loop {
        print!("\nDigite uma senha --> ");
        io::stdout().flush().expect("erro ao dar flush");

        // leitura escondida
        let senha = read_password().expect("erro lendo senha");

        print!("\nConfirme sua senha --> ");
        io::stdout().flush().expect("erro ao dar flush");

        let csenha = read_password().expect("erro lendo senha");

        if senha == csenha && !senha.is_empty() {

            // cria objeto de cripto
            let mut hasher = Sha256::new();

            // alimenta ele com os &[u8]
            hasher.update(senha.as_bytes());

            // faz o hash deles e finaliza o objeto
            let result = hasher.finalize();

            // muda para de by para hexa
            let hash_hex = format!("{:x}", result);

            print!("\nCole sua chave pública --> ");
            io::stdout().flush().expect("erro ao dar flush");

            let mut pubkey = String::new();
            io::stdin().read_line(&mut pubkey).expect("erro ao ler a linha");
            let pubkey = pubkey.trim().to_string();

            if !pubkey.is_empty(){
                match db::criar_usuario(&nome_usuario, &hash_hex, &pubkey) {
                        Ok(_) => {},
                        Err(e) => eprintln!("ERRO ao add usuario no BD: {}", e),
                    }

                println!("\nSenha e Chave Pública confirmadas. Usuário criado.");

                break;
            } else {
                println!("ERRO: A chave pública está vazia. Por favor, cole uma chave válida.");
            }
            
        } else {
            println!("ERRO: As senhas não são iguais ou uma delas está vazia.");
        }
    }
}