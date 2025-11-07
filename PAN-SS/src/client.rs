use std::{io::{self, Write}, u8};

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

}