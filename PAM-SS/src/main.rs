mod client;
mod db;
mod signer;

fn main() {
    // inicia ou cria banco de dados
    match db::inicializar_db() {
        Ok(_) => {},
        Err(e) => eprintln!("ERRO ao inicializar o BD: {}", e),
    }
    // chamando a interface que possui as opcoes de input para escolher oq o usuario deseja fazer
    client::interface();
}
