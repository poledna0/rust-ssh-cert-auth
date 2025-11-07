use rusqlite::{Connection, Result};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Usuario {
    pub id: i32,
    pub nome_usuario: String,
    pub senha_hash: String,
    pub mfa_secret: String,
}



pub fn inicializar_db() -> Result<()> {
    //Abre a conexão ou cria o arquivo dados.db se não existir
    let conn = Connection::open("dados.db")?;

    // cria a tabela (se ela ainda não existir)
    println!("[db] inicializar_db: abrindo/criando dados.db e garantindo tabela usuarios");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS usuarios (
            id              INTEGER PRIMARY KEY,
            nome_usuario    TEXT NOT NULL UNIQUE,
            senha_hash      TEXT NOT NULL,
            mfa_secret      TEXT NOT NULL
        )",
        [],
    )?;

    Ok(())
}

#[allow(dead_code)]
pub fn criar_usuario(username: &str, password_hash: &str, mfa_secret: &str) -> Result<()> {
    println!("[db] criar_usuario: username='{}' mfa_secret='{}'", username, mfa_secret);
    let conn = Connection::open("dados.db")?;

    let res = conn.execute(
        "INSERT INTO usuarios (nome_usuario, senha_hash, mfa_secret) 
         VALUES (?1, ?2, ?3)",
        [username, password_hash, mfa_secret],
    );

    match res {
        Ok(rows) => {
            println!("[db] criar_usuario: inseriu {} linha(s)", rows);
            Ok(())
        }
        Err(e) => {
            eprintln!("[db] criar_usuario: erro ao inserir usuario: {}", e);
            Err(e)
        }
    }
}

#[allow(dead_code)]
pub fn buscar_usuario_para_login(username: &str) -> Result<Usuario> {
    let conn = Connection::open("dados.db")?;

    let mut stmt = conn.prepare(
        "SELECT id, nome_usuario, senha_hash, mfa_secret FROM usuarios WHERE nome_usuario = ?1",
    )?;

    let usuario_result = stmt.query_row([username], |row| {
        Ok(Usuario {
            id: row.get(0)?,
            nome_usuario: row.get(1)?,
            senha_hash: row.get(2)?,
            mfa_secret: row.get(3)?,
        })
    });

    match &usuario_result {
        Ok(u) => println!("[db] buscar_usuario_para_login: encontrado user='{}' id={}", u.nome_usuario, u.id),
        Err(e) => eprintln!("[db] buscar_usuario_para_login: nenhum usuario encontrado ou erro: {}", e),
    }

    usuario_result
}
