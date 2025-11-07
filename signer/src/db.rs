use rusqlite::{Connection, Result};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Usuario {
    pub id: i32,
    pub nome_usuario: String,
    pub senha_hash: String,
    pub chave_publica: String,
}

pub fn inicializar_db() -> Result<()> {
    //Abre a conexão ou cria o arquivo dados.db se não existir
    let conn = Connection::open("dados.db")?;

    // cria a tabela (se ela ainda não existir)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS usuarios (
            id              INTEGER PRIMARY KEY,
            nome_usuario    TEXT NOT NULL UNIQUE,
            senha_hash      TEXT NOT NULL,
            chave_publica   TEXT NOT NULL
        )",
        [],
    )?;

    Ok(())
}

#[allow(dead_code)]
pub fn criar_usuario(username: &str, password_hash: &str, pub_key: &str) -> Result<()> {
    let conn = Connection::open("dados.db")?;

    conn.execute(
        "INSERT INTO usuarios (nome_usuario, senha_hash, chave_publica) 
         VALUES (?1, ?2, ?3)",
        [username, password_hash, pub_key],
    )?;

    Ok(())
}

#[allow(dead_code)]
pub fn buscar_usuario_para_login(username: &str) -> Result<Usuario> {
    let conn = Connection::open("dados.db")?;

    let mut stmt = conn.prepare(
        "SELECT id, nome_usuario, senha_hash, chave_publica FROM usuarios WHERE nome_usuario = ?1",
    )?;

    let usuario_result = stmt.query_row([username], |row| {
        Ok(Usuario {
            id: row.get(0)?,
            nome_usuario: row.get(1)?,
            senha_hash: row.get(2)?,
            chave_publica: row.get(3)?,
        })
    });

    usuario_result
}
