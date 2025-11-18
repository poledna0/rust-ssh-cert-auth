# Rust SSH Certificate Auth

Sistema de autenticação SSH baseado em **Certificados Digitais Temporários**. O projeto utiliza uma arquitetura de serviços em Rust para garantir que o acesso ao servidor SSH seja feito apenas por usuários autenticados (Senha + MFA) e com chaves assinadas por tempo limitado.

![Fluxo do Sistema](image.png)

## Arquitetura

O sistema é dividido em três componentes principais:

1.  **Client :** Interface de linha de comando para o usuário.
2.  **Signer :** Gerencia autenticação (DB), valida MFA e solicita assinaturas.
3.  **Vault :** Autoridade Certificadora. Guarda a chave privada da CA e assina chaves públicas.

---

## Menu do Cliente (Client CLI)

O cliente interage com o sistema através de um menu numerado. Veja como funciona cada opção:


### `(1) - Fazer login`
Fluxo para obter o certificado assinado:
1.  **Credenciais:** Pede *usuário* e *senha*.
2.  **MFA:** Solicita o código de 6 dígitos do seu autenticador.
3.  **Chave Pública:** Se validado, o sistema pede que você **cole sua chave pública SSH** (conteúdo do arquivo `.pub`).
4.  **Resultado:** O cliente recebe o certificado (`.pem`) e o salva localmente.

### `(2) - Criar conta`
* **Entrada:** Solicita um *username* e uma *senha* (com confirmação).
* **Processo:** Envia o hash da senha para o Signer e registra o usuário.
* **Saída:** O sistema exibe um **MFA Secret** na tela.
    * *Atenção:* Você deve adicionar esse código em um app autenticador (Google Authenticator, Authy) para gerar os códigos temporários.


### `(3) - Acessar servidor SSH`
Automatiza a conexão SSH usando o certificado gerado. O sistema pedirá 4 dados:
1.  **Usuário SSH:** O usuário do sistema operacional no servidor (ex: `ubuntu` ou `root`).
2.  **Host:** O IP ou domínio do servidor (ex: `192.168.1.15`).
3.  **Caminho da chave privada:** Local da sua chave privada (ex: `~/.ssh/id_ed25519`).
4.  **Caminho do certificado:** Local onde o arquivo `.pem` foi salvo.

---

## Como funciona o Backend

### Signer
Atua como o "guardião" da segurança.
* **Banco de Dados:** Usa SQLite para armazenar usuários e segredos MFA.
* **Validação:** Confere Hash de senha e valida o código TOTP (MFA).
* **Proxy:** Apenas encaminha a chave para a Vault se o usuário estiver totalmente autenticado.

### Vault (CA)
Atua como a Autoridade Certificadora isolada.
* **Setup:** Gera automaticamente as chaves da CA se não existirem.
* **Assinatura:** Recebe a chave pública vinda do Signer e gera um certificado via `ssh-keygen`.
* **Segurança:** Os certificados possuem validade curta (ex: 10 minutos) para reduzir riscos.

---

## Como Rodar

Certifique-se de ter o Rust, OpenSSH e as libs do SQLite instaladas. Execute os componentes em terminais separados:
```bash
sudo apt install libsqlite3-dev libssl-dev pkg-config
```
---
1. **Iniciar o Vault:**
   ```bash
   cargo run --bin vault
   ```
---
2. **Iniciar o Cliente:**
   ```bash
   cargo run --bin client
   ```
---
3. **Iniciar o Signer:**
   ```bash
   cargo run --bin signer
   ```
---