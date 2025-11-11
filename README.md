

## Descrição
Projeto simples para demonstrar autenticação SSH por **certificados temporários**.  
Três componentes principais simulam o fluxo: **client → signer → vault (CA)**. A CA (vault) assina chaves públicas e devolve certificados com validade curta (ex.: 10 minutos).

![Diagrama do Sistema](image.png)

```bash
cd vault/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
sudo apt install libsqlite3-dev libssl-dev pkg-config
```

## Resumo rápido
- Fluxo: cliente envia chave → signer valida → vault assina → cliente usa certificado.
- Ferramentas: Rust (backend), Flask (vault), OpenSSH (`ssh-keygen`).
- Certificados temporários: prática para reduzir risco de chave comprometida.

---
