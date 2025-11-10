from flask import Flask, request, jsonify
import subprocess
import tempfile
import os
import re
from pathlib import Path

app = Flask(__name__)

# Diretório base para as chaves (mesmo diretório do script)
BASE_DIR = Path(__file__).parent.absolute()
CA_KEY_PATH = BASE_DIR / "ca_key"  # ssh-keygen não precisa de extensão
CA_PUB_KEY_PATH = BASE_DIR / "ca_key.pub"

def validate_ssh_public_key(key_string):
    """Valida formato básico de uma chave SSH"""
    # Formato básico: tipo chave-base64 comentário
    ssh_key_pattern = r'^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/]+[=]{0,3}(\s+[^\n]+)?$'
    return bool(re.match(ssh_key_pattern, key_string.strip()))

# Gera a chave da CA se não existir
def setup_ca():
    if not os.path.exists(CA_KEY_PATH):
        # Gera chave privada da CA no formato OpenSSH
        subprocess.run([
            "ssh-keygen",
            "-t", "ed25519",        # Tipo de chave
            "-f", str(CA_KEY_PATH), # Caminho do arquivo
            "-C", "ssh-ca@local",   # Comentário identificador
            "-N", ""                # Sem senha
        ], check=True)
        print("[CA] Nova chave gerada:", CA_KEY_PATH)

# Inicializa a CA
setup_ca()

@app.route('/sign', methods=['POST'])
def sign_key():
    temp_files = []  # Lista para garantir limpeza em caso de erro
    try:
        data = request.get_json()
        if not data or 'public_key' not in data or 'username' not in data:
            return jsonify({'error': 'Campos obrigatórios: public_key e username'}), 400

        ssh_public_key = data['public_key'].strip()
        username = data['username']

        # Valida formato da chave SSH
        if not validate_ssh_public_key(ssh_public_key):
            return jsonify({'error': 'Formato de chave SSH inválido'}), 400

        # Cria diretório temporário para trabalhar com os arquivos
        temp_dir = Path(tempfile.mkdtemp())
        temp_files.append(temp_dir)  # Para limpeza posterior

        # Arquivo temporário para a chave pública com extensão .pub
        pub_file_path = temp_dir / "key.pub"
        pub_file_path.write_text(ssh_public_key + "\n")
        temp_files.append(pub_file_path)

        # Caminho pro certificado de saída (ssh-keygen adiciona -cert automaticamente)
        cert_path = pub_file_path.with_name(pub_file_path.stem + "-cert.pub")

        # Assina com a CA usando o ssh-keygen
        result = subprocess.run([
            "ssh-keygen",
            "-s", str(CA_KEY_PATH),     # chave privada da CA
            "-I", f"{username}-cert",    # identificador
            "-n", username,              # principal (usuário autorizado)
            "-V", "+10m",                # validade: 10 minutos
            "-z", str(os.getpid()),      # número serial único
            str(pub_file_path)           # arquivo da chave a ser assinada
        ], capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({
                'error': 'Erro ao assinar chave SSH',
                'details': result.stderr
            }), 500

        # Verifica se o certificado foi gerado
        if not cert_path.exists():
            return jsonify({'error': 'Certificado não foi gerado'}), 500

        # Lê o certificado SSH gerado
        cert_data = cert_path.read_text()

        return jsonify({
            "username": username,
            "certificate": cert_data
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        # Limpa TODOS os arquivos temporários, mesmo em caso de erro
        for path in temp_files:
            try:
                if isinstance(path, Path):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        import shutil
                        shutil.rmtree(path)
            except Exception as e:
                print(f"Erro ao limpar arquivo temporário {path}: {e}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
