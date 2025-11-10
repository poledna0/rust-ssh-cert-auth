from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta
import os


# cria o server
app = Flask(__name__)

# Gera a chave da CA se não existir
def setup_ca():
    if not os.path.exists('ca_key.pem'):
        # Gera chave privada da CA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Salva chave privada da CA
        with open("ca_key.pem", "wb") as f:
            # salva em base64 
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Define que o dono (subject) e o emissor (issuer) são a própria CA (autossinada).
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"SSH CA")
        ])

        #o nome da CA
        #a chave pública da CA
        #número de série aleatório
        #validade de 1 ano (timedelta(days=365))
        #marca que é uma CA (x509.BasicConstraints(ca=True))

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
            # assina com a própria chave privada
        ).sign(private_key, hashes.SHA256())

        # Salva certificado da CA
        with open("ca_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

# Carrega a CA na inicialização
setup_ca()

# cria uma rota HTTP POST
@app.route('/sign', methods=['POST'])
def sign_key():
    try:
        # Recebe a chave pública SSH
        data = request.get_json()
        if not data or 'public_key' not in data:
            return jsonify({'error': 'Chave pública não fornecida'}), 400

        ssh_public_key = data['public_key']

        # Carrega a chave privada da CA
        with open("ca_key.pem", "rb") as key_file:
            ca_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # Carrega o certificado da CA
        with open("ca_cert.pem", "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())

        # Parseia a chave pública SSH enviada
        try:
            ssh_user_public_key_object = serialization.load_ssh_public_key(
                ssh_public_key.encode('utf-8')
            )
        except Exception as e:
            return jsonify({'error': 'Chave pública SSH inválida: {}'.format(str(e))}), 400

        # Cria certificado para a chave pública
        builder = x509.CertificateBuilder()

        # Define o nome do subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"SSH User")
        ])

        cert = builder.subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            ssh_user_public_key_object
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Certificado válido por 10 minutos
            datetime.utcnow() + timedelta(minutes=10)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256())

        # Retorna o certificado em formato PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        return cert_pem

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)