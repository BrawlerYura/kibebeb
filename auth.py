import hashlib
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import psycopg2
import secrets


def generate_key():
    return Fernet.generate_key()


def encrypt_string_with_hash(string, hash_value, key):
    cipher_suite = Fernet(key)
    combined_string = f"{hash_value}|{string}"
    encrypted_data = cipher_suite.encrypt(combined_string.encode())
    return encrypted_data


def decrypt_string_with_hash(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    parts = decrypted_data.split('|')
    if len(parts) != 2:
        return None, None
    provided_hash, extracted_string = parts
    return extracted_string, provided_hash


app = Flask(__name__)

# Подключение к постгре
conn = psycopg2.connect(
    dbname="auth_table",
    user="postgres",
    password="postgres",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        login VARCHAR(500),
        public_key VARCHAR(500),
        message VARCHAR(500),
        hash_key VARCHAR(500)
    )
""")
conn.commit()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if 'login' not in data or 'public_key' not in data or 'passphrase' not in data:
        return jsonify({'error': 'Не указан лоигн или публичный ключ или passphrase'}), 400

    login = data['login']
    public_key = data['public_key']
    passphrase = data['passphrase']

    key = generate_key()
    hash_value = hashlib.sha256(passphrase.encode()).hexdigest()

    hashed_public_key = encrypt_string_with_hash(public_key, hash_value, key)

    cur.execute("SELECT * FROM users WHERE login = %s", (login,))
    existing_user = cur.fetchone()
    if existing_user:
        return jsonify({'error': 'Пользователь с таким логином уже существует'}), 409
    print(key.decode('utf-8'))
    random_string = secrets.token_hex(32)
    cur.execute("INSERT INTO users (login, public_key, message, hash_key) VALUES (%s, %s, %s, %s)", (login, hashed_public_key.decode('utf-8'), random_string, key.decode('utf-8')))
    conn.commit()

    return jsonify({'message': 'Пользователь зарегитрирован успешно', 'random_string': random_string}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'login' not in data or 'encrypted_string' not in data or 'passphrase' not in data:
        return jsonify({'error': 'Не указан логин, зашифрованная строка или пароль'}), 400

    login = data['login']
    encrypted_string = data['encrypted_string']
    passphrase = data['passphrase']
    hash_value = hashlib.sha256(passphrase.encode()).hexdigest()

    cur.execute("SELECT * FROM users WHERE login = %s", (login,))
    user = cur.fetchone()

    if user:
        decrypted_key, provided_hash = decrypt_string_with_hash(user[2], user[4])
        print("decrypted string = " + decrypted_key)
        print("provided_hash = " + provided_hash)

        if provided_hash != hash_value:
            return jsonify({'error': 'Неверный passphrase'}), 400

        decrypted_key_bytes = decrypted_key.encode('utf-8')

        public_key = serialization.load_pem_public_key(
            decrypted_key_bytes,
            backend=default_backend()
        )
        print(user[3])

        try:
            signature_bytes = bytes.fromhex(encrypted_string)

            public_key.verify(
                signature_bytes,
                user[3].encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )

            return jsonify({'message': 'Пользователь успешно авторизован', 'token': 'тут должен быть токен'}), 200
        except Exception as e:
            print(e)
            return jsonify({'error': 'Неверная строка'}), 400
    else:
        return jsonify({'error': 'Пользователь не найден'}), 404


@app.route('/message', methods=['PUT'])
def update_message():
    data = request.get_json()
    if 'login' not in data:
        return jsonify({'error': 'Не указан логин пользователя'}), 400

    login = data['login']

    cur.execute("SELECT * FROM users WHERE login = %s", (login,))
    user = cur.fetchone()
    if not user:
        return jsonify({'error': 'Пользователь с таким логином не найден'}), 404

    random_string = secrets.token_hex(32)
    cur.execute("UPDATE users SET message = %s WHERE login = %s", (random_string, login))
    conn.commit()

    return jsonify({'message': 'Сообщение пользователя успешно обновлено', 'string': random_string}), 200


@app.route('/generateKeys', methods=['GET'])
def generate_keys():
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )

    public_key = private_key.public_key()

    # Сериализация приватного ключа чтобы он норм выглядел
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    print("Приватный ключ:", private_key_pem)

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("публичный ключ:", public_key_pem)

    return jsonify({'private_key': private_key_pem.decode('utf-8'), 'public_key': public_key_pem.decode('utf-8')}), 200


@app.route('/encryptMessage', methods=['GET'])
def encrypt_message():
    data = request.get_json()
    if 'private_key' not in data or 'message' not in data:
        return jsonify({'error': 'Не указан логин и зашифрованная строка'}), 400

    private_key_pem = data['private_key'].encode('utf-8')
    message = data['message'].encode('utf-8')

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    signature_str = signature.hex()

    return jsonify({'signature': signature_str}), 200


if __name__ == '__main__':
    app.run(debug=True)