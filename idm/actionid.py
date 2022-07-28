import os
import base64
import socket
import datetime
from typing import Callable, Tuple

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding

# Crypto configurations
RSA_EXPONENT = 65537
RSA_KEY_SIZE = 2048
RSA_ENCODING = serialization.Encoding.PEM
RSA_HASHALG = hashes.SHA256()
RSA_PRIVKEY_FORMAT = serialization.PrivateFormat.PKCS8
RSA_PRIVKEY_ENCRYPTIONALG = serialization.NoEncryption()
RSA_PRIVKEY_PASSWORD = None
RSA_PUBKEY_FORMAT = serialization.PublicFormat.SubjectPublicKeyInfo
RSA_ENCRYPTION_PADDING = padding.OAEP(
    mgf = padding.MGF1(algorithm = hashes.SHA256()),
    algorithm = RSA_HASHALG,
    label = None
)
RSA_SIGNATURE_PADDING = padding.PSS(
    mgf = padding.MGF1(RSA_HASHALG),
    salt_length = padding.PSS.MAX_LENGTH
)
X509_SIGNATURE_PADDING = padding.PKCS1v15()

# Size parameters
NONCE_SIZE = 16                 # bytes
DATETIME_SIZE = 26              # bytes
HASH_SIZE = 32                  # bytes
X509_SERIALNO_SIZE = 8          # digits in string
X509_CERT_PEM_SIZE = 969        # bytes
SYMMETRIC_KEY_SIZE = 32         # bytes
RSA_PRIVKEY_PEM_SIZE = 1704     # bytes
RSA_PUBKEY_PEM_SIZE = 451       # bytes
RSA_SIGNATURE_SIZE = 256        # bytes
RSA_CIPHERTEXT_SIZE = 256       # bytes
MESSAGE_SIZE = 4096             # bytes

# Hash functions
def generate_hash(*parameters: bytes) -> bytes:
    hasher = hashes.Hash(RSA_HASHALG)
    for parameter in parameters:
        hasher.update(parameter)
    hash_result = hasher.finalize()
    return hash_result

def verify_hash(hash_to_compare: bytes, *parameters: bytes) -> bool:
    hash_result = generate_hash(*parameters)
    return hash_to_compare == hash_result

# Nonce functions
def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)

def verify_nonce(sent_nonce: bytes, received_nonce: bytes) -> bool:
    return sent_nonce == received_nonce

# Symmetric key functions
def generate_key_symmetric() -> bytes:
    return Fernet.generate_key()

def generate_session_key(n1: bytes, n2: bytes) -> bytes:
    hash_result = generate_hash(n1, n2)
    kdf = ConcatKDFHash(
        algorithm = RSA_HASHALG,
        length = SYMMETRIC_KEY_SIZE,
        otherinfo = None
    )
    session_key = kdf.derive(hash_result)
    session_key = base64.urlsafe_b64encode(session_key)
    return session_key

def encrypt_message_symmetric(secret_key: bytes, message: bytes) -> bytes:
    cipher = Fernet(secret_key)
    return cipher.encrypt(message)

def decrypt_message_symmetric(secret_key: bytes, encrypted_message: bytes) -> bytes:
    cipher = Fernet(secret_key)
    return cipher.decrypt(encrypted_message)

def generate_mac(secret_key: bytes, encrypted_message: bytes) -> bytes:
    hasher = hmac.HMAC(secret_key, hashes.SHA256())
    hasher.update(encrypted_message)
    return hasher.finalize()

def verify_mac(secret_key: bytes, encrypted_message: bytes, mac: bytes) -> bool:
    hasher = hmac.HMAC(secret_key, hashes.SHA256())
    hasher.update(encrypted_message)
    try:
        hasher.verify(mac)
        return True
    except InvalidSignature:
        return False

# Asymmetric key functions
def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent = RSA_EXPONENT,
        key_size = RSA_KEY_SIZE
)

def serialise_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding = RSA_ENCODING,
        format = RSA_PRIVKEY_FORMAT,
        encryption_algorithm = RSA_PRIVKEY_ENCRYPTIONALG
)

def deserialise_private_key(private_key_bytes: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(
        private_key_bytes,
        RSA_PRIVKEY_PASSWORD,
    )

def generate_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    return private_key.public_key()

def serialise_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding = RSA_ENCODING,
        format = RSA_PUBKEY_FORMAT
)

def deserialise_public_key(public_key_bytes: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(public_key_bytes)

def encrypt_message_asymmetric(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        RSA_ENCRYPTION_PADDING
    )

def decrypt_message_asymmetric(private_key: rsa.RSAPrivateKey, encrypted_message: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_message,
        RSA_ENCRYPTION_PADDING
    )

def generate_signature(private_key: rsa.RSAPrivateKey, *parameters: bytes) -> bytes:
    hash_result = generate_hash(*parameters)
    return private_key.sign(
        hash_result,
        RSA_SIGNATURE_PADDING,
        utils.Prehashed(RSA_HASHALG)
    )

def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, *parameters: bytes) -> bool:
    hash_result = generate_hash(*parameters)
    try:
        public_key.verify(
            signature,
            hash_result,
            RSA_SIGNATURE_PADDING,
            utils.Prehashed(RSA_HASHALG)
        )
        return True
    except InvalidSignature:
        return False

# Certificate functions
def serialise_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(encoding = RSA_ENCODING)

def deserialise_certificate(certificate_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(certificate_bytes)

def extract_requestor_id_cert(requestor_certificate: x509.Certificate) -> bytes:
    requestor_id = requestor_certificate.subject.rfc4514_string()
    requestor_id = requestor_id[3:].encode()
    return requestor_id

def extract_requestor_id_cert_str(requestor_certificate: x509.Certificate) -> str:
    requestor_id_bytes = extract_requestor_id_cert(requestor_certificate)
    return str(requestor_id_bytes)[2:-1]

def extract_requestor_public_key_cert(requestor_certificate: x509.Certificate) -> rsa.RSAPublicKey:
    return requestor_certificate.public_key()

def verify_certificate(public_key: rsa.RSAPublicKey, requestor_certificate: x509.Certificate) -> bool:
    try:
        public_key.verify(
            requestor_certificate.signature,
            requestor_certificate.tbs_certificate_bytes,
            X509_SIGNATURE_PADDING,
            requestor_certificate.signature_hash_algorithm
        )
        return True
    except InvalidSignature:
        return False

# Other auxiliary functions
def parse_datetime(datetime_bytes: bytes) -> datetime:
    return datetime.datetime.strptime(str(datetime_bytes)[2:-1], '%Y-%m-%d %H:%M:%S.%f')

# Function library
def register_operations(idm_ip: str, idm_port: int, server_id: str, operations: str) -> Tuple[bytes, bytes, bytes, bytes]:
    # Read and load requestor's certificate
    with open("requestor_certificate.pem", "rb") as f:
        requestor_cert_bytes = f.read()
    requestor_cert = deserialise_certificate(requestor_cert_bytes)

    # Read and load requestor's private key
    with open("requestor_private_key.pem", "rb") as f:
        requestor_private_key_bytes = f.read()
    requestor_private_key = deserialise_private_key(requestor_private_key_bytes)

    # Read and load public key of idm
    with open("idm_public_key.pem", "rb") as f:
        idm_public_key_bytes = f.read()
    idm_public_key = deserialise_public_key(idm_public_key_bytes)

    # Extract requestor's ID
    requestor_id = extract_requestor_id_cert(requestor_cert)
    requestor_id_str = extract_requestor_id_cert_str(requestor_cert)
    # print('Initiating operations registration for Requestor ' + requestor_id_str)

    # Encode operations into bytes
    operations = operations.encode()
    server_id = server_id.encode()

    # Generate random key for operations
    random_key = generate_key_symmetric()
    encrypted_operations = encrypt_message_symmetric(random_key, operations)

    # Generate nonce
    nonce = generate_nonce()

    # Building message m1
    message = nonce + random_key
    m1 = encrypt_message_asymmetric(idm_public_key, message)

    # Generate signature on message m1
    m1Sign = generate_signature(requestor_private_key, m1, server_id, encrypted_operations)

    # Build message to send
    message = m1 + server_id + encrypted_operations + requestor_cert_bytes + m1Sign

    # Connect and send message
    requestor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    requestor_socket.connect((idm_ip, idm_port))
    requestor_socket.sendall(message)
    # print('Requestor ' + requestor_id_str + ': Sent message m1')

    #####################################
    #####################################
    # Waiting for connection acceptance #
    #####################################
    #####################################

    # Receive message m2 from IDM
    m2 = requestor_socket.recv(MESSAGE_SIZE)
    # print("Requestor " + requestor_id_str + ": Received message from IDM")

    # Parse message m2
    m2Sign = m2[-RSA_SIGNATURE_SIZE : ]
    token = m2[-2 * RSA_SIGNATURE_SIZE : -RSA_SIGNATURE_SIZE]
    received_nonce = m2[: NONCE_SIZE]
    server_public_key = m2[NONCE_SIZE : NONCE_SIZE + RSA_PUBKEY_PEM_SIZE]
    token_exp_time_bytes = m2[NONCE_SIZE + RSA_PUBKEY_PEM_SIZE : 
                                NONCE_SIZE + RSA_PUBKEY_PEM_SIZE + DATETIME_SIZE]
    policies = m2[NONCE_SIZE + RSA_PUBKEY_PEM_SIZE + DATETIME_SIZE : -2 * RSA_SIGNATURE_SIZE]

    # Verify nonce
    if verify_nonce(nonce, received_nonce):
        # print("Requestor " + requestor_id_str + ": Nonce verified")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": ERROR - Nonce verification failed")
        exit(1)

    # Validate expiration time
    token_exp_time = parse_datetime(token_exp_time_bytes)
    now = datetime.datetime.now()
    if now < token_exp_time:
        # print("Requestor " + requestor_id_str + ": Token expiration time verified")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": ERROR - Token expiration time failed")
        exit(2)

    # Validate signature on message m2
    if verify_signature(idm_public_key, m2Sign, nonce, server_public_key, token_exp_time_bytes, policies, token):
        # print("Requestor " + requestor_id_str + ": Signature is valid")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": ERROR - Invalid signature")
        exit(3)

    # Compute hash of the operations
    H = generate_hash(operations)

    # Validate token
    if verify_signature(idm_public_key, token, requestor_id, H, server_id, policies, token_exp_time_bytes):
        # print("Requestor " + requestor_id_str + ": Token is valid")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": ERROR - Invalid token")
        exit(4)

    # Exit with no errors
    # print("Operations registration is successful for Requestor " + requestor_id_str)
    return (token, token_exp_time_bytes, policies, server_public_key)

def access_service(server_ip: str, server_port: int, operations: str, token_info: Tuple[bytes, bytes, bytes, bytes]) -> bytes:
    # Read and load certificate
    with open("requestor_certificate.pem", "rb") as f:
        cert_bytes = f.read()
    requestor_cert = deserialise_certificate(cert_bytes)

    # Read and load private key
    with open("requestor_private_key.pem", "rb") as f:
        requestor_private_key_bytes = f.read()
    requestor_private_key = deserialise_private_key(requestor_private_key_bytes)

    # Encode operations into bytes
    operations = operations.encode()
    
    # Prepare token and its expiration time, policies, and server's public key
    token = token_info[0]
    token_exp_time_bytes = token_info[1]
    policies_bytes = token_info[2]
    server_public_key_bytes = token_info[3]
    server_public_key = deserialise_public_key(server_public_key_bytes)

    # Extract requestor's ID
    requestor_id_str = extract_requestor_id_cert_str(requestor_cert)
    # print('Initiating operations execution for Requestor ' + requestor_id_str)

    # Compute hash of the operations
    H = generate_hash(operations)

    # Generate nonce
    n1 = generate_nonce()

    # Build message m1
    m1 = cert_bytes + token + token_exp_time_bytes + H + policies_bytes + n1

    # Set up socket connection and send message m1
    requestor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    requestor_socket.connect((server_ip, server_port))
    requestor_socket.sendall(m1)
    # print('Requestor ' + requestor_id_str + ': Sent message m1')

    #####################################
    #####################################
    # Waiting for connection acceptance #
    #####################################
    #####################################

    # Receive and parse message m2
    message = requestor_socket.recv(MESSAGE_SIZE)
    # print("Requestor " + requestor_id_str + ": Received message m2")
    m2 = message[ : 256]
    m2Sign = message[256 : ]

    # Validate signature for message m2
    if verify_signature(server_public_key, m2Sign, m2, n1):
        # print("Requestor " + requestor_id_str + ": Server signature is valid")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": Invalid signature of server")
        requestor_socket.sendall(b"ERROR: Invalid signature")
        requestor_socket.close()
        exit(5)

    # Decrypt message m2
    n2 = decrypt_message_asymmetric(requestor_private_key, m2)

    # Build session key
    session_key = generate_session_key(n1, n2)

    # Build and send message m3
    message = n2 + operations
    m3 = encrypt_message_symmetric(session_key, message)
    requestor_socket.sendall(m3)

    #######################################
    #######################################
    # Waiting for message from the server #
    #######################################
    #######################################

    # Receive execution results from server
    results = requestor_socket.recv(MESSAGE_SIZE)
    mac = results[-HASH_SIZE: ]
    results = results[ : -HASH_SIZE]

    # Verify mac
    if verify_mac(session_key, results, mac):
        # print("Requestor " + requestor_id_str + ": MAC is valid")
        pass
    else:
        # print("Requestor " + requestor_id_str + ": Invalid mac")
        requestor_socket.sendall(b"ERROR: Invalid signature")
        requestor_socket.close()
        exit(6)
    
    # Decrypting results
    results = decrypt_message_symmetric(session_key, results)
    return results.decode()

def issue_token(requestor_conn: socket.socket, check_policies: Callable, get_server_public_key: Callable, server_db: str) -> None:
    # Read and load idm's public key
    with open("idm_public_key.pem", "rb") as f:
        idm_public_key_bytes = f.read()
    idm_public_key = deserialise_public_key(idm_public_key_bytes)

    # Read and load idm's private key
    with open("idm_private_key.pem", "rb") as f:           
        idm_private_key_bytes = f.read()
    idm_private_key = deserialise_private_key(idm_private_key_bytes)

    # Receive and parse the message
    message = requestor_conn.recv(MESSAGE_SIZE)
    m1 = message[0 : RSA_CIPHERTEXT_SIZE]
    server_id = message[RSA_CIPHERTEXT_SIZE : RSA_CIPHERTEXT_SIZE + 8]
    requestor_cert_bytes = message[-RSA_SIGNATURE_SIZE - X509_CERT_PEM_SIZE : -RSA_SIGNATURE_SIZE]
    requestor_signature = message[-RSA_SIGNATURE_SIZE : ]
    encrypted_operations = message[RSA_CIPHERTEXT_SIZE + 8 : -RSA_SIGNATURE_SIZE - X509_CERT_PEM_SIZE]

    # Extract requestor's ID
    requestor_cert = deserialise_certificate(requestor_cert_bytes)
    requestor_id = extract_requestor_id_cert(requestor_cert)
    requestor_id_str = extract_requestor_id_cert_str(requestor_cert)
    print('Received message from Requestor ' + requestor_id_str)

    # Validate certificate
    if verify_certificate(idm_public_key, requestor_cert):
        print("Requestor " + requestor_id_str + ": Certificate is valid")
    else:
        print("Requestor " + requestor_id_str + ": Invalid certificate")
        requestor_conn.sendall(b"ERROR: Certificate check failed")
        requestor_conn.close()
        exit()

    # Validate requestor's signature
    requestor_public_key = extract_requestor_public_key_cert(requestor_cert)    # Extract requestor's public key from requestor's certificate
    if verify_signature(requestor_public_key, requestor_signature, m1, server_id, encrypted_operations):
        print("Requestor " + requestor_id_str + ": Signature is valid")
    else:
        print("Requestor " + requestor_id_str + ": Invalid signature")
        requestor_conn.sendall(b"ERROR: Signature check")
        requestor_conn.close()
        exit()

    # Decrypt and parse encrypted part of message m1
    message = decrypt_message_asymmetric(idm_private_key, m1)
    nonce = message[ : NONCE_SIZE]
    encrypted_operations_key = message[NONCE_SIZE :]
    operations = decrypt_message_symmetric(encrypted_operations_key, encrypted_operations)
    
    policies = check_policies(requestor_conn, operations, requestor_id_str)

    # Computing the hash of the script
    H = generate_hash(operations)

    # Setting the expiration time of the token
    expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=15)
    expiration_time = str(expiration_time).encode()

    # Build token
    token = generate_signature(idm_private_key, requestor_id, H, server_id, policies, expiration_time)

    # Get server's public key from idm's database
    server_public_key = get_server_public_key(server_db, server_id)

    # Build message m2
    m2 = nonce + server_public_key + expiration_time + policies + token

    # Build signature
    m2Sign = generate_signature(idm_private_key, nonce, server_public_key, expiration_time, policies, token)

    # Send message
    message = m2 + m2Sign
    requestor_conn.sendall(message)
    requestor_conn.close()
    print("Requestor " + requestor_id_str + ": Sending message m2")

    # Close the connection and exit with no errors
    print("Closing the connection for Requestor " + requestor_id_str)
    exit()

def check_token(requestor_conn: socket.socket, server_id: str) -> Tuple[str, str, bytes]:
    # Read and load server's private key
    with open("server_private_key.pem", "rb") as f:           
        server_private_key_bytes = f.read()
    server_private_key = deserialise_private_key(server_private_key_bytes)

    # Read and load idm's public key
    with open("idm_public_key.pem", "rb") as f:
        idm_public_key_bytes = f.read()
    idm_public_key = deserialise_public_key(idm_public_key_bytes)

    # Receive and parse the message
    message = requestor_conn.recv(MESSAGE_SIZE)
    requestor_cert_bytes = message[ : X509_CERT_PEM_SIZE]
    token = message[X509_CERT_PEM_SIZE : 
                    X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE]
    token_exp_time_bytes = message[ X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE : 
                                    X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE + DATETIME_SIZE]
    H = message[X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE + DATETIME_SIZE : 
                X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE + DATETIME_SIZE + HASH_SIZE]
    policies = message[X509_CERT_PEM_SIZE + RSA_SIGNATURE_SIZE + DATETIME_SIZE + HASH_SIZE : -NONCE_SIZE]
    n1 = message[-NONCE_SIZE : ]

    # Extract requestor's ID and public key
    requestor_cert = deserialise_certificate(requestor_cert_bytes)
    requestor_id = extract_requestor_id_cert(requestor_cert)
    requestor_id_str = extract_requestor_id_cert_str(requestor_cert)
    requestor_public_key = requestor_cert.public_key()
    print('Received message from Requestor ' + requestor_id_str)

    # Validate expiration time
    token_exp_time = parse_datetime(token_exp_time_bytes)
    now = datetime.datetime.now()
    if now < token_exp_time:
        print("Requestor " + requestor_id_str + ": Token expiration time validated")
    else:
        print("Requestor " + requestor_id_str + ": Invalid token expiration time")
        requestor_conn.sendall(b"ERROR: Token expiration time validation failed")
        requestor_conn.close()
        exit()

    # Validate certificate
    if verify_certificate(idm_public_key, requestor_cert):
        print("Requestor " + requestor_id_str + ": Certificate is valid")
    else:
        print("Requestor " + requestor_id_str + ": Invalid certificate")
        requestor_conn.sendall(b"ERROR: Certificate validation failed")
        requestor_conn.close()
        exit()

    # Validate token
    if verify_signature(idm_public_key, token, requestor_id, H, server_id.encode(), policies, token_exp_time_bytes):
        print("Requestor " + requestor_id_str + ": Token is valid")
    else:
        print("Requestor " + requestor_id_str + ": ERROR - Invalid token")
        requestor_conn.sendall(b"ERROR: Token validation failed")
        requestor_conn.close()
        exit()

    # Choose n2
    n2 = generate_nonce()

    # Derive session key
    session_key = generate_session_key(n1, n2)

    # Build and send message m2
    m2 = encrypt_message_asymmetric(requestor_public_key, n2)
    m2Sign = generate_signature(server_private_key, m2, n1)
    message = m2 + m2Sign
    requestor_conn.sendall(message)
    print("Requestor " + requestor_id_str + ": Sending message m2")

    ######################################
    ######################################
    # Waiting for message from requestor #
    ######################################
    ######################################

    # Receive, decrypt and parse message m3
    message = requestor_conn.recv(MESSAGE_SIZE)
    print("Requestor " + requestor_id_str + ": Received message m3")
    m3 = decrypt_message_symmetric(session_key, message)
    received_n2 = m3[: NONCE_SIZE]
    operations = m3[NONCE_SIZE : ]

    # Verify n2
    if verify_nonce(n2, received_n2):
        print("Requestor " + requestor_id_str + ": Nonce verified")
    else:
        print("Requestor " + requestor_id_str + ": Nonce verification failed")
        requestor_conn.sendall(b"ERROR: Invalid nonce")
        requestor_conn.close()
        exit()

    # Verify H equals hash of operations
    if verify_hash(H, operations):
        print("Requestor " + requestor_id_str + ": Hash of operations verified")
        return (str(operations)[2:-1], requestor_id_str, session_key)
    else:
        print("Requestor " + requestor_id_str + ": Hash of operations verification failed")
        requestor_conn.sendall(b"ERROR: Invalid H")
        requestor_conn.close()
        exit()

def send_session_message(conn: socket.socket, session_key: bytes, message: str) -> None:
    message = message.encode()
    encrypted_message = encrypt_message_symmetric(session_key, message)
    mac = generate_mac(session_key, encrypted_message)
    conn.sendall(encrypted_message + mac)