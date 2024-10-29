from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # If no passphrase is used
    )
    # Save the key to a file PEM format
    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Save the key to a file PEM format
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public)

    return private_key, public_key


def encrypt_message(public_key, message: str):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

def encrypt_message2(public_key, message: str, private_key2):
    """
    Convert an image to a encrypted message.

    Args:
        message (str): Original image array.
        private_key2: manufacture private key

    Returns:
        encrypted_message: encrypted message with the signature from the manufacturer.
    """
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode('utf-8'))
    message_hash = message_hash.finalize()

    signature = private_key2.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return encrypted_message, signature

def decrypt_message2(private_key, encrypted_message, signature):
    """
    Convert an encrypted message to a original message.

    Args:
        encrypted_message (str): Encrypted message from image.
        private_key: Private key of the software

    Returns:
        decrypted_message: decrypted message with the .
    """
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None

        )
    )

    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(decrypted_message.encode('utf-8'))
    message_hash = message_hash.finalize()

    public_key = private_key.public_key()
    public_key.verify(
        signature,
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return decrypted_message.decode('utf-8')