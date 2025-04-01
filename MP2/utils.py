import os
import sys
import io
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def print_raw_data(data):
    sys.stdout.buffer.write(data)

def read_input(file):
    if file:
        with open(file, 'r') as f:
            return f.read()
    else:
        return sys.stdin.read()

def read_input_raw(file):
    if file:
        with open(file, 'rb') as f:
            return f.read()
    else:
        return sys.stdin.buffer.read()

def append_to_path(path, suffix):
    return Path(str(path) + suffix)

def generate_private_key(output, bits):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )
    
    with open(output, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return None

def generate_public_key(private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    public_key = private_key.public_key()
    
    output = append_to_path(private_key_path, ".pub")
    with open(output, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return None

def encrypt_message_rsa_oaep(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message_rsa_oaep(private_key, encrypted_message):
    plaintext = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign_message_with_rsassa_pss(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_message_with_rsassa_pss(public_key, decrypted_message, signature):
    public_key.verify(
        signature,
        decrypted_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return None

def generate_encrypted_message(message, public_key_path, signature_path, output):
    # Load the public key for encryption
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    
    # Load the private key for signing
    with open(signature_path, 'rb') as key_file:
        signature_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    # Encrypt the message
    encrypted_data = encrypt_message_rsa_oaep(public_key, message)
    
    # Sign the original message
    digital_signature = sign_message_with_rsassa_pss(signature_key, message)
    
    # Concatenate the encrypted message and digital signature
    signed_message = encrypted_data + digital_signature
    
    # Write to output or stdout
    if str(output) == ".":
        print_raw_data(signed_message)
    else:
        with open(output, 'wb') as f:
            f.write(signed_message)
    
    return None

def generate_decrypted_message(encrypted_message, private_key_path, signature_path, output, skip_verification):
    # Load the private key for decryption
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
    # Load the public key for verification
    with open(signature_path, 'rb') as key_file:
        signature_key = serialization.load_pem_public_key(
            key_file.read()
        )
    
    # Split the message into encrypted data and signature
    # Assuming 50/50 split as in the original code
    midpoint = len(encrypted_message) // 2
    encrypted_data_slice = encrypted_message[:midpoint]
    signed_message = encrypted_message[midpoint:]
    
    # Decrypt the message
    decrypted_data = decrypt_message_rsa_oaep(private_key, encrypted_data_slice)
    
    # Verify the signature if not skipped
    if not skip_verification:
        try:
            verify_message_with_rsassa_pss(signature_key, decrypted_data, signed_message)
        except InvalidSignature as e:
            raise Exception("Signature verification failed") from e
    
    # Write to output or stdout
    if str(output) == ".":
        print_raw_data(decrypted_data)
    else:
        with open(output, 'wb') as f:
            f.write(decrypted_data)
    
    return None