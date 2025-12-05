from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os

class RSACipher:
    def __init__(self):
        if not os.path.exists('keys'):
            os.makedirs('keys')

    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        with open('keys/private.pem', 'wb') as f:
            f.write(private_key)
        with open('keys/public.pem', 'wb') as f:
            f.write(public_key)
            
        return private_key.decode('utf-8'), public_key.decode('utf-8')

    def load_keys(self):
        try:
            if os.path.exists('keys/private.pem') and os.path.exists('keys/public.pem'):
                with open('keys/private.pem', 'rb') as f:
                    private_key = f.read().decode('utf-8')
                with open('keys/public.pem', 'rb') as f:
                    public_key = f.read().decode('utf-8')
                return private_key, public_key
            return None, None
        except Exception:
            return None, None

    def encrypt(self, message, key):
        rsakey = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(rsakey)
        encrypted_message = cipher.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted_message).decode('utf-8')

    def decrypt(self, ciphertext, key):
        rsakey = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(rsakey)
        decoded_encrypted_message = base64.b64decode(ciphertext)
        decrypted_message = cipher.decrypt(decoded_encrypted_message)
        return decrypted_message.decode('utf-8')

    def sign(self, message, key):
        rsakey = RSA.import_key(key)
        signer = pkcs1_15.new(rsakey)
        digest = SHA256.new(message.encode('utf-8'))
        signature = signer.sign(digest)
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, message, signature, key):
        rsakey = RSA.import_key(key)
        verifier = pkcs1_15.new(rsakey)
        digest = SHA256.new(message.encode('utf-8'))
        try:
            verifier.verify(digest, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False