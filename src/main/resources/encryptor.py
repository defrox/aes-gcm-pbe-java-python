#!/usr/bin/env python3
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets, argparse, sys, binascii

backend = default_backend()

iterations = 65536
bytes_key_length = 32
bytes_salt_length = 16
bytes_iv_length = 16
bytes_auth_tag_length = 16


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=bytes_key_length, salt=salt,
        iterations=iterations, backend=backend)
    return kdf.derive(password)

def aes_gcm_encrypt(message: str, password: str) -> str:
    auth_tag = secrets.token_bytes(bytes_auth_tag_length)
    iv = secrets.token_bytes(bytes_iv_length)
    salt = secrets.token_bytes(bytes_salt_length)
    key = _derive_key(password.encode(), salt)
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode())
    return b64e(iv + salt + ciphertext + auth_tag).decode('utf-8')


def aes_gcm_decrypt(token: str, password: str) -> str:
    try:
        data = b64d(token.encode())
    except (TypeError, binascii.Error):
        raise InvalidToken
    (iv, salt, ciphertext, auth_tag) = data[:bytes_iv_length], data[bytes_iv_length : bytes_iv_length + bytes_salt_length ], data[bytes_iv_length + bytes_salt_length : -bytes_auth_tag_length], data[-bytes_auth_tag_length : ]
    key = _derive_key(password.encode(), salt)
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv, salt), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext)
    return decrypted.decode('utf-8')


def print_help(args, **kwargs):
    kwargs.get("parent_parser").print_help()


def encrypt(args, **kwargs):
    if args.password and args.message:
        password = args.password
        message = args.message
    else:
        print("Password and message required")
        kwargs.get("parent_parser").print_help()
        sys.exit(1)
    result = aes_gcm_encrypt(message, password)
    print(result)
    return result


def decrypt(args, **kwargs):
    if args.password and args.message:
        password = args.password
        message = args.message
    else:
        print("Password and encrypted message required")
        kwargs.get("parent_parser").print_help()
        sys.exit(1)
    result = aes_gcm_decrypt(message, password)
    print(result)
    return result



def test(args, **kwargs):
    if args.password and args.message:
        password = args.password
        message = args.message
    else:
        print("Password and encrypted message required")
        kwargs.get("parent_parser").print_help()
        sys.exit(1)
    print(f'Testing encryption with message: {message}')
    print(f'and password: {password}')
    encrypted = aes_gcm_encrypt(message, password)
    print(f'Encrypted message: {encrypted}')
    decrypted = aes_gcm_decrypt(encrypted, password)
    print(f'Decrypted message: {decrypted}')


def main():
    try:
        parent_parser = argparse.ArgumentParser(description="AES_GCM Password Based encrypter and decrypter")
        parent_parser.set_defaults(func=print_help)

        subparsers = parent_parser.add_subparsers(title="actions", description="valid actions", dest="command")
        parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a message with a password")
        parser_encrypt.add_argument('-p', '--password', type=str, help='password', required=True)
        parser_encrypt.add_argument('-m', '--message', type=str, help='message to encrypt', required=True)
        parser_encrypt.set_defaults(func=encrypt)

        parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a message with a password")
        parser_decrypt.add_argument('-p', '--password', type=str, help='password', required=True)
        parser_decrypt.add_argument('-m', '--message', type=str, help='message to decrypt', required=True)
        parser_decrypt.set_defaults(func=decrypt)

        parser_test = subparsers.add_parser("test", help="Test the python script against the java script")
        parser_test.add_argument('-p', '--password', type=str, help='password', required=True)
        parser_test.add_argument('-m', '--message', type=str, help='message', required=True)
        parser_test.set_defaults(func=test)

        args = parent_parser.parse_args()
        args.func(args=args, parent_parser=parent_parser)

    except Exception as ex:
        print("An error occurred: {}".format(ex))
        sys.exit(1)


if __name__ == "__main__":
    main()
