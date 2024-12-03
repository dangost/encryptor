import os
import sys
import sqlite3
import hashlib
from multiprocessing import Pool, cpu_count
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from argparse import ArgumentParser
from pathlib import Path
from getpass import getpass

CHUNK_SIZE = 1024 * 1024 * 16  # 1mb chunk


def get_key_iv(key_str):
    """Генерирует ключ и IV из строки."""
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(16)
    return key, iv


def encrypt_chunk(key, iv, chunk):
    """Шифрует часть данных."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_chunk = padder.update(chunk) + padder.finalize()
    return encryptor.update(padded_chunk) + encryptor.finalize()


def decrypt_chunk(key, iv, chunk):
    """Расшифровывает часть данных."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_chunk = decryptor.update(chunk) + decryptor.finalize()
    return unpadder.update(padded_chunk) + unpadder.finalize()


def process_file_encrypt(args):
    file_path, key, iv = args
    file_size = os.path.getsize(file_path)
    chunks = []

    with open(file_path, "rb") as f:
        for chunk_index in range((file_size + CHUNK_SIZE - 1) // CHUNK_SIZE):
            chunk = f.read(CHUNK_SIZE)
            encrypted_chunk = encrypt_chunk(key, iv, chunk)
            chunks.append((chunk_index, encrypted_chunk))

    return file_path, chunks


def process_file_decrypt(args):
    file_path, key, iv, chunks = args
    with open(file_path, "wb") as f:
        for chunk_index, encrypted_chunk in sorted(chunks):
            decrypted_chunk = decrypt_chunk(key, iv, encrypted_chunk)
            f.write(decrypted_chunk)


def encrypt_directory(directory, db_path, key):
    key, iv = get_key_iv(key)

    with sqlite3.connect(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            chunk_index INTEGER,
            data BLOB
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key BLOB,
            iv BLOB
        )
        """)
        conn.execute("INSERT INTO metadata (key, iv) VALUES (?, ?)", (key, iv))

        files = list(Path(directory).rglob("*") if Path(directory).is_dir() else [Path(directory)])
        args = [(str(file), key, iv) for file in files if file.is_file()]

        with Pool(cpu_count()) as pool:
            results = pool.map(process_file_encrypt, args)

        for file_path, chunks in results:
            for chunk_index, data in chunks:
                conn.execute(
                    "INSERT INTO files (original_path, chunk_index, data) VALUES (?, ?, ?)",
                    (file_path, chunk_index, data)
                )
        conn.commit()


def decrypt_directory(db_path, output_dir):
    with sqlite3.connect(db_path) as conn:
        key, iv = conn.execute("SELECT key, iv FROM metadata").fetchone()
        records = conn.execute("SELECT original_path, chunk_index, data FROM files").fetchall()

        files = {}
        for original_path, chunk_index, data in records:
            if original_path not in files:
                files[original_path] = []
            files[original_path].append((chunk_index, data))

        output_dir = Path(output_dir)
        args = [
            (output_dir / Path(file).relative_to(file), key, iv, chunks)
            for file, chunks in files.items()
        ]

        with Pool(cpu_count()) as pool:
            pool.map(process_file_decrypt, args)


def main():
    parser = ArgumentParser(description="Encrypt or decrypt files and directories.")
    parser.add_argument("-e", "--encrypt", help="Encrypt a file or directory.", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt a database.", action="store_true")
    parser.add_argument("--file", help="File to process.")
    parser.add_argument("-r", "--directory", help="Directory to process.")
    parser.add_argument("--key", help="Encryption/Decryption key.")

    args = parser.parse_args()

    key = args.key or getpass("Enter encryption/decryption key: ")

    if args.encrypt:
        if args.file:
            output = f"{Path(args.file).name}.fc"
        elif args.directory:
            output = f"{Path(args.directory).name}.fc"
        else:
            print("Error: Please provide a file or directory for encryption.")
            sys.exit(1)
    elif args.decrypt:
        output = None
    else:
        print("Error: Please specify --encrypt or --decrypt.")
        sys.exit(1)

    if args.encrypt and (args.file or args.directory):
        encrypt_directory(args.file or args.directory, output, key)
        print(f"Encryption completed. Output saved to {output}")
    elif args.decrypt:
        if not args.file:
            print("Error: Please provide a .fc file for decryption.")
            sys.exit(1)
        decrypt_directory(args.file, os.getcwd())
        print("Decryption completed. Files restored to current directory.")
    else:
        print("Invalid arguments. Use -h for help.")
        sys.exit(1)


if __name__ == "__main__":
    main()
