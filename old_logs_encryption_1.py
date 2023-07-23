import logging
import sqlite3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from werkzeug.utils import secure_filename


def calculate_checksum(file_data):
    # Calculate the checksum of the file data using SHA-256 hashing algorithm
    sha256 = hashlib.sha256()
    sha256.update(file_data)
    checksum = sha256.hexdigest()
    return checksum


class SongDecryptor:
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key

    def decrypt_lyrics(self, encrypted_lyrics, iv):
        # Decrypt the lyrics using the provided encryption key and IV (converted from hex)
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_lyrics) + decryptor.finalize()

        # Remove padding from the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data


class AddSong:
    def __init__(self):
        # Initialize the SongDecryptor with a random encryption key
        self.song_decryptor = SongDecryptor(os.urandom(32))

    def encrypt_file(self, file_data, encryption_key):
        # Encrypt the file data using AES encryption with CBC mode
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()
        )
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return iv, encrypted_data

    def decrypt_file(self, encrypted_data, iv):
        # Decrypt the file data using the SongDecryptor
        return self.song_decryptor.decrypt_lyrics(encrypted_data, iv)

    def add_song(self):
        song_name = input("Enter the song name: ")
        song_lyrics = input("Enter the song lyrics: ")

        file_path = input("Enter the song file path: ")

        try:
            with open(file_path, "rb") as file:
                song_file = file.read()
                song_filename = secure_filename(os.path.basename(file_path))
        except FileNotFoundError:
            print("File not found.")
            return

        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        # Create the songs table if it doesn't exist
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS songs (name TEXT, lyrics TEXT, encrypted_lyrics BLOB, iv BLOB, song_checksum TEXT)"
        )

        query = (
            "INSERT INTO songs (name, lyrics, encrypted_lyrics, iv) VALUES (?, ?, ?, ?)"
        )
        encryption_key = os.urandom(32)
        iv, encrypted_data = self.encrypt_file(song_lyrics.encode(), encryption_key)
        song_checksum = calculate_checksum(song_lyrics.encode())

        cursor.execute(
            query,
            (song_name, song_lyrics, encrypted_data, iv),
        )

        update_query = "UPDATE songs SET song_checksum=? WHERE name=?"
        cursor.execute(update_query, (song_checksum, song_name))

        conn.commit()

        conn.close()

        print(f"Song '{song_name}' has been added to the database and encrypted.")
"""         print("KEEP THIS KEY TO ACCESS YOUR FILE:")
        print(encryption_key.hex()) """

    def view_song(self):
        song_name = input("Enter the song name to view: ")

        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name, encrypted_lyrics, iv FROM songs WHERE name=?"
        cursor.execute(query, (song_name,))
        result = cursor.fetchone()

        if result is not None:
            (
                song_name,
                encrypted_lyrics,
                iv_hex,
            ) = result

            # Ensure iv_hex is a string
            iv_hex = iv_hex.decode() if isinstance(iv_hex, bytes) else iv_hex

            # Convert the IV from hex to bytes
            iv = bytes.fromhex(iv_hex)

            # Decrypt the lyrics using the provided IV and a new random encryption key
            song_decryptor = SongDecryptor(os.urandom(32))
            decrypted_lyrics = song_decryptor.decrypt_lyrics(encrypted_lyrics, iv)

            # Display the decrypted lyrics
            print(f"Decrypted Lyrics for '{song_name}':\n{decrypted_lyrics.decode()}")
        else:
            print(f"Song '{song_name}' does not exist in the database.")

        conn.close()


class AdminTools:
    def __init__(self):
        self.add_song_tool = AddSong()

    def choice_logs_menu(self):
        while True:
            print("\nAdmin Tools Menu:")
            print("[1] Option 1: Select 1 for logs")
            print("[2] Option 2: Select 2 to quit")

            choice = input("> ")

            if choice == "1":
                logging.info("Admin user accessed the logs.")
                print("Logs file has been opened.")
                self.logs()
            elif choice == "2":
                logging.info("Admin user chose to go back to the main menu.")
                print("Returning to the main menu.")
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")

    def logs(self):
        logs_file = "application.log"
        try:
            with open(logs_file, "r", encoding="utf-8") as file:
                logs_messages = file.read()
                print(logs_messages)
        except FileNotFoundError:
            print("Logs file failed to open.")

    def modify_file_in_database(self, filename):
        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name, lyrics, encrypted_lyrics, iv, song_checksum FROM songs WHERE name=?"
        cursor.execute(query, (filename,))
        result = cursor.fetchone()

        if result is not None:
            (
                song_name,
                song_lyrics,
                encrypted_lyrics,
                iv,
                song_checksum,
            ) = result

            new_filename = input("Enter the new filename: ")
            new_lyrics = input("Enter the new lyrics: ")

            file_path = input("Enter the path to the new song file: ")
            new_song_file = open(file_path, "rb").read()
            new_song_filename = secure_filename(os.path.basename(file_path))

            # Update the file entry with the new filename, lyrics, and file data
            update_query = "UPDATE songs SET name=?, lyrics=?, encrypted_lyrics=?, iv=? WHERE name=?"
            cursor.execute(
                update_query,
                (new_filename, new_lyrics, new_song_file, iv, song_name),
            )

            conn.commit()

            print(f"File '{song_name}' has been modified to '{new_filename}'.")
        else:
            print(f"File '{filename}' does not exist in the database.")

        conn.close()

    def delete_file_from_database(self, filename):
        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name FROM songs WHERE name=?"
        cursor.execute(query, (filename,))
        result = cursor.fetchone()

        if result is not None:
            confirmation = input(
                f"Do you want to delete '{filename}'? Press 'y' to confirm or 'n' to cancel: "
            )

            if confirmation.lower() == "y":
                delete_query = "DELETE FROM songs WHERE name=?"
                cursor.execute(delete_query, (filename,))

                conn.commit()

                print(f"File '{filename}' has been deleted from the database.")
            else:
                print("Deletion canceled.")
        else:
            print(f"File '{filename}' does not exist in the database.")
            conn.close()

    def view_song(self, filename):
        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name, encrypted_lyrics, iv FROM songs WHERE name=?"
        cursor.execute(query, (filename,))
        result = cursor.fetchone()

        if result is not None:
            (
                song_name,
                encrypted_lyrics,
                iv_hex,
            ) = result

            # Ensure iv_hex is a string
            if isinstance(iv_hex, bytes):
                iv_hex = iv_hex.decode()

            # Convert the IV from hex to bytes
            iv = bytes.fromhex(iv_hex)

            # Decrypt the lyrics using the provided IV and a new random encryption key
            song_decryptor = SongDecryptor(os.urandom(32))
            decrypted_lyrics = song_decryptor.decrypt_lyrics(encrypted_lyrics, iv)

            # Display the decrypted lyrics
            print(f"Decrypted Lyrics for '{song_name}':\n{decrypted_lyrics.decode()}")
        else:
            print(f"Song '{song_name}' does not exist in the database.")

        conn.close()


admin_tools = AdminTools()

print("Thanks for using the Admin Tools!")
option = input(
    "Choose an option: \na) Logs\nb) Add Song\nc) Modify File\nd) Delete File\ne) View Song\nf) Quit\n"
)

if option.lower() == "a":
    admin_tools.choice_logs_menu()
elif option.lower() == "b":
    admin_tools.add_song_tool.add_song()
elif option.lower() == "c":
    filename = input("Enter the filename to modify: ")
    admin_tools.modify_file_in_database(filename)
elif option.lower() == "d":
    filename = input("Enter the filename to delete: ")
    admin_tools.delete_file_from_database(filename)
elif option.lower() == "e":
    filename = input("Enter the filename to view: ")
    admin_tools.view_song(filename)
elif option.lower() == "f":
    print("Exiting...")
else:
    print("Invalid option.")
