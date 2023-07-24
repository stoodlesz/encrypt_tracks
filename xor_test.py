# pylint: disable=missing-function-docstring
import logging
import sqlite3
import os
import hashlib
from werkzeug.utils import secure_filename


class SongEncryptor:
    @staticmethod
    def xor_encrypt(data, key):
        # Perform XOR encryption on data using the given key
        encrypted_data = bytes([a ^ b for a, b in zip(data, key)])
        return encrypted_data

    @staticmethod
    def xor_decrypt(encrypted_data, key):
        # Perform XOR decryption on encrypted_data using the given key
        decrypted_data = bytes([a ^ b for a, b in zip(encrypted_data, key)])
        return decrypted_data


class ArtistTools:
    @classmethod
    def add_song(cls):
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
            "CREATE TABLE IF NOT EXISTS songs (name TEXT, lyrics TEXT, encrypted_lyrics BLOB, song_checksum TEXT)"
        )

        # Generate a random encryption key for XOR encryption
        encryption_key = os.urandom(len(song_lyrics.encode()))

        # Encrypt the song lyrics using XOR
        encrypted_lyrics = SongEncryptor.xor_encrypt(
            song_lyrics.encode(), encryption_key
        )

        # Calculate the checksum of the song lyrics
        song_checksum = hashlib.sha256(song_lyrics.encode()).hexdigest()

        query = "INSERT INTO songs (name, lyrics, encrypted_lyrics, song_checksum) VALUES (?, ?, ?, ?)"
        cursor.execute(
            query,
            (song_name, song_lyrics, encrypted_lyrics, song_checksum),
        )

        # Create a table to store the encryption keys
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS song_keys (song_name TEXT, encryption_key BLOB)"
        )

        # Insert the encryption key into the song_keys table
        key_query = "INSERT INTO song_keys (song_name, encryption_key) VALUES (?, ?)"
        cursor.execute(key_query, (song_name, encryption_key))

        conn.commit()
        conn.close()

        print(f"Song '{song_name}' has been added to the database and encrypted.")

    @classmethod
    def modify_song(cls):
        filename = input("Enter the filename to modify: ")

        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name, lyrics, encrypted_lyrics, song_checksum FROM songs WHERE name=?"
        cursor.execute(query, (filename,))
        result = cursor.fetchone()

        if result is not None:
            (
                song_name,
                song_lyrics,
                encrypted_lyrics,
                song_checksum,
            ) = result

            new_filename = input("Enter the new filename: ")
            new_lyrics = input("Enter the new lyrics: ")

            # Update the song checksum for the modified lyrics
            new_song_checksum = hashlib.sha256(new_lyrics.encode()).hexdigest()

            # Encrypt the new song lyrics using XOR
            encryption_key = cursor.execute(
                "SELECT encryption_key FROM song_keys WHERE song_name=?", (song_name,)
            ).fetchone()[0]
            encrypted_lyrics = SongEncryptor.xor_encrypt(
                new_lyrics.encode(), encryption_key
            )

            # Update the file entry with the new filename, lyrics, and encrypted data
            update_query = "UPDATE songs SET name=?, lyrics=?, encrypted_lyrics=?, song_checksum=? WHERE name=?"
            cursor.execute(
                update_query,
                (
                    new_filename,
                    new_lyrics,
                    encrypted_lyrics,
                    new_song_checksum,
                    song_name,
                ),
            )

            conn.commit()

            print(
                f"File '{song_name}' has been modified to '{new_filename}' and re-encrypted."
            )
        else:
            print(f"File '{filename}' does not exist in the database.")

        conn.close()

    @classmethod
    def delete_song(cls):
        filename = input("Enter the filename to delete: ")

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

                delete_key_query = "DELETE FROM song_keys WHERE song_name=?"
                cursor.execute(delete_key_query, (filename,))

                conn.commit()

                print(f"File '{filename}' has been deleted from the database.")
            else:
                print("Deletion canceled.")
        else:
            print(f"File '{filename}' does not exist in the database.")

        conn.close()

    @classmethod
    def view_song(cls):
        filename = input("Enter the filename to view: ")

        conn = sqlite3.connect("library.db")
        cursor = conn.cursor()

        query = "SELECT name, encrypted_lyrics FROM songs WHERE name=?"
        cursor.execute(query, (filename,))
        result = cursor.fetchone()

        if result is not None:
            song_name, encrypted_lyrics = result

            # Get the encryption key from the song_keys table
            encryption_key = cursor.execute(
                "SELECT encryption_key FROM song_keys WHERE song_name=?", (song_name,)
            ).fetchone()[0]

            # Decrypt the lyrics using XOR and the encryption key
            decrypted_lyrics = SongEncryptor.xor_decrypt(
                encrypted_lyrics, encryption_key
            )

            print(f"Decrypted Lyrics for '{song_name}':\n{decrypted_lyrics.decode()}")
        else:
            print(f"Song '{filename}' does not exist in the database.")

        conn.close()


class AdminTools:
    @staticmethod
    def choice_logs_menu():
        while True:
            print("\nAdmin Tools Menu:")
            print("[1] Option 1: Select 1 for logs")
            print("[2] Option 2: Select 2 to quit")

            choice = input("> ")

            if choice == "1":
                logging.info("Admin user accessed the logs.")
                print("Logs file has been opened.")
                AdminTools.logs()
            elif choice == "2":
                logging.info("Admin user chose to go back to the main menu.")
                print("Returning to the main menu.")
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")

    @staticmethod
    def logs():
        logs_file = "application.log"
        try:
            with open(logs_file, "r", encoding="utf-8") as file:
                logs_messages = file.read()
                print(logs_messages)
        except FileNotFoundError:
            print("Logs file failed to open.")


print("Thanks for using the Admin Tools!")
option = input(
    "Choose an option: \na) Logs\nb) Add Song\nc) Modify Song\nd) Delete Song\ne) View Song\nf) Quit\n"
)

if option.lower() == "a":
    AdminTools.choice_logs_menu()
elif option.lower() == "b":
    ArtistTools.add_song()
elif option.lower() == "c":
    ArtistTools.modify_song()
elif option.lower() == "d":
    ArtistTools.delete_song()
elif option.lower() == "e":
    ArtistTools.view_song()
elif option.lower() == "f":
    print("Exiting...")
else:
    print("Invalid option.")
