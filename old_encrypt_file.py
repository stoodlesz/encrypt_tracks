import sqlite3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def calculate_checksum(file_data):
    sha256 = hashlib.sha256()
    sha256.update(file_data)
    checksum = sha256.hexdigest()
    return checksum


def encrypt_file_to_database(
    input_file_path, lyrics_file_path, filename, encryption_key
):
    # Read the input file
    with open(input_file_path, "rb") as input_file:
        file_data = input_file.read()
    # Generate a random initialisation vector (IV) for the song
    iv = os.urandom(16)
    # Create an AES cipher with CBC mode for the song
    cipher = Cipher(
        algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()
    )
    # Create a padder for PKCS7 padding for the song
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Apply padding to the file data
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded file data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Calculate the checksum of the file data
    file_checksum = calculate_checksum(file_data)

    # Read the lyrics file
    with open(lyrics_file_path, "rb") as lyrics_file:
        lyrics_data = lyrics_file.read()

    # Generate a random initialisation vector (IV) for the lyrics
    lyrics_iv = os.urandom(16)

    # Create an AES cipher with CBC mode for the lyrics
    lyrics_cipher = Cipher(
        algorithms.AES(encryption_key), modes.CBC(lyrics_iv), backend=default_backend()
    )

    # Create a padder for PKCS7 padding for the lyrics
    lyrics_padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Apply padding to the lyrics data
    lyrics_padded_data = lyrics_padder.update(lyrics_data) + lyrics_padder.finalize()

    # Encrypt the padded lyrics data
    lyrics_encryptor = lyrics_cipher.encryptor()
    encrypted_lyrics = (
        lyrics_encryptor.update(lyrics_padded_data) + lyrics_encryptor.finalize()
    )

    # Calculate the checksum of the lyrics data
    lyrics_checksum = calculate_checksum(lyrics_data)

    # Connect to the database
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()

    # Add the 'encrypted_lyrics' column if it doesn't exist
    cursor.execute("PRAGMA table_info(encrypted_files)")
    columns = cursor.fetchall()
    column_names = [column[1] for column in columns]
    if "encrypted_lyrics" not in column_names:
        cursor.execute("ALTER TABLE encrypted_files ADD COLUMN encrypted_lyrics BLOB")
    # Add the 'file_checksum' column if it doesn't exist
    if "file_checksum" not in column_names:
        cursor.execute("ALTER TABLE encrypted_files ADD COLUMN file_checksum TEXT")
    # Add the 'lyrics_checksum' column if it doesn't exist
    if "lyrics_checksum" not in column_names:
        cursor.execute("ALTER TABLE encrypted_files ADD COLUMN lyrics_checksum TEXT")

    # Prepare the query to insert the encrypted data into the database
    query = "INSERT INTO encrypted_files (filename, encrypted_data, encrypted_lyrics, file_checksum, lyrics_checksum) VALUES (?, ?, ?, ?, ?)"

    # Execute the query with the encrypted data, lyrics, and checksums
    cursor.execute(
        query,
        (filename, encrypted_data, encrypted_lyrics, file_checksum, lyrics_checksum),
    )

    # Commit the data
    conn.commit()
    # Close the connection
    conn.close()


def delete_file_from_database(filename):
    # Delete a file from the database
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()

    # Check if the file exists in the database
    cursor.execute("SELECT filename FROM encrypted_files WHERE filename=?", (filename,))
    result = cursor.fetchone()

    if result is not None:
        # Prompt the user for confirmation
        confirmation = input(
            f"Do you want to delete '{filename}'? Press 'y' to confirm or 'n' to cancel: "
        )

        if confirmation.lower() == "y":
            # Delete the file from the database
            cursor.execute("DELETE FROM encrypted_files WHERE filename=?", (filename,))

            # Commit the data
            conn.commit()

            print(f"File '{filename}' has been deleted from the database.")
        else:
            print("Deletion cancelled.")
    else:
        print(f"File '{filename}' does not exist in the database.")

    # Close the connection
    conn.close()


def modify_file_in_database(filename):
    # Modify a file in the database
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()

    # Check if the file exists in the database
    cursor.execute("SELECT filename FROM encrypted_files WHERE filename=?", (filename,))
    result = cursor.fetchone()

    if result is not None:
        new_filename = input("Enter the new filename: ")

        # Update the file entry in the database with the new filename
        cursor.execute(
            "UPDATE encrypted_files SET filename=? WHERE filename=?",
            (new_filename, filename),
        )

        # Commit the data
        conn.commit()

        print(f"File '{filename}' has been modified in the database.")
    else:
        print(f"File '{filename}' does not exist in the database.")

    # Close the connection
    conn.close()


# Prompt the user to enter the necessary information
input_file_path = input("Enter the path to the input file: ")
lyrics_file_path = input("Enter the path to the lyrics file: ")
filename = input("Enter the desired filename for the encrypted file: ")
# Generate a random encryption key
encryption_key = os.urandom(32)

# Encrypt and store the file in the database
encrypt_file_to_database(input_file_path, lyrics_file_path, filename, encryption_key)

# Display a thank you message
print("Thanks for uploading!")

# Prompt the user to choose an option
option = input("Choose an option: \na) Modify\nb) Delete\nc) Exit\n")

# Check the user's chosen option and perform the corresponding action
if option.lower() == "a":
    # Modify the file in the database
    modify_file_in_database(filename)
elif option.lower() == "b":
    # Delete the file from the database
    delete_file_from_database(filename)
elif option.lower() == "c":
    # Exit the program
    print("Exiting...")
else:
    # Handle invalid option
    print("Invalid option.")
