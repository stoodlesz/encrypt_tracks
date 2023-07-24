## Music Library Application

This is a simple music library application that allows artists to add, modify, delete, and view their songs. Each song is encrypted using XOR encryption and is linked to the artist's username and password to provide secure access.

## Requirements

Before running the application, ensure you have the following dependencies installed:

- Python 3.x
- SQLite 3
- cryptography (install via pip install cryptography)
- Werkzeug (install via pip install Werkzeug)

## How to Use

You can start the application by running **xor_encryption.py**:

```bash
python xor_encryption.py
```

Upon launching the application, signing in as **admin**, you will see the main menu with several options:

```bash
Choose an option:
[a] Logs
[b] Add Song
[c] Delete Song
[d] Quit
```

- If you select a, you will be view logs, if admin.

Upon launching the application, signing in as an **artist**, you will see the main menu with several options:

```bash
Choose an option:
[b] Add Song
[b] Modify Song
[c] View Song
[d] Quit
```

- If you select a, you will be view logs, if admin.

- To add a new song, select b. You will be asked to provide the song name, lyrics, and the path to the song file. You will need to copy and paste the relative file path of the song from the file explorer, for example, open the entire folder in your IDE and using the file explorer in the IDE, right-click on the song you want to upload and `copy path`. This will be the path you use to upload the file. Please view the video file attached to this file called "SongMenu.gif" to see it in action (please note this is just to demonstrate the encryption and database works, it is not the finished product).

![Video_Proof](https://github.com/stoodlesz/encrypt_tracks/assets/29131646/27d3ee9f-9df3-4643-b4ff-8f02652e30d1)

> Add a new song to the database.

        This function allows the user to add a new song to the song database. It prompts the user
        to enter the song name, lyrics, and the file path of the song to be added. The function
        encrypts the lyrics using XOR encryption, calculates the checksum of the lyrics, and stores
        the song details along with the encryption key in the database.

        Note:
            The encrypted lyrics and the encryption key will be stored in separate database tables.

        Raises:
            FileNotFoundError: If the file path provided by the user does not exist.

- To modify a song, select c. You will be prompted for the song's filename and your username and password for verification. After authentication, you can enter the new song filename and lyrics.

  > Modify an existing song in the database.

         This function allows the user to modify an existing song in the song database. It prompts
         the user to enter the filename of the song to be modified, and then the new filename and
         lyrics. The function re-encrypts the modified lyrics using the existing encryption key and
         updates the song details in the database.

         Note:
             The encryption key for the song remains unchanged.

         Raises:
             FileNotFoundError: If the file path provided by the user does not exist.

- To delete a song, select d. Similar to modification, you will need to enter the song's filename. It will double-check with a y or n request.

  > Delete a song from the database.

        This function allows the user to delete a song from the song database. It prompts the user
        to enter the filename of the song to be deleted. The function removes both the song entry
        and its associated encryption key from the database.

        Note:
            The associated encryption key for the song is deleted from the database.

        Raises:
            FileNotFoundError: If the file path provided by the user does not exist.

- To view a song, select e.

  > View the decrypted lyrics of a song.

        This function allows the user to view the decrypted lyrics of a song by providing the filename.
        The lyrics are decrypted using XOR with the associated encryption key from the song_keys table.

- To quit the application, select f.

## SQL Statements

To show how the SQL file works here is a demonstration:

```bash
#!/bin/bash

# Create the SQLite database file
touch library.db

# Execute SQL commands to create the 'songs' table
sqlite3 library.db <<EOF
CREATE TABLE IF NOT EXISTS songs (
    name TEXT,
    lyrics TEXT,
    encrypted_lyrics BLOB,
    song_checksum TEXT
);

CREATE TABLE IF NOT EXISTS song_keys (
    song_name TEXT,
    encryption_key BLOB
);
EOF

# Placeholder values for the song details
song_name="YourSongName"
song_lyrics="YourSongLyrics"
encrypted_lyrics="YourEncryptedData"
song_checksum="YourChecksum"
encryption_key="YourEncryptionKey"

# Insert a new song into the 'songs' table
sqlite3 library.db "INSERT INTO songs (name, lyrics, encrypted_lyrics, song_checksum) VALUES ('$song_name', '$song_lyrics', '$encrypted_lyrics', '$song_checksum');"

# Insert the encryption key into the 'song_keys' table
sqlite3 library.db "INSERT INTO song_keys (song_name, encryption_key) VALUES ('$song_name', '$encryption_key');"

# Update an existing song in the 'songs' table
new_filename="YourNewSongName"
new_lyrics="YourModifiedLyrics"
new_song_checksum="YourNewChecksum"
sqlite3 library.db "UPDATE songs SET name='$new_filename', lyrics='$new_lyrics', encrypted_lyrics='$encrypted_lyrics', song_checksum='$new_song_checksum' WHERE name='$song_name';"

# Delete a song from the 'songs' table
song_to_delete="SongToDelete"
sqlite3 library.db "DELETE FROM songs WHERE name='$song_to_delete';"

# Delete a song's encryption key from the 'song_keys' table
sqlite3 library.db "DELETE FROM song_keys WHERE song_name='$song_to_delete';"

# Retrieve a song's details from the 'songs' table
song_to_retrieve="SongToRetrieve"
sqlite3 library.db "SELECT name, lyrics, encrypted_lyrics, song_checksum FROM songs WHERE name='$song_to_retrieve';"

# Retrieve a song's encryption key from the 'song_keys' table
sqlite3 library.db "SELECT encryption_key FROM song_keys WHERE song_name='$song_to_retrieve';"
```

Replace the placeholders ("YourSongName", "YourSongLyrics", etc.) with the desired values in the script. When these are run, it will execute the SQL commands using the provided placeholders to create, insert, update, and retrieve data from the SQLite database.
