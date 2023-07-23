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

Upon launching the application, you will see the main menu with several options:

```bash
Choose an option:
[a] Logs
[b] Add Song
[c] Modify Song
[d] Delete Song
[e] View Song
[f] Quit
```

- If you select a, you will be view logs, if admin.

- To add a new song, select b. You will be asked to provide the song name, lyrics, and the path to the song file. You will need to copy and paste the relative file path of the song from the file explorer, for example, open the entire folder in your IDE and using the file explorer in the IDE, right-click on the song you want to upload and `copy path`. This will be the path you use to upload the file. Please view the video file attached to this file called "SongMenu.gif".

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
