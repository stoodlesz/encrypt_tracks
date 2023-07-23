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

- To add a new song, select b. You will be asked to provide the song name, lyrics, and the path to the song file. Additionally, you need to enter your username and password to link the song to your account.

- To modify a song, select c. You will be prompted for the song's filename and your username and password for verification. After authentication, you can enter the new song filename and lyrics.

- To delete a song, select d. Similar to modification, you will need to enter the song's filename and your username and password to confirm the deletion.

- To view a song, select e. Again, enter the song's filename and your username and password to decrypt and view the song's lyrics.

- To quit the application, select f.
