# File Encryption and Database Management

This code provides a basic file encryption and database management system. It allows you to encrypt files, store them in a SQLite database, and perform operations such as modifying and deleting files.

## Prerequisites

- Python 3.x
- SQLite
- `cryptography` library (can be installed via `pip install cryptography`)

## Getting Started

1. Clone or download the code repository to your local machine.

2. Install the required dependencies by running the following command:

```bash
pip install cryptography
```

3. Create an empty SQLite database named `library.db` in the same directory as the code.

4. Execute the code using the Python interpreter:

```bash
python encrypt-file.py
```

## Encrypting and Storing Files

1. When prompted, enter the path to the input file (the file you want to encrypt).

2. Enter the path to the lyrics file (optional - provide lyrics for the song).

3. Enter the desired filename for the encrypted file.

4. The code will encrypt the input file, store the encrypted data and lyrics in the database, and display a message confirming the successful upload.

## Modifying a File

1. After uploading a file, you will be presented with a menu to choose an option.

2. Select option "a" to modify a file.

3. Enter the filename of the file you want to modify.

4. Enter the new filename for the file.

5. The code will update the file entry in the database with the new filename and display a message confirming the modification.

## Deleting a File

1. After uploading a file, you will be presented with a menu to choose an option.

2. Select option "b" to delete a file.

3. Enter the filename of the file you want to delete.

4. You will be prompted for confirmation with a message showing the filename.

5. To proceed with the deletion, enter "y" and press Enter. To cancel the deletion, enter "n" and press Enter.

6. If the deletion is confirmed, the file will be removed from the database, and a message confirming the deletion will be displayed.

## Exiting the Program

1. After uploading a file or performing any operation, you will be presented with a menu to choose an option.

2. Select option "c" to exit the program.

3. The program will display an exit message and terminate.

## Modifying and Deleting Files using SQLite Commands in Bash

To perform the delete or modify operations on the database using bash commands, you can utilize the SQLite command-line tool. Here are the commands you can use:

### Delete a file from the database:

```bash
sqlite3 library.db "DELETE FROM encrypted_files WHERE filename='<filename>';"
```

Replace `filename` with the actual filename you want to delete.

### Modify a file in the database:

```bash
sqlite3 library.db "UPDATE encrypted_files SET <column_name>='<new_value>' WHERE filename='<filename>';"
```

Replace `<column_name>` with the specific column name you want to modify, `<new_value>` with the new value you want to assign to that column, and `<filename>` with the filename of the record you want to modify.

Please note that you need to have the library.db file in the current directory, and you should have the SQLite command-line tool installed on your system.

Note:
It is important to handle the encryption key securely to ensure the confidentiality of the files.
# encrypt_tracks
