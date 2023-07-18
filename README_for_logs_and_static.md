# Admin Logs Song Creation, Modification, Deletion - README

Admin Tools is a command-line application designed to manage a song library with lyrics encryption. This application allows you to add, modify, and delete songs in the library. It uses SQLite to store song information, including encrypted lyrics and a checksum to ensure data integrity.

## Prerequisites

Before running the Admin Tools application, ensure you have the following installed:

- Python 3 (https://www.python.org/downloads/)
- The required Python packages listed:
  - cryptography
  - sqlite3
  - werkzeug

## Getting Started

- Clone the repository or download the source code files to your local machine.

- Navigate to the directory containing the admin_tools.py file.

- Make sure you have the library.db file in the same directory. If not, the application will create it automatically.

- Run the application using the following command:

```bash
python logs_encryption_1.py
```

## How to Use

Upon running the Admin Tools application, you'll be presented with a menu where you can choose from the following options:

a) Logs: View the contents of the `insert file name` file containing logs.

b) Add Song: Add a new song to the library with lyrics and an optional song file (e.g., .mp3, .flac).

c) Modify File: Modify the name, lyrics, or song file of an existing song.

d) Delete File: Delete a song from the library.

e) Quit: Exit the application.

**Option b) Add Song**
When you select option "b" to add a new song, follow these steps:

1. Enter the song name when prompted.

2. Enter the song lyrics when prompted.

If desired, you can upload a song file in .mp3 or .flac format when prompted. Simply provide the file path to the song file. The application will read the file and store it in the database.

The lyrics will be encrypted using AES encryption with Cipher Block Chaining (CBC) mode, and the encryption key will be randomly generated. The encrypted data will be stored in the database along with the initialisation vector (IV) and a checksum to verify the data's integrity.

**Option c) Modify File**
When you select option "c" to modify a file, follow these steps:

1. Enter the name of the file you want to modify when prompted.

2. You can modify the file's name, lyrics, and song file. If you want to keep the current data, simply press Enter.

3. If you decide to modify the lyrics or upload a new song file, the application will re-encrypt the data using a new encryption key, IV, and checksum.

**Option d) Delete File**
When you select option "d" to delete a file, follow these steps:

1. 2. Enter the name of the file you want to delete when prompted.

The application will ask for confirmation before deleting the file. Type 'y' to confirm the deletion or 'n' to cancel.

## Encryption Details

The Admin Tools application uses AES encryption with Cipher Block Chaining (CBC) mode to encrypt the song lyrics. A random encryption key (32 bytes) and IV (16 bytes) are generated for each song. The encrypted data and IV are stored in the database along with a checksum of the original lyrics to ensure data integrity.

## Log File

The application logs all activities and user interactions to the application.log file. The log file contains the timestamp, log level (INFO or ERROR), and the logged message.

## Troubleshooting

If the application fails to open the library.db file or the application.log file, check if you have sufficient permissions to access these files.

Make sure to provide valid file paths when uploading song files or modifying songs.

## Additional Notes

It is essential to keep a backup of the library.db file in case of data loss or corruption.

Be cautious when modifying or deleting songs, as these actions cannot be undone.

For security reasons, avoid sharing the encryption key or the contents of the library.db file with unauthorised users.

## Contributions

Contributions to this project are welcome! If you find any issues or have suggestions for improvements, please feel free to submit a pull request or create an issue on the project's GitHub repository.
