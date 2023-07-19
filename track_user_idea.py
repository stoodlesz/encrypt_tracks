# ... (existing code from xor_test.py with the libraries and imports and encryption and decryption) this is just an idea of how we could set up this file!

class ArtistTools:
    @classmethod
    def login(cls):
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Check if the username and password match an existing user
        # and log the user in if the credentials are correct.

    @classmethod
    def register(cls):
        username = input("Enter your desired username: ")
        password = input("Enter your desired password: ")

        # Create a new user account with the given username and password.

    @classmethod
    def add_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not user_logged_in():
            print("You need to log in first.")
            return

        # ... (rest of the code to add a song)

    @classmethod
    def modify_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not user_logged_in():
            print("You need to log in first.")
            return

        # ... (rest of the code to modify a song)

    @classmethod
    def delete_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not user_logged_in():
            print("You need to log in first.")
            return

        # ... (rest of the code to delete a song)

    @classmethod
    def view_song(cls):
        # ... (rest of the code to view a song)

# ... (existing code below)

def user_logged_in():
    # Implement this function to check if a user is logged in based on the session.
    # Return True if the user is logged in, otherwise False.

print("Thanks for using the Admin Tools!")
option = input(
    "Choose an option: \na) Login\nb) Register\nc) Add Song\nd) Modify Song\ne) Delete Song\nf) View Song\ng) Quit\n"
)

if option.lower() == "a":
    ArtistTools.login()
elif option.lower() == "b":
    ArtistTools.register()
elif option.lower() == "c":
    ArtistTools.add_song()
elif option.lower() == "d":
    ArtistTools.modify_song()
elif option.lower() == "e":
    ArtistTools.delete_song()
elif option.lower() == "f":
    ArtistTools.view_song()
elif option.lower() == "g":
    print("Exiting...")
else:
    print("Invalid option.")

## -------------------------------------------------------
# OR THIS IS ANOTHER IDEA:

import current_user  # Import the current_user module from the authentication system

# ... (CODE FROM XOR_TEST FILE LIKE BEFORE)

class ArtistTools:
    @classmethod
    def add_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not current_user.is_authenticated():
            print("You need to log in first.")
            return

        song_name = input("Enter the song name: ")
        song_lyrics = input("Enter the song lyrics: ")

        # ... (rest of the code to add a song)

        # Retrieve the user_id of the currently logged-in user
        user_id = current_user.get_user_id()

        # Store the song details along with the user_id in the songs table
        query = "INSERT INTO songs (user_id, name, lyrics, encrypted_lyrics, song_checksum) VALUES (?, ?, ?, ?, ?)"
        cursor.execute(
            query,
            (user_id, song_name, song_lyrics, encrypted_lyrics, song_checksum),
        )

        # ... (rest of the code to store the encryption key in the song_keys table)

        conn.commit()
        conn.close()

        print(f"Song '{song_name}' has been added to the database and encrypted.")

    @classmethod
    def modify_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not current_user.is_authenticated():
            print("You need to log in first.")
            return

        # ... (rest of the code to retrieve the song to modify)

        # Check if the song belongs to the currently logged-in user
        if song_user_id != current_user.get_user_id():
            print("You are not the owner of this song. Access denied.")
            return

        # ... (rest of the code to modify the song)

    @classmethod
    def delete_song(cls):
        # Ensure the user is logged in before allowing access to this function.
        if not current_user.is_authenticated():
            print("You need to log in first.")
            return

        # ... (rest of the code to retrieve the song to delete)

        # Check if the song belongs to the currently logged-in user
        if song_user_id != current_user.get_user_id():
            print("You are not the owner of this song. Access denied.")
            return

        # ... (rest of the code to delete the song)

    # ... (existing code below)

