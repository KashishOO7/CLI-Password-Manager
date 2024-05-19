import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from git import Repo
import secrets
import getpass
import datetime, time

def encrypt_data(data, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    password = password.encode() if isinstance(password, str) else password
    key = kdf.derive(password)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encrypted_data

def decrypt_data(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    password = password.encode() if isinstance(password, str) else password
    key = kdf.derive(password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[32:]) + decryptor.finalize()
    return decrypted_data

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()-_" for char in password):
        return False
    return True

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            service_url TEXT,
            username TEXT,
            encrypted_data BLOB NOT NULL,
            notes TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            master_password BLOB NOT NULL,
            security_enabled INTEGER NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS secret_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_note BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
        )
    ''')
    conn.commit()
    conn.close()

def store_password(db_path, service, service_url, username, encrypted_data, notes):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        INSERT INTO passwords (service, service_url, username, encrypted_data, notes) 
        VALUES (?, ?, ?, ?, ?)''', (service, service_url, username, encrypted_data, notes))
    conn.commit()
    conn.close()

def retrieve_passwords(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT service, service_url, username, encrypted_data, notes FROM passwords')
    rows = c.fetchall()
    conn.close()
    return rows

def set_master_password(db_path, master_password, security_enabled):
    master_password = master_password.encode()
    encrypted_master_password = encrypt_data(master_password, master_password)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM master_password')
        c.execute('INSERT INTO master_password (id, master_password, security_enabled) VALUES (1, ?, ?)',
                  (encrypted_master_password, security_enabled))
        conn.commit()
    except sqlite3.Error as e:
        print("Error occurred:", e)
    finally:
        conn.close()

def get_master_password(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute('SELECT master_password, security_enabled FROM master_password WHERE id = 1')
        result = c.fetchone()
        return result if result else (None, None)
    except sqlite3.Error as e:
        print("Error occurred:", e)
        return None, None
    finally:
        conn.close()

def update_password(db_path, service, new_service=None, new_url=None, new_username=None, new_password=None, new_notes=None):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM passwords WHERE service = ?', (service,))
    result = c.fetchone()

    if not result:
        print("Service not found.")
        conn.close()
        return
    
    update_query = "UPDATE passwords SET "
    update_values = []
    if new_service:
        update_query += "service = ?, "
        update_values.append(new_service)
    if new_url:
        update_query += "service_url = ?, "
        update_values.append(new_url)
    if new_username:
        update_query += "username = ?, "
        update_values.append(new_username)
    if new_password:
        encrypted_data = encrypt_data(new_password.encode(), get_master_password(db_path)[0])
        update_query += "encrypted_data = ?, "
        update_values.append(encrypted_data)
    if new_notes:
        update_query += "notes = ?, "
        update_values.append(new_notes)
    
    update_query = update_query.rstrip(', ')
    update_query += " WHERE service = ?"
    update_values.append(service)

    c.execute(update_query, update_values)
    conn.commit()
    conn.close()
    print(f"Details for {service} updated successfully.")

def store_secret_note(db_path, note, master_password):
    encrypted_note = encrypt_data(note.encode(), master_password)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('INSERT INTO secret_notes (encrypted_note) VALUES (?)', (encrypted_note,))
    conn.commit()
    conn.close()

def retrieve_secret_notes(db_path, master_password):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT id, encrypted_note, created_at, updated_at FROM secret_notes')
    rows = c.fetchall()
    conn.close()
    
    notes = []
    for row in rows:
        note_id, encrypted_note, created_at, updated_at = row
        decrypted_note = decrypt_data(encrypted_note, master_password).decode()
        notes.append((note_id, decrypted_note, created_at, updated_at))
    return notes

def update_secret_note(db_path, note_id, new_note, master_password):
    encrypted_note = encrypt_data(new_note.encode(), master_password)
    updated_at = datetime.datetime.now()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        UPDATE secret_notes 
        SET encrypted_note = ?, updated_at = ? 
        WHERE id = ?
    ''', (encrypted_note, updated_at, note_id))
    conn.commit()
    conn.close()

def sync_to_github(repo_path, db_path):
    repo = Repo(repo_path)
    repo.git.add(db_path)
    repo.index.commit("Update encrypted password database")
    origin = repo.remote(name='origin')
    origin.push()

def generate_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def authenticate_master_password(stored_password, input_password):
    try:
        decrypted_master_password = decrypt_data(stored_password, input_password.encode())
        return decrypted_master_password == input_password.encode()
    except Exception:
        return False

def main():
    db_path = 'MyDatabase.db' # Path to your database file
    repo_path = 'D:/codes/Projects/password_manager' # Path to your local git repository

    init_db(db_path)

    master_password, security_enabled = get_master_password(db_path)
    attempts = 5

    if master_password:
        while attempts > 0:
            input_password = getpass.getpass("Enter your master password: ")
            if authenticate_master_password(master_password, input_password):
                break
            else:
                attempts -= 1
                print(f"Incorrect master password. {attempts} attempts left.")
                if attempts == 0 and security_enabled:
                    os.remove(db_path)
                    print("""Too many failed attempts. The database has been deleted.
                          Don't pretend to be someone you're not. Or Try again, lol you can't :)
                          """)
                    return
                elif attempts == 0:
                    print("""Too many failed attempts.
                          Don't pretend to be someone you're not. Or Try again!
                          """)
                    return
    else:
        print("----- Welcome to your local Vault 1.0 -----")
        print("\n")
        input_password = getpass.getpass("Set a new master password: ")
        if is_strong_password(input_password):
            print("Password is strong enough. Good to go.")
            confirm_password = getpass.getpass("Confirm your master password: ")
            if input_password != confirm_password:
                print("Passwords do not match. Now, I know why you wanna use a password manager.")
                return
            security_choice = input("Enable security feature (delete database after 5 failed attempts)? (y/n): ").lower()
            security_enabled = 1 if security_choice == 'y' else 0
            set_master_password(db_path, input_password, security_enabled)
            print("Master password set! Atleast you're a master of something now. Be Happy!")
        else:
            print("Password is weak. Try again. Or Just read the Manual!")
            exit()

    while True:
        print("\nOptions:")
        print("1. Add a new password")
        print("2. Retrieve passwords")
        print("3. Generate a random password")
        print("4. Sync database to GitHub")
        print("5. Help")
        print("6. Edit Existing Password")
        print("7. Add Secret Note")
        print("8. Retrieve Secret Notes")
        print("9. Edit Secret Note")
        print("10. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            service_url = input("Enter the service URL (or leave empty): ")
            username = input("Enter the username (or leave empty): ")
            password = getpass.getpass("Enter the password: ")
            notes = input("Enter any notes (or leave empty): ")
            encrypted_data = encrypt_data(password.encode(), input_password)
            store_password(db_path, service, service_url, username, encrypted_data, notes)
            print("\nCredentials for {} added successfully. No need to eat almonds anymore.".format(service))

        elif choice == '2':
            rows = retrieve_passwords(db_path)
            for service, service_url, username, encrypted_data, notes in rows:
                decrypted_data = decrypt_data(encrypted_data, input_password).decode()
                print(f"Service: {service}, URL: {service_url}, Username: {username}, Password: {decrypted_data}, Notes: {notes}")

        elif choice == '3':
            try:
                length = int(input("Enter the length of the password: "))
                password = generate_password(length)
                print(f"Generated Password: {password}")
            except ValueError:
                print("OH! You need to enter numeric value. Try again. Or Just read the Manual!")
        
        elif choice == '4':
            sync_to_github(repo_path, db_path)
            print("Database synced with GitHub. Don't get locked out of your GitHub, bro! I'd be helpless then.")
        
        elif choice == '5':
            print("""
----- Welcome to your local Vault 1.0 User Manual -----

This tool helps you securely store, retrieve, and manage your passwords with added security features. Here's how to use it:

1. Setup Master Password:
    - On first run, you will be prompted to set a master password. This master password secures all your other passwords.
    - You can also enable a security feature that will self-destruct the database after 5 failed login attempts. Full Tight Security!

2. Main Menu Options:
    - 1. Add a New Password:
        - Enter the service name (e.g., Gmail, Tinder, etc).
        - Optionally, enter the service URL (e.g., www.gmail.com).
        - Enter the username associated with the service.
        - Enter the password you wish to store. Don't blame us later if you yourself stored the wrong password.
        - Optionally, add any notes (e.g., "This account is for...").
    - 2. Retrieve Passwords:
        - View all stored passwords along with their associated service name, URL, username, and notes.
    - 3. Generate a Random Password:
        - Generate a secure, random password of the specified length.
    - 4. Sync Database to GitHub:
        - Backup your encrypted password database to your GitHub repository.
        - How this works? Refer to the readme of this code.
    - 5. Help:
        - View this help menu.
    - 6. Edit Existing Password:
        - Update details of an existing password entry.
    - 7. Add Secret Note:
        - Add a secret note to the database with optional timestamps for creation and last update.
    - 8. Edit Secret Note:
        - Edit an existing secret note.
    - 9. Retrieve Secret Notes:
        - View all stored secret notes along with their timestamps.
    - 10. Exit:
        - Exit the application safely, quietly, and nicely.

Security Feature:
   - If enabled, entering the wrong master password 5 times will delete your database. This ensures maximum security. And this is all I can offer for now

Quick Tips:
- Passwords: Keep them long and complex! Strong password policy is already implemented, you dont't have any other option.
- Service URL: Helps you quickly identify the service.
- Username: Useful if you have multiple accounts on the same service.
- Notes: Add any extra details like recovery answers or security hints.
              """)
        
        elif choice == '6':
            service = input("Enter the service name to update: ")
            new_service = input("Enter the new service name (or press enter to skip): ")
            new_url = input("Enter the new URL (or press enter to skip): ")
            new_username = input("Enter the new username (or press enter to skip): ")
            new_password = input("Enter the new password (or press enter to skip): ")
            new_notes = input("Enter the new notes (or press enter to skip): ")
            update_password(db_path, service, new_service, new_url, new_username, new_password, new_notes)
        
        elif choice == '7':
            note = input("Enter the secret note: ")
            store_secret_note(db_path, note, input_password)

        elif choice == '8':
            notes = retrieve_secret_notes(db_path, input_password)
            for note in notes:
                print(note)
        
        elif choice == '9':
            note_id = int(input("Enter the ID of the note to edit: "))
            new_note = input("Enter the new note: ")
            update_secret_note(db_path, note_id, new_note, input_password)
            print(f"Note ID {note_id} has been updated.")

        elif choice == '10':
            print("Exiting the application.")
            time.sleep(2)
            print("Goodbye! Have a great day ahead.")
            break

        else:
            print("Invalid choice. What the heck are you even trying to do.")

if __name__ == '__main__':
    main()
