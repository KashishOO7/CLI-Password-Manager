from libraries import *

console = Console()

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def is_password_breached(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_password[:5]
    try:
        response = requests.get(f"{HIBP_API_URL}{prefix}")
        response.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[bold red]Error querying HIBP API: {str(e)}[/bold red]")
        return False
    suffix = sha1_password[5:]
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            console.print(f"[bold red]Password has been breached {count} times![/bold red]")
            return True
    return False

def check_master_password(master_password):
    if is_password_breached(master_password):
        print("This master password has been breached! Please choose another password.")
        return False
    else:
        print("Master password is safe.")
        return True

def display_title():
    title = Text("Password Vault 1.0", style="bold magenta")
    subtitle = Text("Your Secure Digital Locker", style="italic cyan")
    console.print(title)
    console.print(subtitle)

def display_menu():
    menu = Table(show_header=False, expand=False, border_style="bold blue")
    menu.add_column("Option", style="cyan", justify="right")
    menu.add_column("Description", style="yellow")
    menu.add_row("1", "Add a new password")
    menu.add_row("2", "Retrieve passwords")
    menu.add_row("3", "Generate a random password")
    menu.add_row("4", "Sync database to GitHub")
    menu.add_row("5", "Help")
    menu.add_row("6", "Edit Existing Password")
    menu.add_row("7", "Add Secret Note")
    menu.add_row("8", "Retrieve Secret Notes")
    menu.add_row("9", "Edit Secret Note")
    menu.add_row("10", "Exit")
    console.print(Panel(menu, title="[bold]Menu Options[/bold]", border_style="bold blue", expand=False))

def access_granted_sound():
    winsound.Beep(1000, 500)

def access_denied_sound():
    path1 = 'media/warning.mp3'
    playsound(path1)

def prompt_sound():
    winsound.Beep(800, 300)

def show_help():
    help_text = """
# **----- Welcome to Your Local Vault 1.0 User Manual -----**

## **1. Setup Master Password:**
- Initially, you will be prompted to set a master password. This master password secures all your other passwords.
- Optionally, enable a security feature that will self-destruct the database after 5 failed login attempts. **Full Tight Security!**

## **2. Main Menu Options:**
- **1. Add a New Password:**
    - Enter the service name (e.g., Gmail, Tinder, etc.).
    - Optionally, enter the service URL (e.g., www.gmail.com).
    - Enter the username associated with the service.
    - Enter the password you wish to store. _Don't blame us later if you yourself stored the wrong password._
    - Optionally, add any notes (e.g., "This account is for...").

- **2. Retrieve Passwords:**
    - View all stored passwords along with their associated service name, URL, username, and notes.

- **3. Generate a Random Password:**
    - Generate a secure, random password of the specified length.

- **4. Sync Database to GitHub:**
    - Backup your encrypted password database to your GitHub repository. How this works? Refer to the readme of this code.

- **5. Help:**
    - View this help menu.

- **6. Edit Existing Password:**
    - Update details of an existing password entry.

- **7. Add Secret Note:**
    - Add a secret note to the database. _Because we know you have secrets._

- **8. Edit Secret Note:**
    - Edit an existing secret note.

- **9. Retrieve Secret Notes:**
    - View all stored secret notes along with their timestamps of creation and last update.

- **10. Exit:**
    - Exit the application safely and quietly without any fuss.

## **Security Feature:**
- If enabled, entering the wrong master password **5 times** will delete your database. This ensures maximum security. _And this is all I can offer for now._

## **Quick Tips:**
- **Passwords:** Keep them long and complex! Strong password policy is already implemented, so you have no other option.
- **Service URL:** Helps you quickly identify the service.
- **Username:** Useful if you have multiple accounts on the same service.
- **Notes:** Add any extra details like recovery answers or security hints.
    """
    markdown_help = Markdown(help_text)
    help_panel = Panel(
        Align.center(markdown_help), title="[bold blue]Vault 1.0 User Manual[/bold blue]", border_style="bold green"
    )
    console.print(help_panel)

def display_password_policy():
    policy = """
    Password Policy:
    - More than 8 characters
    - At least 1 uppercase letter (A-Z)
    - At least 1 lowercase letter (a-z)
    - At least 1 digit (0-9)
    - At least 1 special character (!@#$%^&*()_+-=)
    """
    console.print(Panel(policy, title="Password Policy", style="bold cyan"))


def display_passwords(rows, input_password):
    table = Table(title="Stored Passwords")
    table.add_column("Service", style="cyan")
    table.add_column("URL", style="magenta")
    table.add_column("Username", style="green")
    table.add_column("Password", style="red")
    table.add_column("Notes", style="yellow")

    for service, service_url, username, encrypted_data, notes in rows:
        try:
            decrypted_data = decrypt_data(encrypted_data, input_password).decode('utf-8')
        except UnicodeDecodeError:
            decrypted_data = "[Error: Unable to decode password]"
        except Exception as e:
            decrypted_data = f"[Error: {str(e)}]"
        table.add_row(service, service_url, username, decrypted_data, notes)

    console.print(table)

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
    """
    Initializes the SQLite database if it does not exist.
    Creates tables for storing passwords, master password, secret notes, etc.
    """
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
        console.print(f"[bold green]Master password set successfully![/bold green]")
    except sqlite3.Error as e:
        console.print(f"[bold red]Error Occurred: {e}[/bold red]")
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
        console.print(f"[bold red]Error Occurred: {e}[/bold red]")
        return None, None
    finally:
        conn.close()

def update_password(db_path, service, new_service=None, new_url=None, new_username=None, new_password=None, new_notes=None, master_password=None):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM passwords WHERE service = ?', (service,))
    result = c.fetchone()

    if not result:
        console.print(f"[bold red]Service: {service} NOT FOUND![/bold red]")
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
        try:
            encrypted_data = encrypt_data(new_password.encode(), master_password)
            update_query += "encrypted_data = ?, "
            update_values.append(encrypted_data)
        except Exception as e:
            console.print(f"[bold red]Error encrypting password: {str(e)}[/bold red]")
            conn.close()
            return
    if new_notes:
        update_query += "notes = ?, "
        update_values.append(new_notes)
    
    update_query = update_query.rstrip(', ')
    update_query += " WHERE service = ?"
    update_values.append(service)

    c.execute(update_query, update_values)
    conn.commit()
    conn.close()
    console.print(f"[bold green]Details for {service} updated successfully.[/bold green]")

def store_secret_note(db_path, note, master_password):
    encrypted_note = encrypt_data(note.encode(), master_password)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('INSERT INTO secret_notes (encrypted_note) VALUES (?)', (encrypted_note,))
    conn.commit()
    conn.close()
    console.print(f"[bold green]Secret note added successfully![/bold green]")

def retrieve_secret_notes(db_path, master_password):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT id, encrypted_note, created_at, updated_at FROM secret_notes')
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("[bold yellow]No secret notes found.[/bold yellow]")
        return
    table = Table(title="Secret Notes")
    table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("Note", style="magenta")
    table.add_column("Created At", style="green")
    table.add_column("Updated At", style="yellow")

    for note_id, encrypted_note, created_at, updated_at in rows:
        decrypted_note = decrypt_data(encrypted_note, master_password).decode()
        table.add_row(str(note_id), decrypted_note, created_at, updated_at)

    console = Console()
    console.print(table)

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
    try:
        repo = Repo(repo_path)
        repo.git.add(db_path)
        repo.index.commit("Update encrypted password database")
        origin = repo.remote(name='origin')
        origin.push()
        console.print(f"[bold green]Database synced with GitHub. Don't get locked out of your GitHub, bro! I'd be helpless then[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error syncing with GitHub: {e}[/bold red]")

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
    db_path = 'MyDatabase.db'
    repo_path = 'path to your local repo folder'

    init_db(db_path)
    display_title()
    
    master_password, security_enabled = get_master_password(db_path)
    attempts = 5
    authenticated_master_password = None

    if master_password:
        while attempts > 0:
            prompt_sound()
            input_password = Prompt.ask("[bold blue]Please enter your master password to unlock the vault:[/bold blue]", password=True)
            
            if authenticate_master_password(master_password, input_password):
                authenticated_master_password = input_password
                access_granted_sound()
                console.print("[bold green]Access granted! Welcome back, Vault Guardian.[/bold green]")
                break
            else:
                attempts -= 1
                console.print(f"[bold red]Access denied! {attempts} attempts left.[/bold red]")
                if attempts == 0 and security_enabled:
                    os.remove(db_path)
                    console.print(Panel("Too many failed attempts. Vault has initiated self-destruction protocol", style="bold red"))
                    time.sleep(1)
                    access_denied_sound()
                    console.print("[bold red]WARNING! The vault has been purged. All contents have been destroyed.[/bold red]")

                    return
                elif attempts == 0:
                    access_denied_sound()
                    console.print("[bold red]Access denied. The following incident has been logged.[/bold red]")
                    return
    else:
        console.print(Panel("Welcome to your local Vault 1.0", style="bold green"))
        print("\n")
        display_password_policy()

        while True:
            input_password = Prompt.ask("Enter your master password", password=True)
            breached_password = is_password_breached(input_password)
            if breached_password:
                console.print("[bold red]This password has been found in a breach. Please choose a different password.[/bold red]")
                continue  

            if not is_strong_password(input_password):
                console.print("[bold red]Password is weak. Please try again with a stronger password.[/bold red]")
                continue

            console.print("[bold green]Password is strong enough and not breached. Good to go![/bold green]")
            confirm_password = Prompt.ask("Confirm your master password", password=True)

            if input_password != confirm_password:
                console.print("[bold red]Passwords do not match! Please try again[/bold red]")
                continue 

            security_choice = Confirm.ask("Enable security feature (delete database after 5 failed attempts)?")
            security_enabled = 1 if security_choice else 0
            set_master_password(db_path, input_password, security_enabled)
            authenticated_master_password = input_password
            console.print("[bold green]Master password set![/bold green]")
            break

    while True:
        display_menu()
        choice = Prompt.ask(
        "Enter your choice",
        choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"],
        default="10"
    )
        if choice == '1':
            service = Prompt.ask("Enter the service name")
            service_url = Prompt.ask("Enter the service URL (or leave empty): ")
            username = Prompt.ask("Enter the username (or leave empty): ")
            password = Prompt.ask("Enter the password: ", password=True)
            notes = Prompt.ask("Enter any notes (or leave empty): ")
            encrypted_data = encrypt_data(password.encode(), input_password)
            store_password(db_path, service, service_url, username, encrypted_data, notes)
            console.print(f"[bold green]Credentials for {service} added successfully. No need to eat almonds anymore.[/bold green]")

        elif choice == '2':
            rows = retrieve_passwords(db_path)
            display_passwords(rows, input_password)

        elif choice == '3':
            try:
                length = IntPrompt.ask("Enter the length of the password: ")
                password = generate_password(length)
                console.print(f"[bold green]Generated Password: {password}[/bold green]")
            except ValueError:
                console.print(f"[bold red]OH! You need to enter numeric value. Try again. Or Just read the Manual![/bold red]")
        
        elif choice == '4':
            sync_to_github(repo_path, db_path)

        elif choice == '5':
            show_help()

        elif choice == '6':
            service = Prompt.ask("Enter the service name to update")
            new_service = Prompt.ask("Enter the new service name (or press enter to skip)")
            new_url = Prompt.ask("Enter the new URL (or press enter to skip)")
            new_username = Prompt.ask("Enter the new username (or press enter to skip)")
            new_password = Prompt.ask("Enter the new password (or press enter to skip)", password=True)
            new_notes = Prompt.ask("Enter the new notes (or press enter to skip)")
            update_password(db_path, service, new_service, new_url, new_username, new_password, new_notes, authenticated_master_password)        
        
        elif choice == '7':
            note = Prompt.ask("Enter the secret note: ")
            store_secret_note(db_path, note, input_password)

        elif choice == '8':
            notes = retrieve_secret_notes(db_path, input_password)

        elif choice == '9':
            note_id = None
            while note_id is None:
                try:
                    note_id = IntPrompt.ask("Enter the ID of the note to edit")
                except ValueError:
                    console.print("[bold red]Invalid input. Please enter a numeric ID.[/bold red]")
            new_note = Prompt.ask("Enter the new note")
            try:
                update_secret_note(db_path, note_id, new_note, input_password)
                console.print(f"[bold green]Note ID {note_id} has been updated.[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Error updating note: {str(e)}[/bold red]")
        
        elif choice == "10":
            console.print("[bold yellow]Exiting the application.[/bold yellow]")
            time.sleep(1)
            console.print(Panel("Goodbye! Have a great day ahead.", style="bold green"))
            break

        else:
            console.print("[bold red]Invalid choice. What the heck are you even trying to do.[/bold red]")

if __name__ == '__main__':
    main()

# Run this code and see the magic
# Built by Kashish Charaya :)