# Password Vault 1.0
Welcome to Password Vault 1.0 — your secure digital locker for passwords and secret notes! This tool offers tight security, password storage, random password generation, secret note storage, and syncing your data securely to your private GitHub repository.

## Features

- **Master Password**: Secure all your data with a single master password.

- **Password Storage**: Store your passwords securely using encryption that includes service, URL, username, notes.

- **Retrieve Passwords**: Access your stored Data. Or edit them.

- **Password Breach Check**: Check your password against known breaches using the Have I Been Pwned (HIBP) API.

- **Secret Notes**: Store secret notes that are encrypted and timestamped.

- **Random Password Generator**: Create complex passwords with just a click.

- **Security Features**: Optional self-destruction of the database after 5 failed login attempts.

- **GitHub Sync**: Backup your encrypted database to a private GitHub repository.

## Setup

### Prerequisites

- Python 3.6 or higher
- Git
- pip

### Installation

1. **Clone the Repository**:

    * Open a terminal or command prompt.
    * Clone the repository from GitHub:

    ```bash
    git clone https://github.com/yourusername/password-vault.git
    ```

    ```bash
    cd password-vault
    ```


2. **Install dependancies**
    ```python
    pip install -r requirements.txt
    ```

3. **Setting Up a Private GitHub Repository**
    - You’ll need to set up a private GitHub repository where the encrypted database will be stored.

    * Log in to GitHub and create a new private repository.
    * After creating the repository, initialize it locally by linking your local folder to the remote repository:
    
    
    ```bash
    git remote add origin https://github.com/yourusername/private-repo.git
    ```

    * Make your first commit to this private repo:

    ```bash
    git add .
    git commit -m "Initial commit for Password Vault"
    git push -u origin master
    ```

4. **Running the Application**
    - Run the main Python file:

        ```bash
        python main.py
        ```

    - On the first run, you'll be asked to set a master password. This master password will protect all your other passwords and secret notes.

    - You'll also have the option to enable the security feature that deletes the database after 5 failed login attempts.
    
5. **Edits You need to make**
    - Search for "Path to your local git" in the main.py and point in to yours.

    - Set the name of your database you wish to create. Search for "Path to your database file"