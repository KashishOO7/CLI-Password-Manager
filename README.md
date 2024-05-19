# Password-manager with encrypted database that supports remote sync via GitHub and Git

# Local Vault 1.0

Local Vault 1.0 is a secure password manager that helps you store, retrieve, and manage your passwords locally. It has encrypted database, a master password for added security, and an optional self-destruct mechanism after multiple failed attempts.

You can customize and add more features as you'd like. Feel free to contribute and provide feedback.

## Features

- **Master Password**: Secure all your data with a single master password.
- **Add Passwords**: Store service credentials securely.
- **Retrieve Passwords**: Access your stored passwords. Or edit them.
- **Generate Random Passwords**: Create strong, random passwords.
- **Sync to GitHub**: Backup your encrypted database to a GitHub repository using git.
- **Secret Notes**: Store and manage encrypted secret notes with timestamps.

## Setup

### Prerequisites

- Python 3.6 or higher
- Git
- SQLite3
- GitHub account with a private repository
- Will to learn and make this code better.

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/KashishOO7/CLI-Password-Manager.git
   cd local-vault
   ```
   
2. **Install dependancies**
    ```python
        pip install -r requirements.txt
    ```

3. **Before running the Program**
    - 

  **GitHub Sync Setup**
 - Create a New Private Repository on GitHub:
 - Set Up Local Repository:

    git init
    git remote add origin https://github.com/your-username/local-vault.git # Change this to your private repo URL

    Commit and Push Initial Changes:

    git add .
    git commit -m "Initial commit"
    git push -u origin master

    If you face any error while pushing or unable to see result reflected on your repo then, you might need to mess around your repo settings a little. 

    Change default branch from your repo settings, if not same.

4. Search for "Path to your local git" in the main.py and set it.

5. Set the name of your database you wish to create. Search for "Path to your database file"
