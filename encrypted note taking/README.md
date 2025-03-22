# Encrypted Notes Manager

A simple desktop application for creating, opening, editing, and deleting encrypted notes.

## Features

- Create new encrypted notes with a title and content
- Encrypt notes with a password using AES-GCM encryption
- Open existing notes by providing the correct password
- Delete notes when they're no longer needed
- Simple and clean tkinter-based GUI
- Strong encryption using the cryptography library

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- cryptography library

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install cryptography
```

## Usage

Run the application:

```bash
python encrypted_notes_manager.py
```

### Creating a New Note

1. Click on "File" > "New Note" or start the application
2. Enter a title for your note
3. Write your note content
4. Click "File" > "Save Note"
5. Enter and confirm a password to encrypt your note

### Opening an Existing Note

1. Click on "File" > "Open Note"
2. Select your note file (.enote)
3. Enter the password used to encrypt the note

### Deleting a Note

1. Open the note you want to delete
2. Click on "File" > "Delete Note"
3. Confirm the deletion

## Security

- Notes are encrypted using AES-GCM, a strong authenticated encryption algorithm
- Password-based key derivation uses PBKDF2 with 100,000 iterations
- Each note has its own unique salt and nonce for encryption
- Passwords are never stored, only used for encryption/decryption