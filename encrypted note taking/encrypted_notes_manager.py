import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import json
import os
from pathlib import Path
import base64
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptedNotesManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Notes Manager")
        self.root.geometry("800x600")
        
        # Set notes directory
        self.notes_dir = Path.home() / "EncryptedNotes"
        self.notes_dir.mkdir(exist_ok=True)
        
        # Current note state
        self.current_note = {
            "title": "",
            "content": "",
            "filepath": None
        }
        
        self.setup_ui()
    
    def setup_ui(self):
        # Menu bar
        menubar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Note", command=self.new_note)
        file_menu.add_command(label="Open Note", command=self.open_note)
        file_menu.add_command(label="Save Note", command=self.save_note)
        file_menu.add_separator()
        file_menu.add_command(label="Delete Note", command=self.delete_note)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)
        
        # Title entry
        title_frame = tk.Frame(self.root, pady=5)
        title_frame.pack(fill=tk.X)
        
        tk.Label(title_frame, text="Title:").pack(side=tk.LEFT, padx=5)
        self.title_entry = tk.Entry(title_frame)
        self.title_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Text area for note content
        self.content_text = tk.Text(self.root, wrap=tk.WORD)
        self.content_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def derive_key(self, password, salt):
        """Derive encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for AES-256
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, password):
        """Encrypt data using AES-GCM"""
        # Generate salt and nonce
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        # Derive key from password and salt
        key = self.derive_key(password, salt)
        
        # Encrypt data
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        
        # Combine salt, nonce, and ciphertext for storage
        encrypted_data = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using AES-GCM"""
        try:
            # Extract components
            salt = base64.b64decode(encrypted_data["salt"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            
            # Derive key from password and salt
            key = self.derive_key(password, salt)
            
            # Decrypt data
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode()
        except Exception as e:
            raise ValueError("Decryption failed. Incorrect password or corrupted file.") from e
    
    def new_note(self):
        """Create a new note"""
        if self.content_text.get("1.0", tk.END).strip():
            if not messagebox.askyesno("New Note", "Discard current note and create a new one?"):
                return
        
        self.current_note = {
            "title": "",
            "content": "",
            "filepath": None
        }
        
        self.title_entry.delete(0, tk.END)
        self.content_text.delete("1.0", tk.END)
        self.status_var.set("New note created")
    
    def open_note(self):
        """Open an existing encrypted note"""
        filepath = filedialog.askopenfilename(
            initialdir=self.notes_dir,
            title="Open Encrypted Note",
            filetypes=(("Encrypted Notes", "*.enote"), ("All files", "*.*"))
        )
        
        if not filepath:
            return
            
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not password:
            return
            
        try:
            with open(filepath, 'r') as f:
                note_data = json.load(f)
                
            # Decrypt note content
            decrypted_content = self.decrypt_data(note_data["encrypted_content"], password)
            
            # Update UI
            self.title_entry.delete(0, tk.END)
            self.title_entry.insert(0, note_data["title"])
            
            self.content_text.delete("1.0", tk.END)
            self.content_text.insert("1.0", decrypted_content)
            
            # Update current note info
            self.current_note = {
                "title": note_data["title"],
                "content": decrypted_content,
                "filepath": filepath
            }
            
            self.status_var.set(f"Opened note: {note_data['title']}")
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open note: {str(e)}")
    
    def save_note(self):
        """Save the current note"""
        title = self.title_entry.get().strip()
        content = self.content_text.get("1.0", tk.END).strip()
        
        if not title:
            messagebox.showerror("Error", "Please enter a title for the note")
            return
            
        if not content:
            messagebox.showerror("Error", "Cannot save an empty note")
            return
            
        # For new notes or "Save As", get a password
        if not self.current_note["filepath"]:
            password = simpledialog.askstring("Password", "Enter password to encrypt note:", show="*")
            if not password:
                return
                
            password_confirm = simpledialog.askstring("Confirm Password", "Confirm password:", show="*")
            if password != password_confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            # Create filename from title (sanitized)
            safe_title = "".join(c for c in title if c.isalnum() or c in " _-").strip()
            safe_title = safe_title.replace(" ", "_")
            filepath = self.notes_dir / f"{safe_title}.enote"
            
            # Check if file already exists
            if filepath.exists():
                if not messagebox.askyesno("Overwrite", f"A note with the title '{title}' already exists. Overwrite?"):
                    return
        else:
            # Use existing filepath and prompt for password again
            filepath = self.current_note["filepath"]
            password = simpledialog.askstring("Password", "Enter password to encrypt note:", show="*")
            if not password:
                return
        
        try:
            # Encrypt the content
            encrypted_content = self.encrypt_data(content, password)
            
            # Prepare note data for storage
            note_data = {
                "title": title,
                "encrypted_content": encrypted_content
            }
            
            # Save to file
            with open(filepath, 'w') as f:
                json.dump(note_data, f, indent=2)
                
            # Update current note info
            self.current_note = {
                "title": title,
                "content": content,
                "filepath": str(filepath)
            }
            
            self.status_var.set(f"Saved note: {title}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save note: {str(e)}")
    
    def delete_note(self):
        """Delete the current note"""
        if not self.current_note["filepath"]:
            messagebox.showerror("Error", "No note is currently open")
            return
            
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the note '{self.current_note['title']}'?"):
            try:
                os.remove(self.current_note["filepath"])
                
                # Clear current note
                self.title_entry.delete(0, tk.END)
                self.content_text.delete("1.0", tk.END)
                
                self.current_note = {
                    "title": "",
                    "content": "",
                    "filepath": None
                }
                
                self.status_var.set("Note deleted")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete note: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedNotesManager(root)
    root.mainloop()