import os
import tkinter as tk
from tkinter import filedialog, messagebox
from modules.aes import encrypt_file_aes, decrypt_file_aes
from modules.chacha import encrypt_file_chacha, decrypt_file_chacha
from modules.rsa import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa
from modules.utils import extract_metadata

class EncryptionToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("400x400")

        self.main_menu()

    def main_menu(self):
        """Create the main menu for selecting Encrypt or Decrypt."""
        self.clear_frame()

        tk.Label(self.root, text="Select an action:", font=("Arial", 14)).pack(pady=20)

        encrypt_btn = tk.Button(self.root, text="Encrypt a File", command=self.show_encrypt_menu, width=20)
        encrypt_btn.pack(pady=10)

        decrypt_btn = tk.Button(self.root, text="Decrypt a File", command=self.show_decrypt_menu, width=20)
        decrypt_btn.pack(pady=10)

        generate_keys_btn = tk.Button(self.root, text="Generate RSA Keys", command=self.generate_keys, width=20)
        generate_keys_btn.pack(pady=10)

    def show_encrypt_menu(self):
        """Show encryption options (AES-256, ChaCha20, RSA)."""
        self.clear_frame()
        tk.Label(self.root, text="Enter Password (Not needed for RSA):", font=("Arial", 12)).pack(pady=10)

        self.password_entry = tk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        tk.Label(self.root, text="Select Encryption Algorithm:", font=("Arial", 12)).pack(pady=10)

        self.encryption_algorithm = tk.StringVar(value="AES")
        tk.Radiobutton(self.root, text="AES-256", variable=self.encryption_algorithm, value="AES").pack()
        tk.Radiobutton(self.root, text="ChaCha20", variable=self.encryption_algorithm, value="ChaCha20").pack()
        tk.Radiobutton(self.root, text="RSA", variable=self.encryption_algorithm, value="RSA").pack()

        tk.Button(self.root, text="Select File", command=self.encrypt_file).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.main_menu).pack(pady=10)

    def show_decrypt_menu(self):
        """Show decryption options, ensuring password entry is present."""
        self.clear_frame()

        tk.Label(self.root, text="Enter Password (Not needed for RSA):", font=("Arial", 12)).pack(pady=10)

        self.password_entry = tk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.root, text="Select File", command=self.decrypt_file).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.main_menu).pack(pady=10)

    def generate_keys(self):
        """Generate RSA keys and show save location in messagebox."""
        private_key, public_key = generate_rsa_keys()
        messagebox.showinfo(
            "RSA Key Generation",
            f"RSA Keys Generated!\n\n"
            f"🔑 Private Key: {os.path.abspath(private_key)}\n"
            f"🔑 Public Key: {os.path.abspath(public_key)}"
        )

    def encrypt_file(self):
        """Encrypt a file using the selected algorithm."""
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        algorithm = self.encryption_algorithm.get()

        if algorithm == "RSA":
            public_key_path = filedialog.askopenfilename(title="Select RSA Public Key File")
            if not public_key_path:
                messagebox.showerror("Error", "Please select a valid RSA public key file.")
                return

            encrypted_file = encrypt_file_rsa(file_path, public_key_path)

        else:
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password")
                return

            if algorithm == "AES":
                encrypted_file = encrypt_file_aes(file_path, password)
            else:
                encrypted_file = encrypt_file_chacha(file_path, password)

        messagebox.showinfo("Encryption", f"File encrypted successfully!\nSaved as: {encrypted_file}")

    def decrypt_file(self):
        """Decrypt a file, auto-detecting or manually selecting the encryption algorithm."""
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        password = self.password_entry.get()  # Ensure password entry is present

        # Auto-detect algorithm
        algorithm, _ = extract_metadata(file_path)

        if not algorithm:
            # Ask user to manually select the algorithm if auto-detection fails
            algorithm = self.ask_manual_algorithm()
            if not algorithm:
                messagebox.showerror("Error", "No algorithm selected. Decryption aborted.")
                return

        # Handle RSA decryption (manual private key selection, no password required)
        if algorithm == "RSA":
            private_key_path = filedialog.askopenfilename(title="Select RSA Private Key File")
            if not private_key_path:
                messagebox.showerror("Error", "Please select a valid RSA private key file.")
                return
            decrypt_func = lambda f, _: decrypt_file_rsa(f, private_key_path)  # RSA ignores password
            password = None  

        # Handle AES & ChaCha20 decryption
        elif algorithm == "AES":
            decrypt_func = decrypt_file_aes
        elif algorithm == "ChaCha20":
            decrypt_func = decrypt_file_chacha
        else:
            messagebox.showerror("Error", "Invalid algorithm selected.")
            return

        # Ensure password is provided for AES/ChaCha20
        if not password and algorithm in ["AES", "ChaCha20"]:
            messagebox.showerror("Error", "Please enter a password")
            return

        # Attempt decryption
        try:
            decrypted_file = decrypt_func(file_path, password)
            messagebox.showinfo("Decryption", f"File decrypted successfully!\nSaved as: {decrypted_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def ask_manual_algorithm(self):
        """Prompt user to manually select an encryption algorithm if auto-detection fails."""
        algorithm_window = tk.Toplevel(self.root)
        algorithm_window.title("Select Algorithm")
        algorithm_window.geometry("300x200")

        tk.Label(algorithm_window, text="Select the encryption algorithm:", font=("Arial", 12)).pack(pady=10)

        selected_algorithm = tk.StringVar(value="AES")  # Default selection

        tk.Radiobutton(algorithm_window, text="AES-256", variable=selected_algorithm, value="AES").pack()
        tk.Radiobutton(algorithm_window, text="ChaCha20", variable=selected_algorithm, value="ChaCha20").pack()
        tk.Radiobutton(algorithm_window, text="RSA", variable=selected_algorithm, value="RSA").pack()

        def confirm_selection():
            algorithm_window.destroy()

        tk.Button(algorithm_window, text="Confirm", command=confirm_selection).pack(pady=10)

        algorithm_window.wait_window()  # Wait for user input
        return selected_algorithm.get()

    def clear_frame(self):
        """Clear the window for switching between menus."""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionToolGUI(root)
    root.mainloop()
