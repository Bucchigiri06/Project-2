import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto_engine import encrypt_file, decrypt_file

def launch_gui():
    root = tk.Tk()
    root.title("Secure File Storage System (AES Encryption)")
    root.geometry("520x300")
    root.resizable(False, False)

    selected_file = tk.StringVar()
    password = tk.StringVar()

    ttk.Label(root, text="Secure File Storage System", font=("Arial", 16)).pack(pady=10)

    def browse_file():
        file_path = filedialog.askopenfilename()
        selected_file.set(file_path)

    ttk.Entry(root, textvariable=selected_file, width=50).pack(padx=10)
    ttk.Button(root, text="Browse File", command=browse_file).pack(pady=8)

    ttk.Label(root, text="Enter Password:").pack(pady=3)
    ttk.Entry(root, textvariable=password, width=40, show="*").pack()

    def encrypt_action():
        if not selected_file.get() or not password.get():
            messagebox.showerror("Error", "Please select file and enter password")
            return
        output = selected_file.get() + ".enc"
        encrypt_file(password.get(), selected_file.get(), output)
        messagebox.showinfo("Success", f"Encrypted file saved as:\n{output}")

    def decrypt_action():
        if not selected_file.get() or not password.get():
            messagebox.showerror("Error", "Please select file and enter password")
            return
        if not selected_file.get().endswith(".enc"):
            messagebox.showerror("Error", "Please select a .enc encrypted file")
            return
        output = selected_file.get().replace(".enc", "_decrypted")
        decrypt_file(password.get(), selected_file.get(), output)
        messagebox.showinfo("Success", f"Decrypted file saved as:\n{output}")

    ttk.Button(root, text="Encrypt File", command=encrypt_action).pack(pady=10)
    ttk.Button(root, text="Decrypt File", command=decrypt_action).pack()

    root.mainloop()
