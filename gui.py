import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from crypto_engine import encrypt_file, decrypt_file
import threading

def launch_gui():
    root = tk.Tk()
    root.title("Secure File Storage System")
    root.geometry("720x420")
    root.resizable(False, False)
    root.configure(bg="#0f172a")  # dark slate background

    # ================= STYLES =================
    style = ttk.Style()
    style.theme_use("default")

    style.configure(
        "TButton",
        font=("Segoe UI", 11),
        padding=10
    )
    style.configure(
        "TEntry",
        font=("Segoe UI", 11),
        padding=6
    )
    style.configure(
        "TLabel",
        background="#0f172a",
        foreground="#e5e7eb",
        font=("Segoe UI", 11)
    )
    style.configure(
        "Header.TLabel",
        font=("Segoe UI", 20, "bold"),
        foreground="#38bdf8"
    )
    style.configure(
        "SubHeader.TLabel",
        font=("Segoe UI", 10),
        foreground="#94a3b8"
    )

    # ================= HEADER =================
    ttk.Label(
        root,
        text="🔐 Secure File Storage System",
        style="Header.TLabel"
    ).pack(pady=(20, 5))

    ttk.Label(
        root,
        text="AES-256 Encryption with Integrity Verification",
        style="SubHeader.TLabel"
    ).pack(pady=(0, 20))

    # ================= CARD =================
    card = tk.Frame(
        root,
        bg="#020617",
        highlightbackground="#38bdf8",
        highlightthickness=1
    )
    card.pack(padx=40, pady=10, fill="both", expand=True)

    file_path = tk.StringVar()
    password = tk.StringVar()
    status = tk.StringVar(value="Idle")

    # ================= FILE INPUT =================
    ttk.Label(card, text="Select File").pack(anchor="w", padx=25, pady=(25, 5))
    file_frame = tk.Frame(card, bg="#020617")
    file_frame.pack(fill="x", padx=25)

    file_entry = ttk.Entry(file_frame, textvariable=file_path)
    file_entry.pack(side="left", fill="x", expand=True)

    def browse():
        file_path.set(filedialog.askopenfilename())

    ttk.Button(file_frame, text="Browse", width=10, command=browse).pack(side="left", padx=10)

    # ================= PASSWORD =================
    ttk.Label(card, text="Encryption Password").pack(anchor="w", padx=25, pady=(20, 5))
    ttk.Entry(card, textvariable=password, show="*").pack(fill="x", padx=25)

    # ================= PROGRESS =================
    progress = ttk.Progressbar(card, mode="indeterminate")
    progress.pack(fill="x", padx=25, pady=20)

    # ================= ACTIONS =================
    btn_frame = tk.Frame(card, bg="#020617")
    btn_frame.pack(pady=10)

    def encrypt_action():
        if not file_path.get() or not password.get():
            return messagebox.showerror("Error", "Please select a file and enter password")

        def task():
            try:
                progress.start(10)
                status.set("Encrypting file...")
                out = file_path.get() + ".enc"
                encrypt_file(password.get(), file_path.get(), out)
                status.set("Encryption completed successfully ✔")
                messagebox.showinfo("Success", f"Encrypted File:\n{out}")
            finally:
                progress.stop()

        threading.Thread(target=task, daemon=True).start()

    def decrypt_action():
        if not file_path.get().endswith(".enc"):
            return messagebox.showerror("Error", "Please select a .enc file")

        def task():
            try:
                progress.start(10)
                status.set("Decrypting and verifying integrity...")
                out = file_path.get().replace(".enc", "_decrypted")
                meta = decrypt_file(password.get(), file_path.get(), out)
                status.set("Decryption successful ✔")
                messagebox.showinfo(
                    "Success",
                    f"File Restored Successfully\n\n"
                    f"Original Name: {meta['original_name']}\n"
                    f"Timestamp: {meta['timestamp']}"
                )
            except Exception as e:
                status.set("Integrity verification failed ❌")
                messagebox.showerror("Security Alert", str(e))
            finally:
                progress.stop()

        threading.Thread(target=task, daemon=True).start()

    ttk.Button(btn_frame, text="Encrypt File", width=18, command=encrypt_action).grid(row=0, column=0, padx=20)
    ttk.Button(btn_frame, text="Decrypt File", width=18, command=decrypt_action).grid(row=0, column=1, padx=20)

    # ================= STATUS BAR =================
    status_bar = tk.Label(
        root,
        textvariable=status,
        bg="#020617",
        fg="#22c55e",
        font=("Segoe UI", 10),
        anchor="w",
        padx=10
    )
    status_bar.pack(fill="x", side="bottom")

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
