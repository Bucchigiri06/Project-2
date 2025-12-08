# ULTRA MODERN GUI - ADVANCED UI DESIGN WITH GRADIENT BACKGROUND, CARD UI, BIG BUTTONS, ICONS

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto_engine import encrypt_file, decrypt_file
import threading, time

# MAIN UI

def launch_gui():
    root = tk.Tk()
    root.title("Secure AES Encryption System - Premium Edition")
    root.geometry("900x560")
    root.resizable(False, False)

    # --- GRADIENT BACKGROUND ---
    canvas = tk.Canvas(root, width=900, height=560)
    canvas.pack(fill="both", expand=True)
    for i in range(560):
        color = f"#{int(30+i/3):02x}{int(30+i/3):02x}{int(30+i/3):02x}"
        canvas.create_line(0, i, 900, i, fill=color)

    # CARD CONTAINER
    card = tk.Frame(root, bg="#111111", bd=0, highlightbackground="#4fc3f7", highlightthickness=2)
    card.place(relx=0.5, rely=0.5, anchor="center", width=700, height=420)

    # --- SECTION HEADER ---
    title = tk.Label(card, text="🔐 AES256 Advanced File Security", font=("Segoe UI", 22, "bold"), fg="#4fc3f7", bg="#111111")
    title.pack(pady=20)

    selected_file = tk.StringVar()
    password = tk.StringVar()

    # --- FILE SELECT ---
    file_frame = tk.Frame(card, bg="#111111")
    file_frame.pack(pady=10)

    tk.Label(file_frame, text="Choose File:", fg="white", bg="#111111", font=("Segoe UI", 12)).grid(row=0, column=0, padx=10)
    entry = tk.Entry(file_frame, textvariable=selected_file, width=45, font=("Segoe UI", 11), bd=0, relief="flat")
    entry.grid(row=0, column=1, ipady=5)

    def browse():
        path = filedialog.askopenfilename()
        selected_file.set(path)

    browse_btn = tk.Button(file_frame, text="Browse", font=("Segoe UI", 10, "bold"), bg="#4fc3f7", fg="black", relief="flat", width=10, command=browse)
    browse_btn.grid(row=0, column=2, padx=10)

    # --- PASSWORD ---
    pass_frame = tk.Frame(card, bg="#111111")
    pass_frame.pack(pady=15)

    tk.Label(pass_frame, text="Password:", fg="white", bg="#111111", font=("Segoe UI", 12)).grid(row=0, column=0, padx=10)
    pass_entry = tk.Entry(pass_frame, textvariable=password, width=30, show="*", font=("Segoe UI", 11), bd=0, relief="flat")
    pass_entry.grid(row=0, column=1, ipady=5)

    def toggle_visible():
        pass_entry.config(show="" if pass_entry.cget("show") == "*" else "*")

    tk.Button(pass_frame, text="👁", bg="#4fc3f7", fg="black", relief="flat", width=4, command=toggle_visible).grid(row=0, column=2, padx=10)

    # --- PROGRESS BAR ---
    progress = ttk.Progressbar(card, length=500, mode='determinate')
    progress.pack(pady=15)

    def process(task):
        progress.start(10)
        time.sleep(1.8)
        progress.stop()
        task()
        progress['value'] = 0

    # --- ENCRYPT ---
    def encrypt_btn():
        if not selected_file.get() or not password.get():
            return messagebox.showerror("Error", "Please fill all fields")
        output = selected_file.get()+".enc"
        threading.Thread(target=lambda: process(lambda: (encrypt_file(password.get(), selected_file.get(), output), messagebox.showinfo("Done", output)))).start()

    # --- DECRYPT ---
    def decrypt_btn():
        if not selected_file.get().endswith('.enc'):
            return messagebox.showerror("Error", "Choose a .enc file only")
        output = selected_file.get().replace('.enc','_decrypted')
        threading.Thread(target=lambda: process(lambda: (decrypt_file(password.get(), selected_file.get(), output), messagebox.showinfo("Done", output)))).start()

    # BUTTON GROUP
    btn_frame = tk.Frame(card, bg="#111111")
    btn_frame.pack(pady=15)

    tk.Button(btn_frame, text="Encrypt File", font=("Segoe UI", 12), bg="#4fc3f7", fg="black", relief="flat", width=15, height=2, command=encrypt_btn).grid(row=0, column=0, padx=20)
    tk.Button(btn_frame, text="Decrypt File", font=("Segoe UI", 12), bg="#00e676", fg="black", relief="flat", width=15, height=2, command=decrypt_btn).grid(row=0, column=1, padx=20)

    tk.Label(card, text="Premium Security • Designed by Suhas", font=("Segoe UI", 10), fg="#b0bec5", bg="#111111").pack(pady=10)

    root.mainloop()

if __name__ == '__main__':
    launch_gui()
