import socket
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.fernet import Fernet

# Use the same hardcoded encryption key as the server
ENCRYPTION_KEY = b'V1StGXR8_Z5jdHi6B-myT0F7kJJ0wLgF3g5CfaFBWdw='
cipher = Fernet(ENCRYPTION_KEY)

PORT = 5000


class ClientApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Chat App")
        master.geometry("700x600")

        # --- Login / Signup Screen ---
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(pady=20)

        # Server IP Field
        self.server_ip_label = tk.Label(self.login_frame, text="Server IP:")
        self.server_ip_label.pack(padx=5, pady=5)
        self.server_ip_entry = tk.Entry(self.login_frame)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.pack(padx=5, pady=5)

        self.username_label = tk.Label(self.login_frame, text="Username:")
        self.username_label.pack(padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(padx=5, pady=5)

        self.password_label = tk.Label(self.login_frame, text="Password:")
        self.password_label.pack(padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack(padx=5, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.pack(padx=5, pady=5)

        self.signup_button = tk.Button(self.login_frame, text="Sign Up", command=self.signup)
        self.signup_button.pack(padx=5, pady=5)

        # --- Chat Screen (hidden until authenticated) ---
        self.chat_frame = tk.Frame(master)

        # Left frame for chat
        self.left_frame = tk.Frame(self.chat_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_text = scrolledtext.ScrolledText(self.left_frame, state='disabled')
        self.chat_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry_field = tk.Entry(self.left_frame)
        self.entry_field.pack(padx=10, pady=10, fill=tk.X)
        self.entry_field.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(self.left_frame, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)

        # Right frame for online users
        self.right_frame = tk.Frame(self.chat_frame, width=200)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)
        self.users_label = tk.Label(self.right_frame, text="Online Users")
        self.users_label.pack(pady=5)
        self.users_listbox = tk.Listbox(self.right_frame)
        self.users_listbox.pack(fill=tk.BOTH, expand=True)

        self.client = None
        self.username = None
        self.authenticated = False

    def connect_to_server(self):
        server_ip = self.server_ip_entry.get().strip()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client.connect((server_ip, PORT))
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to server: {e}")
            self.master.quit()
            return False

        # Start the receive thread after a successful connection
        self.receive_thread = threading.Thread(target=self.receive)
        self.receive_thread.daemon = True
        self.receive_thread.start()
        return True

    def login(self):
        if not self.client or self.client.fileno() == -1:  # Ensure a new connection
            if not self.connect_to_server():
                return
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        auth_data = {"action": "login", "username": username, "password": password}
        self.client.send(cipher.encrypt(json.dumps(auth_data).encode('utf-8')))
        self.username = username

    def signup(self):
        if not self.client or self.client.fileno() == -1:  # Check if the client socket is closed
            if not self.connect_to_server():
                return
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        auth_data = {"action": "signup", "username": username, "password": password}
        self.client.send(cipher.encrypt(json.dumps(auth_data).encode('utf-8')))
        self.username = username

    def switch_to_chat(self):
        self.login_frame.forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def receive(self):
        while True:
            try:
                encrypted_message = self.client.recv(4096)
                if not encrypted_message:
                    break
                message = cipher.decrypt(encrypted_message).decode('utf-8')
                # Handle authentication responses and update commands
                if message == "LOGIN":
                    continue
                elif message in ("LOGIN_SUCCESS", "SIGNUP_SUCCESS"):
                    self.authenticated = True
                    self.switch_to_chat()
                elif message == "LOGIN_FAILED":
                    messagebox.showerror("Error", "Login failed. Check your credentials.")
                    self.client.close()  # Close the connection
                    self.client = None  # Reset client to prevent further use
                    break

                elif message == "USER_EXISTS":
                    messagebox.showerror("Error", "Username already exists.")
                    self.client.close()
                    self.client = None
                    break

                elif message.startswith("/update_users "):
                    users_csv = message[len("/update_users "):]
                    users = users_csv.split(",") if users_csv else []
                    self.users_listbox.delete(0, tk.END)
                    for user in users:
                        self.users_listbox.insert(tk.END, user)
                else:
                    self.chat_text.config(state='normal')
                    self.chat_text.insert(tk.END, message + "\n")
                    self.chat_text.config(state='disabled')
                    self.chat_text.see(tk.END)
            except Exception as e:
                print("Receive error:", e)
                break

    def send_message(self):
        message = self.entry_field.get().strip()
        # The local /clear command clears only this client's chat window.
        if message == "/clear":
            self.chat_text.config(state='normal')
            self.chat_text.delete("1.0", tk.END)
            self.chat_text.config(state='disabled')
            self.entry_field.delete(0, tk.END)
            return
        if message:
            try:
                self.client.send(cipher.encrypt(message.encode('utf-8')))
            except Exception as e:
                print("Send error:", e)
            self.entry_field.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
