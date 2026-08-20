import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import hashlib
import os
import struct
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

class SecureP2PMessenger:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Messenger (Alice & Bob)")
        self.root.geometry("650x750")
        
        self.conn = None
        self.is_connected = False
        self.file_save_dir = os.path.join(os.getcwd(), "received_files")
        if not os.path.exists(self.file_save_dir):
            os.makedirs(self.file_save_dir)

        self._build_gui()

    def _build_gui(self):
        # Connection & Security Frame 
        conn_frame = tk.LabelFrame(self.root, text="Connection & Security Setup")
        conn_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(conn_frame, text="Host/IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ip_entry = tk.Entry(conn_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(conn_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        tk.Label(conn_frame, text="Shared Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = tk.Entry(conn_frame, width=15, show="*")
        self.password_entry.insert(0, "secret")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(conn_frame, text="Key Length (n):").grid(row=1, column=2, padx=5, pady=5, sticky="e")
        self.key_len_var = tk.StringVar(value="56")
        self.key_dropdown = ttk.Combobox(conn_frame, textvariable=self.key_len_var, values=["56", "128"], width=4)
        self.key_dropdown.grid(row=1, column=3, padx=5, pady=5)

        self.host_btn = tk.Button(conn_frame, text="Host", command=self.host_server)
        self.host_btn.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.connect_peer)
        self.connect_btn.grid(row=2, column=2, columnspan=2, pady=5)

        # Chat Display Frame
        chat_frame = tk.LabelFrame(self.root, text="Chat & Ciphertext Display")
        chat_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.chat_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled', height=20)
        self.chat_display.pack(padx=5, pady=5, fill="both", expand=True)

        # Message Input Frame
        input_frame = tk.Frame(self.root)
        input_frame.pack(padx=10, pady=5, fill="x")

        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda event: self.send_text())

        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_text)
        self.send_btn.pack(side="left")

        self.attach_btn = tk.Button(input_frame, text="Attach File", command=self.send_file)
        self.attach_btn.pack(side="left", padx=(5, 0))

    # CRYPTOGRAPHY MODULE
    def derive_key(self):
        """
        Derives an encryption key from the shared password using hashing.
        """
        password = self.password_entry.get().encode()
        bits = int(self.key_len_var.get())
        
        if bits == 56:
            # SHA-1 hash, truncated to 8 bytes. 
            # DES uses 8-byte keys (64 bits) but 8 bits are parity, making it 56-bit effective.
            return hashlib.sha1(password).digest()[:8]
        elif bits == 128:
            # MD5 produces exactly 128 bits (16 bytes) for AES-128.
            return hashlib.md5(password).digest()

    def encrypt_data(self, data: bytes) -> bytes:
        key = self.derive_key()
        bits = int(self.key_len_var.get())
        
        if bits == 56:
            cipher = DES.new(key, DES.MODE_ECB)
            block_size = DES.block_size
        else:
            cipher = AES.new(key, AES.MODE_ECB)
            block_size = AES.block_size
            
        padded_data = pad(data, block_size)
        return cipher.encrypt(padded_data)

    def decrypt_data(self, ciphertext: bytes) -> bytes:
        key = self.derive_key()
        bits = int(self.key_len_var.get())
        
        if bits == 56:
            cipher = DES.new(key, DES.MODE_ECB)
            block_size = DES.block_size
        else:
            cipher = AES.new(key, AES.MODE_ECB)
            block_size = AES.block_size
            
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, block_size)

    # NETWORK MODULE 
    def host_server(self):
        port = int(self.port_entry.get())
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        self.log_gui(f"Server listening on port {port}...")
        
        def accept_conn():
            self.conn, addr = server.accept()
            self.is_connected = True
            self.log_gui("P2P Connection Established.")
            threading.Thread(target=self.receive_loop, daemon=True).start()
            
        threading.Thread(target=accept_conn, daemon=True).start()

    def connect_peer(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.conn.connect((ip, port))
            self.is_connected = True
            self.log_gui("P2P Connection Established.")
            threading.Thread(target=self.receive_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def send_network_payload(self, ciphertext: bytes):
        if not self.is_connected or not self.password_entry.get():
            messagebox.showwarning("Warning", "Ensure you are connected and password is set.")
            return
        
        # Framing: send 4-byte integer representing the length of the incoming ciphertext
        msg_len = struct.pack("!I", len(ciphertext))
        self.conn.sendall(msg_len + ciphertext)

    def receive_loop(self):
        while self.is_connected:
            try:
                # Read the 4-byte length header
                raw_msglen = self.recvall(4)
                if not raw_msglen:
                    break
                msglen = struct.unpack("!I", raw_msglen)[0]
                
                # Read the actual ciphertext payload
                ciphertext = self.recvall(msglen)
                if ciphertext:
                    self.process_incoming(ciphertext)
            except Exception as e:
                self.log_gui(f"System: Connection dropped. {e}")
                self.is_connected = False
                break

    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    # MESSAGING MODULE #
    def send_text(self):
        text = self.msg_entry.get()
        if not text: return
        
        # Format: TYPE|FILENAME|PAYLOAD
        payload = f"TEXT||{text}".encode()
        try:
            ciphertext = self.encrypt_data(payload)
            self.log_gui(f"[PLAINTEXT ME]: {text}")
            self.log_gui(f"[CIPHERTEXT SENT]\n{ciphertext.hex()[:80]}...", color="grey")
            self.send_network_payload(ciphertext)
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Check password and key settings.\n{e}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath: return
        
        filename = os.path.basename(filepath)
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
                
            header = f"FILE|{filename}|".encode()
            payload = header + file_data
            ciphertext = self.encrypt_data(payload)
            
            self.log_gui(f"[PLAINTEXT ME sent file]: {filename} ({len(file_data)} bytes)")
            self.log_gui(f"[CIPHERTEXT SENT]\n{ciphertext.hex()[:80]}...", color="grey")
            self.send_network_payload(ciphertext)
        except Exception as e:
            messagebox.showerror("File Error", str(e))

    def process_incoming(self, ciphertext: bytes):
        try:
            self.log_gui(f"[CIPHERTEXT RECEIVED]\n{ciphertext.hex()[:80]}...", color="grey")
            plaintext = self.decrypt_data(ciphertext)
            
            # Parse the custom framing
            parts = plaintext.split(b'|', 2)
            msg_type = parts[0].decode()
            filename = parts[1].decode()
            data = parts[2]
            
            if msg_type == "TEXT":
                self.log_gui(f"[PLAINTEXT PEER]: {data.decode()}")
            elif msg_type == "FILE":
                save_name = f"recv_{filename}"
                save_path = os.path.join(self.file_save_dir, save_name)
                with open(save_path, 'wb') as f:
                    f.write(data)
                self.log_gui(f"[PLAINTEXT PEER]: Media saved as {save_name}")
                
        except Exception as e:
            self.log_gui(f"System: Decryption failed. Keys or padding may be mismatched. {e}", color="red")

    def log_gui(self, message, color="black"):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        # Quick tag for coloring
        if color != "black":
            self.chat_display.tag_add(color, "end-2l", "end-1c")
            self.chat_display.tag_config(color, foreground=color)
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureP2PMessenger(root)
    root.mainloop()
