# Secure Instant Point-to-Point (P2P) Messaging

**Course:** CS 5173/4173 Computer Security

## Overview

This application facilitates encrypted point-to-point communication. It utilizes a graphical interface to process and display the transmission of text messages, picture files, voice recordings, and standard data files using either 56-bit DES or 128-bit AES encryption schemas.

## Requirements

To execute this script, ensure the python cryptography package is installed:
`pip install pycryptodome`

All files required to test the program in the input files

## Execution Instructions

1. Open two independent instances of the application by running `python p2p_messenger.py` in two separate terminal windows (one acting as the Host, one as the Peer).
2. The GUI comes pre-filled with a default **Shared Password** (`secret`) and a **Key Length** (`56` for DES).
3. In the first window (Host), verify the settings and click the **Host** button to start listening on the default port.
4. In the second window (Peer), ensure the **Host/IP** is `127.0.0.1` (for local testing), match the settings, and click the **Connect** button.
5. To send text, type your message in the bottom entry field and press `Enter` (or click **Send**).
6. To send media (pictures, voice, documents), click **Attach File** to open a system dialog and select your file. It will be securely transmitted and automatically saved with a `recv_` prefix in the `received_files` directory.

## How the Code Works

The application (`p2p_messenger.py`) is broken down into three main parts:

### 1. Security (Cryptography)
This part handles locking (encrypting) and unlocking (decrypting) your messages so no one else can read them.
* **Passwords**: It turns your typed password into a secure secret key.
* **Locking/Unlocking**: It uses standard security methods (DES or AES) to scramble your messages before they are sent, and unscramble them when they are received.

### 2. Connection (Network)
This part handles connecting the two computers together over the network.
* **Hosting/Connecting**: One person "hosts" the connection (like opening a door), and the other person "connects" to them using an IP address and port number.
* **Sending Data**: It makes sure messages are sent completely in one piece without getting cut off.

### 3. Messaging
This part handles typing text and attaching files.
* **Sending**: When you send a message or file, the code labels what type of data it is, scrambles it for security, and sends it to the other person.
* **Receiving**: When a scrambled message arrives, the code unscrambles it. If it's text, it shows up in the chat window. If it's a file, it gets saved in the `received_files` folder automatically.
