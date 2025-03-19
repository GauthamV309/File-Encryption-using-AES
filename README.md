# Secure File Management System

This project is a secure file upload and download system built using Flask, SQLAlchemy, Flask-Login, and cryptographic encryption techniques. It allows users to register, log in, upload files with encryption, and download them with password-based decryption. Files are encrypted using AES in CBC mode, and the password used for encryption/decryption is the user's username.

## Features

- **User Authentication**: Secure user registration and login using hashed passwords.
- **File Upload**: Users can upload files that are encrypted with a password derived from their username.
- **File Download**: Users can download encrypted files and decrypt them using a password.
- **Flask-Based Web Interface**: Simple and responsive web UI using Flask templates for user interaction.
- **Database Storage**: SQLAlchemy stores user credentials and file metadata in a SQLite database.
- **File Security**: Files are encrypted using AES encryption (CBC mode) for confidentiality.

---

## Project Setup

### Prerequisites

Make sure you have the following installed:

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Cryptography

You can install the necessary dependencies using the following command:

```bash
pip install -r requirements.txt
```

### Directory Structure

```
.
├── app.py                  # Main Flask application file
├── instance
      database.db             # SQLite database file for storing user and file data
├── uploads/                # Directory where uploaded files are stored
├── templates/              # HTML templates for Flask views
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   └── download.html
└── requirements.txt        # List of dependencies
```

### Environment Setup

1. **Clone the repository**:

```bash
git clone https://github.com/GauthamV309/File-Encryption-using-AES
cd File-Encryption-using-AES
```

2. **Create a virtual environment (optional but recommended)**:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. **Install required dependencies**:

```bash
pip install -r requirements.txt
```

4. **Run the Flask Application**:

```bash
python app.py
```

By default, the application will run on `http://127.0.0.1:5000`.

---

## Application Flow

### 1. User Registration

- **Route**: `/register` (GET/POST)
- **Description**: New users can register by providing a username and password. Passwords are securely hashed using `scrypt` before storing in the database.

### 2. User Login

- **Route**: `/login` (GET/POST)
- **Description**: Users can log in with their username and password. On successful login, they are redirected to their dashboard.

### 3. File Upload

- **Route**: `/upload` (POST)
- **Description**: After logging in, users can upload files. The files are encrypted using AES encryption, where the user's username is used as the encryption password.

### 4. File Download

- **Route**: `/download/<int:file_id>` (GET/POST)
- **Description**: Users can download encrypted files by providing the password they used for encryption. The file will be decrypted and sent to the user as an attachment.

### 5. Dashboard

- **Route**: `/dashboard` (GET)
- **Description**: After logging in, users are redirected to their dashboard where they can view and manage their uploaded files.

---

## Encryption Details

The encryption is performed using the **AES (Advanced Encryption Standard)** algorithm in **CBC (Cipher Block Chaining)** mode. The key for encryption is derived from the user's username (padded or truncated to 32 bytes). A random 16-byte IV (Initialization Vector) is generated for each file, ensuring that identical files encrypted with the same password will have different ciphertexts.

- **Encryption**: AES-CBC with padding (PKCS7)
- **Decryption**: AES-CBC with padding removal

### Encrypt File Function

```python
def encrypt_file(file_data, password):
    key = password.encode('utf-8').ljust(32)[:32]  # 32-byte key
    iv = os.urandom(16)  # Random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # Padding to 128-bit block size
    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data
```

### Decrypt File Function

```python
def decrypt_file(file_data, password):
    key = password.encode('utf-8').ljust(32)[:32]  # 32-byte key
    iv = file_data[:16]  # First 16 bytes are the IV
    encrypted_data = file_data[16:]  # The rest is the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()  # Remove padding
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data
```

---

## Security Considerations

- The user's **username** is used as the encryption password, which means it is important that usernames are not easily guessable.
- Encryption key length is fixed to 32 bytes, and the password is padded or truncated to meet this requirement.
- Ensure that the `SECRET_KEY` in the Flask configuration is sufficiently strong to prevent attacks like CSRF (Cross-Site Request Forgery).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributing

We welcome contributions to improve the security and functionality of this project. Please feel free to open issues and pull requests for any bug fixes, features, or improvements.

---

## Acknowledgements

- **Flask**: Lightweight web framework used for the web application.
- **SQLAlchemy**: ORM used for managing the database.
- **Flask-Login**: User session management.
- **Cryptography**: Provides encryption and decryption features.

---

## Troubleshooting

If you encounter any issues, please check the following:

- Ensure the SQLite database (`database.db`) exists and is accessible.
- Make sure the `uploads/` folder exists and is writable by the application.
- If running in a production environment, make sure to set the `SECRET_KEY` to a secure value.

---

Enjoy secure file uploads and downloads!
