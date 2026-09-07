# PWMGR

PWMGR is a desktop password manager for Windows and Linux. Built with Qt6, it uses modern cryptography, zstd compression, and password quality checks on your master key.

---

## Features

* **Cross-Platform**: Runs on Windows and Linux.
* **Qt6 GUI**: Simple desktop interface.
* **TOTP Support**: Generate and store Time-based One-Time Passwords along with stored entries.
* **Auto-Hiding Fields**: Passwords and TOTP tokens are hidden by default and automatically hide again 30 seconds after being revealed.
* **Auto-Save**: Changes save automatically while working and when closing the window.
* **Zstd Compression**: Compresses data with Zstandard before encryption (and after when it actually reduces file size).

---

## Security & Cryptography

* **Key Derivation**: Argon2id (`time_cost=13`, `memory_cost=524288` / ~512 MB, `parallelism=1`).
* **Encryption**: AES-GCM.
* **Integrity**: BLAKE3 and Ed25519 signatures.

> **Vault Load Time**: Because of the high Argon2id parameters, expects around a 5-second delay between the main window opening and the vault finishing loading. This depends on your hardware and is expected behavior.

---

## Master Password Security

PWMGR uses **zxcvbn** to enforce strength constraints on your **master password**. 

Master password strength is indicated by a progress bar:

* 🔴 **Red (Rejected)**: Under 10^8 estimated guesses. The application will reject the password.
* 🔵 **Blue (Prompt)**: Between 10^8 and 10^10 estimated guesses. Allowed, but the app will nudge you each time to move toward a stronger passphrase.
* 🟢 **Green (Secure)**: 10^10 estimated guesses or higher.

---

## Dependencies & Requirements

PWMGR relies on the following third-party Python packages:

* **`PyQt6`**: Desktop graphical user interface framework.
* **`pyotp`**: Time-based One-Time Password (TOTP) management.
* **`zstandard`**: Fast compression library.
* **`zxcvbn`**: Password strength estimation.
* **`cryptography`**: Primitive crypto operations, certificates, asymmetric key support, and AES-GCM.
* **`argon2-cffi`**: Low-level bindings for Argon2id key derivation.
* **`blake3`**: BLAKE3 cryptographic hashing.
* **`numpy`**: Converting strings to bytes quickly.
