# PWMGR

PWMGR is a desktop password manager for Windows and Linux. Built with Qt6, it uses modern cryptography, zstd compression, and password quality checks on your master key.

---

## Features

* **Cross-Platform**: Runs on Windows and Linux.
* **Qt6 GUI**: A simple desktop interface with clean support for both Light and Dark modes.
* **TOTP Support**: Generate and store Time-based One-Time Passwords along with stored entries.
* **Auto-Hiding Fields**: Passwords and TOTP tokens are hidden by default.
* **Auto-Save**: Changes save automatically while working and when closing the window.
* **Zstd Compression**: Compresses data with Zstandard before encryption (and after when it is able to reduce file size).
> **Platform Note**: Demo screenshots showcase Dark mode on both Windows and Linux (KDE). The application UI remains consistent across Linux desktop environments, though window decorations, fonts, and other system-level styling may vary (e.g., KDE, GNOME, Xfce).

---

## Startup Flow

When PWMGR starts, it will first open a file selector where you can create a new `.pwmgr1` file or load an existing one.

After selecting the vault file, PWMGR will prompt you for the **master password**. At this stage, you can either enter the existing password and click **Unlock**, or change the password before unlocking.

Once the vault is unlocked, the main password manager window will open.

---

## Security & Cryptography

* **Key Derivation**: Argon2id (`time_cost=13`, `memory_cost=524288` / ~512 MB, `parallelism=1`) derives the master key from the master password.
* **Key Normalization**: BLAKE3 is used to derive a AES key from the Argon2id-derived key, ensuring a consistent key length for AES-GCM.
* **Encryption**: AES-GCM is used to encrypt the vault data with the derived single-use key.
* **Integrity & Signatures**: Ed25519 signatures are used to provide cryptographic authenticity and integrity verification.

> **Vault Load Time**: Because of the high Argon2id parameters, expect around a 5-second delay between the main window opening and the vault finishing loading. This depends on your hardware and is expected behavior.

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
