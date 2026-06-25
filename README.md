# 🔐 SecureVault (Console Edition)

SecureVault is a cross-platform encrypted vault application written in Java that enables secure storage of files, directories, passwords, and API keys. It combines modern cryptography, parallel file processing, and advanced security mechanisms to provide a secure environment for protecting sensitive data.

Designed with security and performance in mind, SecureVault supports password rotation, configurable lockdown policies, self-destruct protection, and efficient handling of large vaults through a dedicated vault-key architecture.

---

## ✨ Features

### 📦 Secure Storage

Store and manage:

* 📄 Files
* 📁 Directories
* 🔑 Passwords
* 🛠️ API Keys

All vault contents are encrypted before being written to disk.

---

### 🔒 Strong Encryption

SecureVault uses industry-standard cryptographic primitives:

* AES/GCM/NoPadding for authenticated encryption
* PBKDF2WithHmacSHA256 for password-based key derivation
* AES-256 encryption keys

This provides:

* 🔐 Confidentiality
* 🛡️ Integrity
* ✅ Authentication

for all stored data.

---

### 🗝️ Vault-Key Architecture

Instead of encrypting vault contents directly with the user's password, SecureVault uses a dedicated vault key.

During vault creation:

1. A random vault key is generated.
2. The user's password is processed using PBKDF2WithHmacSHA256.
3. The derived key encrypts the vault key.
4. The vault key encrypts all vault contents.

```text
Master Password
       │
       ▼
PBKDF2WithHmacSHA256
       │
       ▼
Key Encryption Key
       │
       ▼
Encrypted Vault Key
       │
       ▼
Random Vault Key
       │
       ▼
Vault Contents
```

This design improves scalability and enables efficient password rotation.

---

### 🔄 Password Rotation

Master passwords can be changed at any time.

Since vault data is protected by a separate vault key, changing the password only requires re-encrypting the vault key rather than re-encrypting the entire vault.

✅ Fast password updates

✅ Independent of vault size

✅ Efficient even for large vaults

---

### ⚡ Parallel File Processing

SecureVault supports parallel processing of multiple files to improve performance during vault operations.

Implementation technologies:

* Java Virtual Threads
* Executor-based task management

Benefits:

* Faster imports and exports
* Better utilization of modern hardware
* Improved scalability for large vaults

---

### 🚨 Lockdown Mode

Lockdown Mode prevents access to vault contents when suspicious activity is detected.

It can be:

* Enabled manually
* Triggered automatically after a user-defined number of failed password attempts

When active, vault contents remain inaccessible until the lockdown condition is cleared.

---

### 💥 Self-Destruct Mode

For highly sensitive vaults, SecureVault can permanently destroy vault contents.

Options include:

* Manual self-destruction
* Automatic self-destruction after a configurable number of failed authentication attempts

This provides an additional layer of protection against unauthorized access.

---

### 🌍 Cross-Platform Compatibility

SecureVault uses a platform-independent vault format.

Tested on:

* 🐧 Linux
* 🪟 Windows

Vaults created on one platform can be accessed on another without modification.

---

## 🛡️ Security Overview

| Component             | Implementation         |
| --------------------- | ---------------------- |
| Encryption Algorithm  | AES/GCM/NoPadding      |
| Key Size              | AES-256                |
| Key Derivation        | PBKDF2WithHmacSHA256   |
| Authentication        | GCM Authentication Tag |
| Password Rotation     | ✅ Supported            |
| Lockdown Mode         | ✅ Supported            |
| Self-Destruct Mode    | ✅ Supported            |
| Cross-Platform Vaults | ✅ Supported            |

---

## 🏗️ Technology Stack

| Category         | Technology                  |
| ---------------- | --------------------------- |
| Language         | Java 25                     |
| Build Tool       | Maven                       |
| Encryption       | AES-GCM                     |
| Key Derivation   | PBKDF2-HMAC-SHA256          |
| Concurrency      | Virtual Threads & Executors |
| Platform Support | Linux, Windows              |

---

## 📋 Requirements

* Java 25
* Maven 3.9+

---

## 🏗️ Building

Clone the repository:

```bash
git clone https://github.com/anonymous6291/secure-vault-core.git
cd secure-vault-core
```

Build the project:

```bash
mvn clean package
```

---

## ▶️ Running

Run the generated JAR:

```bash
java -jar target/secure-vault-core-1.0-SNAPSHOT.jar
```

---

## 🎯 Use Cases

SecureVault is suitable for securely storing:

* Personal documents
* Password collections
* API credentials
* Project secrets
* Configuration files
* Backup archives
* Sensitive business data

---

## 🚀 Project Highlights

* 🔐 Authenticated encryption using AES-GCM
* 🗝️ Dedicated vault-key architecture
* 🔄 Efficient password rotation
* ⚡ Parallel file processing using Virtual Threads
* 🚨 Configurable Lockdown Mode
* 💥 Configurable Self-Destruct Mode
* 🌍 Cross-platform vault compatibility
* 📁 Support for files and directories
* 🔑 Secure password and API key storage
* ☕ Built with Java 25

---

## ⚠️ Disclaimer

SecureVault is an educational and portfolio project developed to explore cryptography, concurrency, secure storage systems, and Java application development.

While the application employs modern cryptographic techniques and security-focused design principles, users should independently evaluate whether it meets their requirements before using it to protect highly sensitive or mission-critical data.
