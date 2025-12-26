# 🏦 Complete Bank Manager

A secure, offline desktop application for managing bank cards and details. Built with Python, Tkinter, and SQLite.

## ✨ Features

*   **🔒 Secure Authentication**: Master password protection using PBKDF2 hashing.
*   **🛡️ Data Encryption**: Sensitive details (Account No, PIN, CVV) are encrypted using AES (Fernet).
*   **👁️ Privacy**: Data masking in the user interface.
*   **📊 Excel Integration**: Professional Import and Export capabilities.
*   **📂 Portable**: Works from any folder; self-contained database.

## 🚀 Installation & Setup

Follow these step-by-step commands to get started.

### 1. Clone the Repository
Open your terminal or command prompt:

```bash
git clone <your-repository-url>
cd <repository-directory>
```

*(Alternatively, download the ZIP from GitHub and extract it)*

### 2. Install Dependencies
Ensure you have Python installed. Then run:

```bash
pip install -r requirements.txt
```

### 3. Run the Application
Start the Bank Manager:

```bash
python bank_application/main.py
```

## 🛠️ Usage Guide

1.  **First Run**: You will be prompted to set a **Master Password**. Remember this password; it encrypts your data!
2.  **Dashboard**: Add, Edit, or Delete cards using the buttons.
3.  **Excel**: Use "Export Excel" to backup data (unmasked) or "Import Excel" to restore data.

---
**Note:** This application runs locally. Your data stays on your machine.
