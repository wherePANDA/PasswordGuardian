# PasswordGuardian – Password Strength Meter & Secure Generator

**PasswordGuardian** is a lightweight, single-file PHP web app that helps users **measure password strength** and **generate secure passwords or passphrases**. No external services, no tracking—just drop it on a PHP server and go.

## ✨ Features

- **Strength Meter**
  - Entropy estimate (bits) with a clean visual meter
  - Actionable suggestions (length, variety, sequences, repeats)
  - Flags a tiny demo list of common passwords (local only)

- **Secure Generator**
  - Password mode: choose length (8–128), upper/lower/digits/symbols, and **exclude ambiguous** characters
  - Passphrase mode: choose number of words (2–10) and separator (e.g. `-`, `_`, space)
  - Cryptographically secure RNG via PHP’s `random_int`
  - Copy to clipboard, “send to meter”, and show/hide controls

- **Zero Dependencies**
  - Single `index.php` file
  - No external APIs or CDNs required
  - Works on PHP 7.4+ (tested up to PHP 8.x)

## 🚀 Quick Start

1. **Copy** `index.php` to your web server directory (e.g., `/var/www/html/passwordguardian/`).
2. **Open** in your browser: `https://your-domain.com/passwordguardian/index.php`
3. Start typing a password to **check strength** or use the **generator** panel.

> **Note:** The app never sends your typed password off the page. The optional server call is used only to generate random secrets on the same host for broader browser compatibility.

## 🛡️ Security Notes

- Uses PHP’s `random_int` under the hood for cryptographically secure randomness.
- Includes a **very small demonstration** list of common passwords for local checks.  
  For production, consider integrating a **larger offline list** (e.g., top 100k) or a local Pwned Passwords hash range set. Avoid calling external services with full passwords.
- Entropy calculation is a **heuristic** (L·log₂(N) minus simple pattern penalties). It’s intended for education and guidance—not a formal proof of strength.
- Always pair strong passwords with **MFA** (TOTP or security keys) for critical accounts.

## ⚙️ Configuration

You can tweak defaults by editing `index.php`:

- Default password length: `value="16"`
- Passphrase default: `5` words with `-` separator
- Ambiguous character filtering: enabled by default (configurable via checkbox)
- UI styling is inline CSS; adjust color variables in the `:root` block.

## 📦 Tech Stack

- **Language:** PHP (server), vanilla JS (client)
- **No frameworks** or external packages

## 🧪 Compatibility

- PHP 7.4+  
- Modern browsers for clipboard & UI (fallbacks gracefully to server-side generation)

## 📝 License

[MIT](LICENSE) © 2025 Catalin / trustpixel.com
