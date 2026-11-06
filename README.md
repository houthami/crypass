# Crypass

A small password picker for Windows. Click into any email or password field, press
**Ctrl+Shift+Space**, pick the account, and Crypass types the value for you.

Everything stays on your PC in one encrypted file. There is no account, no cloud and no
network access.

## Download

| Version | Date | Platform | Download |
|---|---|---|---|
| **1.0.0** | 2026-11-05 | Windows 10/11 (64-bit) | [crypass-1.0.0-windows-x64.exe](https://github.com/houthami/crypass/releases/download/v1.0.0/crypass-1.0.0-windows-x64.exe) |

All versions and release notes are on the [Releases page](https://github.com/houthami/crypass/releases).

Crypass is a single `.exe` with no installer, so put it somewhere permanent (for example
`C:\Program Files\Crypass` or a folder in your user profile) and run it.

> Windows SmartScreen may warn about it the first time because the file isn't code-signed.
> Choose **More info → Run anyway** only if you downloaded it from the link above.

## How to use it

1. Run Crypass. It lives in the system tray.
2. The first time, create your **master password**. If you forget it, your accounts can't be
   recovered.
3. Click into a login field in any app or website and press **Ctrl+Shift+Space**.
4. Choose the account with the arrow keys and press **Enter**. **Tab** switches between
   filling the email and the password; Crypass picks the right one when it can tell.

### Shortcuts

| Where | Key | Does |
|---|---|---|
| Anywhere | `Ctrl+Shift+Space` | Open the picker for the field you're in |
| Account list | `Enter` / `Tab` / `Esc` | Fill / switch email or password / close |
| Account list | `Ctrl+N` / `Ctrl+E` / `Ctrl+,` | Add / edit / settings |
| Add or edit | `Ctrl+G` | Generate a 20-character password |
| Locked | `Ctrl+H` | Unlock with Windows Hello (once turned on) |

### Features

- **Types into any app**: browsers, desktop apps and sign-in windows.
- **Remembers where you use each account**: next time on the same site or app, it's at the top.
- **Password generator**: 20 characters with lowercase, uppercase, digits and symbols.
- **Locks itself** after 10 minutes without use, when the laptop sleeps and when you lock Windows.
- **Start with Windows** (tray menu): Crypass starts with your PC and asks for the master
  password right away.
- **Windows Hello**: unlock with your face, fingerprint or PIN (Settings).
- **Backups**: tray menu → *Back Up Vault...*; restore from Settings, the locked screen, or the
  first-run screen on a new PC.
- **Change master password** (Settings).

## Security

- The vault is encrypted with AES-256-GCM. The key comes from your master password through
  Argon2id, so guessing it is slow.
- The vault file is `%APPDATA%\com.zayvo.crypass\vault.crypass`. Without the master password it
  is unreadable, but **keep backups**: if the file is lost, so are your accounts.
- Backups open with the master password that was in use when they were saved. After changing
  the password, save a new backup and delete old ones if the old password leaked.
- Windows Hello is only as strong as your Windows PIN: anyone who knows it and can use your
  Windows account can unlock Crypass on that PC. It turns off after a password change or a restore.
- Crypass won't type into apps running as administrator, because Windows blocks that.

## Build from source

Needs [Rust](https://rustup.rs), [Node.js](https://nodejs.org) and the Tauri prerequisites for
Windows (WebView2 ships with Windows 11).

```sh
npm install
npx tauri build --no-bundle      # builds src-tauri/target/release/crypass.exe
cargo test -p crypass-vault      # run from src-tauri/
```

For development, `npx tauri dev`. Set `CRYPASS_VAULT_PATH` to use a test vault instead of your
real one.

## Roadmap

- Import passwords from Chrome / Edge (CSV)
- Automatic encrypted backups to a folder you choose
- Two-factor (TOTP) codes
- Linux version
