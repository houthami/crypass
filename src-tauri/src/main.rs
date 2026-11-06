// No console in any build: a console window takes focus at launch, which
// dismisses the popup.
#![windows_subsystem = "windows"]

mod platform;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use crypass_vault::matching::{self, Warning};
use crypass_vault::Vault;
use serde::{Deserialize, Serialize};
use tauri::menu::{CheckMenuItem, Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, State, WebviewWindow, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
use zeroize::Zeroizing;

const SHORTCUT: &str = "ctrl+shift+space";
/// Added to the startup entry, so a launch at sign-in can be told from a manual one.
const AUTOSTART_ARG: &str = "--autostart";
const AUTO_LOCK_IDLE: Duration = Duration::from_secs(10 * 60);
const AUTO_LOCK_CHECK: Duration = Duration::from_secs(2);
/// A much longer gap between checks than expected means the PC was asleep.
const SLEEP_GAP: Duration = Duration::from_secs(30);
const PROMPT_FOCUS_TIME: Duration = Duration::from_secs(15);
const PROMPT_FOCUS_RETRY: Duration = Duration::from_millis(250);
/// How long the account just used stays preselected for the same window.
const REMEMBER_ACCOUNT: Duration = Duration::from_secs(120);
/// A page can still be settling just after focus returns, so the check made
/// right before typing gets a few tries.
const RECHECK_ATTEMPTS: u32 = 4;
const RECHECK_DELAY: Duration = Duration::from_millis(150);
const CAPTURE_RETRIES: u32 = 4;
const CAPTURE_RETRY_DELAY: Duration = Duration::from_millis(200);

/// The window and field the popup was opened for.
#[derive(Clone)]
struct Session {
    target: platform::Target,
    /// What accounts are matched against, if it can be confirmed.
    key: Option<String>,
    label: String,
    is_password: Option<bool>,
}

impl Session {
    fn capture(target: platform::Target) -> Self {
        let process = platform::target_process_name(target);
        let in_browser = process.as_deref().is_some_and(matching::is_browser);
        let mut focus = platform::inspect_focus();
        let mut key = matching::context_key(process.as_deref(), focus.url.as_deref());
        // Browsers only build this information once something asks for it, so
        // the first read after a browser starts usually comes back empty.
        let mut retries = 0;
        while in_browser && key.is_none() && retries < CAPTURE_RETRIES {
            std::thread::sleep(CAPTURE_RETRY_DELAY);
            focus = platform::inspect_focus();
            key = matching::context_key(process.as_deref(), focus.url.as_deref());
            retries += 1;
        }

        let title = platform::target_title(target);
        let label = match &key {
            Some(key) if in_browser => matching::display_key(key).to_string(),
            None if in_browser => format!("{title} (site not confirmed)"),
            _ => title,
        };
        Self {
            target,
            key,
            label,
            is_password: focus.is_password,
        }
    }
}

struct LastFill {
    account_id: u32,
    field: Field,
    target: platform::Target,
    at: Instant,
}

#[derive(Default)]
struct AppState {
    session: Mutex<Option<Session>>,
    last_fill: Mutex<Option<LastFill>>,
    vault: Mutex<Option<Vault>>,
    vault_path: OnceLock<PathBuf>,
    /// While a form is open, the popup stays up if the user switches away,
    /// for example to copy a password from another app.
    pinned: AtomicBool,
    /// The popup opened by itself to ask for the master password. Startup apps
    /// can take focus at any moment, so it stays up until answered or dismissed.
    unlock_prompt: AtomicBool,
    /// Chosen in the file dialog. The page never supplies a path itself.
    restore_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    fn path(&self) -> &PathBuf {
        self.vault_path.get().expect("set during setup")
    }

    fn with_vault<T>(
        &self,
        action: impl FnOnce(&mut Vault) -> Result<T, crypass_vault::Error>,
    ) -> Result<T, String> {
        let mut guard = self.vault.lock().unwrap();
        let vault = guard.as_mut().ok_or("Crypass is locked.")?;
        action(vault).map_err(|e| e.to_string())
    }
}

/// Passwords are never part of this: they stay on the Rust side.
#[derive(Clone, Serialize)]
struct AccountSummary {
    id: u32,
    label: String,
    username: String,
    /// Saved for the window being filled.
    matched: bool,
    sites: Vec<SavedSite>,
}

#[derive(Clone, Serialize)]
struct SavedSite {
    key: String,
    label: String,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum VaultStatus {
    Setup,
    Locked,
    Unlocked,
}

#[derive(Clone, Serialize)]
struct PopupView {
    status: VaultStatus,
    target_title: String,
    accounts: Vec<AccountSummary>,
    selected_id: Option<u32>,
    initial_field: Field,
    min_password_chars: usize,
    hello_enabled: bool,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Field {
    Username,
    Password,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum FillOutcome {
    Done,
    /// Nothing was typed. Filling again with `confirmed` set goes ahead.
    Confirm { message: String },
}

fn main_window(app: &AppHandle) -> WebviewWindow {
    app.get_webview_window("main")
        .expect("the main window is defined in tauri.conf.json")
}

/// Accounts saved for this window come first.
fn summaries(vault: &Vault, key: Option<&str>) -> Vec<AccountSummary> {
    let mut accounts: Vec<AccountSummary> = vault
        .entries()
        .iter()
        .map(|e| AccountSummary {
            id: e.id,
            label: e.label.clone(),
            username: e.username.clone(),
            matched: key.is_some_and(|key| e.matches.iter().any(|m| m == key)),
            sites: e
                .matches
                .iter()
                .map(|m| SavedSite {
                    key: m.clone(),
                    label: matching::display_key(m).to_string(),
                })
                .collect(),
        })
        .collect();
    accounts.sort_by_key(|a| !a.matched);
    accounts
}

fn current_view(state: &AppState) -> PopupView {
    let session = state.session.lock().unwrap().clone();
    let key = session.as_ref().and_then(|s| s.key.as_deref());
    let guard = state.vault.lock().unwrap();
    let (status, accounts) = match guard.as_ref() {
        Some(vault) => (VaultStatus::Unlocked, summaries(vault, key)),
        None if state.path().exists() => (VaultStatus::Locked, Vec::new()),
        None => (VaultStatus::Setup, Vec::new()),
    };

    // Filling the same window again usually means the next field of one login.
    let last_fill = state.last_fill.lock().unwrap();
    let recent = last_fill.as_ref().filter(|last| {
        session.as_ref().is_some_and(|s| s.target == last.target)
            && last.at.elapsed() < REMEMBER_ACCOUNT
            && accounts.iter().any(|a| a.id == last.account_id)
    });

    let is_password = session.as_ref().and_then(|s| s.is_password);
    let initial_field = match (is_password, recent) {
        (Some(true), _) => Field::Password,
        (Some(false), _) => Field::Username,
        (None, Some(last)) if last.field == Field::Username => Field::Password,
        (None, _) => Field::Username,
    };

    PopupView {
        status,
        target_title: session.map(|s| s.label).unwrap_or_default(),
        selected_id: recent.map(|last| last.account_id),
        initial_field,
        accounts,
        min_password_chars: crypass_vault::MIN_PASSWORD_CHARS,
        hello_enabled: crypass_vault::quick_unlock_enabled(state.path()),
    }
}

fn on_shortcut(app: &AppHandle) {
    // This must happen before the popup is shown and takes focus.
    let target = platform::capture_target();
    if main_window(app).is_visible().unwrap_or(false) {
        // The unlock prompt can be open while the user is in another window, so
        // the shortcut means that window's field. Otherwise it closes the popup.
        let prompting = app.state::<AppState>().unlock_prompt.load(Ordering::SeqCst);
        if !(prompting && target.is_some()) {
            close_and_restore(app);
            return;
        }
    }
    show_popup(app, target.map(Session::capture), false);
}

/// Asks for the master password without waiting for the shortcut.
fn prompt_unlock(app: &AppHandle) {
    let state = app.state::<AppState>();
    let needs_unlock = state.vault.lock().unwrap().is_none() && state.path().exists();
    if needs_unlock {
        show_popup(app, None, true);
        hold_prompt_focus(app.clone());
    }
}

/// Windows can refuse a background app focus, and startup apps can take it, which
/// would leave the prompt on screen but not ready to type in. This keeps asking
/// until the user does something, so it never pulls focus away from their work.
fn hold_prompt_focus(app: AppHandle) {
    std::thread::spawn(move || {
        let started = Instant::now();
        while started.elapsed() < PROMPT_FOCUS_TIME {
            std::thread::sleep(PROMPT_FOCUS_RETRY);
            let user_acted = platform::idle_time().is_some_and(|idle| idle < started.elapsed());
            let prompting = app.state::<AppState>().unlock_prompt.load(Ordering::SeqCst);
            if user_acted || !prompting {
                return;
            }
            let window = main_window(&app);
            if !window.is_focused().unwrap_or(true) {
                let _ = window.set_focus();
            }
        }
    });
}

fn show_popup(app: &AppHandle, session: Option<Session>, unlock_prompt: bool) {
    let window = main_window(app);
    let state = app.state::<AppState>();

    state.pinned.store(false, Ordering::SeqCst);
    state.unlock_prompt.store(unlock_prompt, Ordering::SeqCst);
    *state.session.lock().unwrap() = session;

    if let Ok(size) = window.outer_size() {
        if let Some((x, y)) = platform::popup_position(size.width, size.height) {
            let _ = window.set_position(PhysicalPosition::new(x, y));
        }
    }

    let _ = window.emit("popup-opened", current_view(&state));
    let _ = window.show();
    let _ = window.set_focus();
}

fn close_and_restore(app: &AppHandle) {
    let _ = main_window(app).hide();
    let state = app.state::<AppState>();
    state.pinned.store(false, Ordering::SeqCst);
    state.unlock_prompt.store(false, Ordering::SeqCst);
    let session = state.session.lock().unwrap().take();
    if let Some(session) = session {
        platform::restore_focus(session.target);
    }
}

fn lock(app: &AppHandle) {
    let state = app.state::<AppState>();
    // Dropping the vault wipes the key and accounts from its memory.
    *state.vault.lock().unwrap() = None;
    *state.last_fill.lock().unwrap() = None;
    state.pinned.store(false, Ordering::SeqCst);
    state.unlock_prompt.store(false, Ordering::SeqCst);
    let window = main_window(app);
    // Clears anything still typed into a form.
    let _ = window.emit("locked", ());
    let _ = window.hide();
}

/// Locks after inactivity, when Windows locks, and after the PC sleeps. After
/// the last two, it asks for the master password once the user is back.
fn start_auto_lock(app: AppHandle, idle_limit: Duration) {
    std::thread::spawn(move || {
        let mut last_check = SystemTime::now();
        let mut prompt_due = false;
        loop {
            std::thread::sleep(AUTO_LOCK_CHECK);

            let now = SystemTime::now();
            let woke_up = now
                .duration_since(last_check)
                .map_or(true, |gap| gap > SLEEP_GAP);
            last_check = now;

            let idle = platform::idle_time().is_some_and(|idle| idle >= idle_limit);
            let desktop_hidden = platform::session_is_locked();
            if woke_up || idle || desktop_hidden {
                let unlocked = app.state::<AppState>().vault.lock().unwrap().is_some();
                if unlocked {
                    lock(&app);
                }
            }

            prompt_due |= woke_up || platform::lock_screen_is_up();
            if prompt_due && !desktop_hidden {
                prompt_due = false;
                prompt_unlock(&app);
            }
        }
    });
}

fn auto_lock_idle_limit() -> Duration {
    // Lets automated tests avoid a 10 minute wait. Not compiled into release builds.
    #[cfg(debug_assertions)]
    if let Some(seconds) = std::env::var("CRYPASS_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return Duration::from_secs(seconds);
    }
    AUTO_LOCK_IDLE
}

fn back_up_vault(app: &AppHandle) {
    let app = app.clone();
    // Dialogs block, so they can't run on the UI thread.
    std::thread::spawn(move || {
        let vault_path = app.state::<AppState>().path().clone();
        if !vault_path.exists() {
            show_message(&app, "Create your vault first.", MessageDialogKind::Info);
            return;
        }

        let Some(destination) = app
            .dialog()
            .file()
            .set_title("Save vault backup")
            .set_file_name("crypass-backup.crypass")
            .add_filter("Crypass vault", &["crypass"])
            .blocking_save_file()
        else {
            return;
        };

        let result = destination.into_path().map_err(|e| e.to_string()).and_then(|path| {
            crypass_vault::export_backup(&vault_path, &path).map_err(|e| e.to_string())
        });
        match result {
            Ok(()) => show_message(
                &app,
                "Backup saved. It's encrypted and opens with your master password.",
                MessageDialogKind::Info,
            ),
            Err(message) => show_message(
                &app,
                &format!("The backup failed. {message}"),
                MessageDialogKind::Error,
            ),
        }
    });
}

fn show_message(app: &AppHandle, message: &str, kind: MessageDialogKind) {
    app.dialog()
        .message(message)
        .title("Crypass")
        .kind(kind)
        .blocking_show();
}

#[tauri::command]
fn popup_state(state: State<'_, AppState>) -> PopupView {
    current_view(&state)
}

/// Nothing works until a vault exists, so setup opens by itself on first run.
/// The page calls this once it has loaded: a popup shown before then loses
/// focus while the webview starts, which closes it straight away.
#[tauri::command]
fn page_ready(app: AppHandle, state: State<'_, AppState>) {
    if !state.path().exists() {
        show_popup(&app, None, false);
    } else if std::env::args().any(|arg| arg == AUTOSTART_ARG) {
        prompt_unlock(&app);
    }
}

#[tauri::command]
fn cancel(app: AppHandle) {
    close_and_restore(&app);
}

#[tauri::command]
fn set_pinned(state: State<'_, AppState>, pinned: bool) {
    state.pinned.store(pinned, Ordering::SeqCst);
}

// Key derivation is deliberately slow, so these two run off the UI thread and
// don't hold the vault lock while it runs.
#[tauri::command]
async fn create_vault(state: State<'_, AppState>, password: String) -> Result<PopupView, String> {
    let password = Zeroizing::new(password);
    let vault = Vault::create(state.path(), &password).map_err(|e| e.to_string())?;
    *state.vault.lock().unwrap() = Some(vault);
    Ok(current_view(&state))
}

#[tauri::command]
async fn unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<PopupView, String> {
    let password = Zeroizing::new(password);
    let vault = Vault::open(state.path(), &password).map_err(|e| e.to_string())?;
    *state.vault.lock().unwrap() = Some(vault);
    close_if_prompted(&app, &state);
    Ok(current_view(&state))
}

/// The unlock prompt wasn't opened for a field, so there's nothing to pick an
/// account for. Returns whether it closed.
fn close_if_prompted(app: &AppHandle, state: &AppState) -> bool {
    let prompted = state.unlock_prompt.swap(false, Ordering::SeqCst);
    if prompted {
        let _ = main_window(app).hide();
    }
    prompted
}

fn show_again(window: &WebviewWindow) {
    let _ = window.show();
    let _ = window.set_focus();
}

// Windows Hello waits for the user, so its commands run off the UI thread. The
// popup hides meanwhile because it's always on top and would cover Hello's window.
#[tauri::command]
async fn unlock_with_hello(app: AppHandle, state: State<'_, AppState>) -> Result<PopupView, String> {
    let window = main_window(&app);
    let _ = window.hide();
    let opened = platform::hello_secret().map(Zeroizing::new).and_then(|secret| {
        Vault::open_with_quick_unlock(state.path(), &secret).map_err(|e| e.to_string())
    });
    match opened {
        Ok(vault) => {
            *state.vault.lock().unwrap() = Some(vault);
            if !close_if_prompted(&app, &state) {
                show_again(&window);
            }
            Ok(current_view(&state))
        }
        Err(message) => {
            show_again(&window);
            Err(message)
        }
    }
}

#[tauri::command]
async fn enable_hello(app: AppHandle, state: State<'_, AppState>) -> Result<PopupView, String> {
    let window = main_window(&app);
    let _ = window.hide();
    let secret = platform::hello_enrol().map(Zeroizing::new);
    show_again(&window);
    let secret = secret?;
    state.with_vault(|v| v.enable_quick_unlock(&secret))?;
    Ok(current_view(&state))
}

#[tauri::command]
async fn disable_hello(state: State<'_, AppState>) -> Result<PopupView, String> {
    crypass_vault::disable_quick_unlock(state.path()).map_err(|e| e.to_string())?;
    platform::hello_remove();
    Ok(current_view(&state))
}

#[tauri::command]
async fn change_master_password(
    state: State<'_, AppState>,
    current: String,
    new: String,
) -> Result<PopupView, String> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);
    state.with_vault(|v| v.change_password(&current, &new))?;
    Ok(current_view(&state))
}

/// Returns the chosen file's name, or nothing if the dialog was cancelled.
#[tauri::command]
async fn pick_backup(app: AppHandle, state: State<'_, AppState>) -> Result<Option<String>, String> {
    // The dialog takes focus, which must not dismiss the popup behind it.
    state.pinned.store(true, Ordering::SeqCst);
    let window = main_window(&app);
    let Some(file) = app
        .dialog()
        .file()
        .set_title("Choose a Crypass backup")
        .add_filter("Crypass vault", &["crypass", "before-restore", "bak"])
        .set_parent(&window)
        .blocking_pick_file()
    else {
        return Ok(None);
    };

    let path = file.into_path().map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    *state.restore_path.lock().unwrap() = Some(path);
    Ok(Some(name))
}

#[tauri::command]
async fn restore_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<PopupView, String> {
    let password = Zeroizing::new(password);
    let backup = state
        .restore_path
        .lock()
        .unwrap()
        .clone()
        .ok_or("Choose a backup first.")?;
    let vault = crypass_vault::restore_backup(&backup, state.path(), &password)
        .map_err(|e| e.to_string())?;

    *state.vault.lock().unwrap() = Some(vault);
    // Account numbers from the replaced vault mean nothing in this one.
    *state.last_fill.lock().unwrap() = None;
    *state.restore_path.lock().unwrap() = None;
    close_if_prompted(&app, &state);
    Ok(current_view(&state))
}

#[tauri::command]
fn generate_password() -> String {
    crypass_vault::generator::generate(crypass_vault::generator::DEFAULT_LENGTH)
}

#[tauri::command]
fn add_account(
    state: State<'_, AppState>,
    label: String,
    username: String,
    password: String,
) -> Result<PopupView, String> {
    let password = Zeroizing::new(password);
    state.with_vault(|v| v.add(&label, &username, &password))?;
    Ok(current_view(&state))
}

/// An empty password keeps the current one.
#[tauri::command]
fn update_account(
    state: State<'_, AppState>,
    id: u32,
    label: String,
    username: String,
    password: String,
) -> Result<PopupView, String> {
    let password = Zeroizing::new(password);
    let new_password = (!password.is_empty()).then_some(password.as_str());
    state.with_vault(|v| v.update(id, &label, &username, new_password))?;
    Ok(current_view(&state))
}

#[tauri::command]
fn remove_site(state: State<'_, AppState>, id: u32, key: String) -> Result<PopupView, String> {
    state.with_vault(|v| v.remove_match(id, &key))?;
    Ok(current_view(&state))
}

#[tauri::command]
fn delete_account(state: State<'_, AppState>, id: u32) -> Result<PopupView, String> {
    state.with_vault(|v| v.remove(id))?;
    Ok(current_view(&state))
}

// Async so waiting on focus and typing run off the UI thread.
#[tauri::command]
async fn fill(
    app: AppHandle,
    state: State<'_, AppState>,
    account_id: u32,
    field: Field,
    confirmed: bool,
) -> Result<FillOutcome, String> {
    let session = state
        .session
        .lock()
        .unwrap()
        .clone()
        .ok_or("No window to fill. Click a field and press the shortcut again.")?;
    let target = session.target;
    if platform::target_is_elevated(target) {
        return Err(
            "This app is running as administrator, so Windows blocks Crypass from typing into it."
                .into(),
        );
    }

    let (value, learn) = {
        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().ok_or("Crypass is locked.")?;
        let entry = vault
            .entry(account_id)
            .ok_or("That account no longer exists.")?;

        let decision = matching::check(&entry.matches, session.key.as_deref());
        if !confirmed {
            if let Some(message) = confirmation_message(&entry.label, &session, field, &decision) {
                return Ok(FillOutcome::Confirm { message });
            }
        }

        let value = Zeroizing::new(match field {
            Field::Username => entry.username.clone(),
            Field::Password => entry.password.clone(),
        });
        (value, decision.learn)
    };
    if value.is_empty() {
        return Err("This account has no email saved.".into());
    }

    let window = main_window(&app);
    let result = window
        .hide()
        .map_err(|e| e.to_string())
        .and_then(|_| type_into(&session, &value));

    match result {
        Ok(()) => {
            state.session.lock().unwrap().take();
            *state.last_fill.lock().unwrap() = Some(LastFill {
                account_id,
                field,
                target,
                at: Instant::now(),
            });
            if let Some(key) = learn {
                // The fill already worked. If this save fails, the site is just
                // learned on a later fill.
                let _ = state.with_vault(|v| v.add_match(account_id, &key));
            }
            Ok(FillOutcome::Done)
        }
        Err(message) => {
            // Bring the popup back because it's the only place to show the error.
            let _ = window.show();
            let _ = window.set_focus();
            Err(message)
        }
    }
}

fn confirmation_message(
    label: &str,
    session: &Session,
    field: Field,
    decision: &matching::Decision,
) -> Option<String> {
    let again = "Press Enter again to fill anyway.";
    match &decision.warning {
        Some(Warning::DifferentSite { saved }) => Some(format!(
            "{label} is saved for {saved}, not this site. Check the address. {again}"
        )),
        Some(Warning::UnconfirmedSite { saved }) => Some(format!(
            "{label} is saved for {saved}, and this site can't be confirmed. {again}"
        )),
        None if field == Field::Password && session.is_password == Some(false) => Some(format!(
            "This isn't a password field, so the password would be visible. {again}"
        )),
        None => None,
    }
}

fn type_into(session: &Session, value: &str) -> Result<(), String> {
    if !platform::wait_for_keys_released() {
        return Err("Nothing was typed because a key was still held down.".into());
    }
    if !platform::restore_focus(session.target) {
        return Err("Nothing was typed because the original window couldn't get focus back.".into());
    }
    if !site_is_unchanged(session) {
        return Err(
            "Nothing was typed because the page changed. Press Esc, check the address, and open Crypass again."
                .into(),
        );
    }
    platform::type_text(session.target, value)
}

/// The page may have navigated while the popup was open, and a secret must only
/// reach the site the user was shown.
fn site_is_unchanged(session: &Session) -> bool {
    let Some(expected) = session.key.as_deref() else {
        return true;
    };
    let process = platform::target_process_name(session.target);
    for attempt in 0..RECHECK_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(RECHECK_DELAY);
        }
        let focus = platform::inspect_focus();
        let key = matching::context_key(process.as_deref(), focus.url.as_deref());
        if key.as_deref() == Some(expected) {
            return true;
        }
    }
    false
}

fn toggle_autostart(app: &AppHandle, item: &CheckMenuItem<tauri::Wry>) {
    let enable = item.is_checked().unwrap_or(false);
    let manager = app.autolaunch();
    let result = if enable {
        manager.enable()
    } else {
        manager.disable()
    };
    if let Err(error) = result {
        // Show what's really set, not what was clicked.
        let _ = item.set_checked(!enable);
        let app = app.clone();
        std::thread::spawn(move || {
            show_message(
                &app,
                &format!("Couldn't change the startup setting. {error}"),
                MessageDialogKind::Error,
            );
        });
    }
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Crypass", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let backup = MenuItem::with_id(app, "backup", "Back Up Vault...", true, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "Start with Windows",
        true,
        app.autolaunch().is_enabled().unwrap_or(false),
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit Crypass", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock_item, &backup, &autostart, &quit])?;
    let mut tray = TrayIconBuilder::new()
        .tooltip("Crypass (Ctrl+Shift+Space)")
        .menu(&menu)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            // No fill target: the foreground window is the taskbar here.
            "open" => show_popup(app, None, false),
            "lock" => lock(app),
            "backup" => back_up_vault(app),
            "autostart" => toggle_autostart(app, &autostart),
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Lets automated tests use a throwaway vault. Not compiled into release builds.
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var("CRYPASS_VAULT_PATH") {
        return Ok(path.into());
    }
    let dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("vault.crypass"))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG]),
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state() == ShortcutState::Pressed {
                        on_shortcut(app);
                    }
                })
                .build(),
        )
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            popup_state,
            page_ready,
            cancel,
            set_pinned,
            create_vault,
            unlock,
            add_account,
            update_account,
            remove_site,
            delete_account,
            fill,
            unlock_with_hello,
            enable_hello,
            disable_hello,
            change_master_password,
            pick_backup,
            restore_backup,
            generate_password
        ])
        .on_window_event(|window, event| {
            // Clicking elsewhere dismisses the popup. Focus stays where the user clicked.
            if let WindowEvent::Focused(false) = event {
                let state = window.state::<AppState>();
                let stays_open = state.pinned.load(Ordering::SeqCst)
                    || state.unlock_prompt.load(Ordering::SeqCst);
                if !stays_open {
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            let handle = app.handle();
            let path = vault_path(handle)?;
            let _ = handle.state::<AppState>().vault_path.set(path);

            setup_tray(handle)?;
            app.global_shortcut().register(SHORTCUT).map_err(|e| {
                format!("Couldn't register {SHORTCUT}; another app may be using it: {e}")
            })?;
            start_auto_lock(handle.clone(), auto_lock_idle_limit());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Crypass");
}
