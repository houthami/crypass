use std::mem::size_of;
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows::core::{w, HSTRING, PWSTR};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, POINT};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfoEx, WTSINFOEXW, WTS_CURRENT_SESSION,
    WTS_SESSIONSTATE_LOCK,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationValuePattern,
    UIA_DocumentControlTypeId, UIA_ValuePatternId,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetLastInputInfo, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, LASTINPUTINFO, VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU,
    VK_RETURN, VK_RWIN, VK_SHIFT, VK_SPACE, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetCursorPos, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindow,
    SetForegroundWindow,
};

/// The window that had focus when the shortcut was pressed.
#[derive(Clone, Copy, PartialEq)]
pub struct Target(isize);

impl Target {
    fn hwnd(self) -> HWND {
        HWND(self.0 as *mut _)
    }
}

pub fn capture_target() -> Option<Target> {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_invalid() {
        return None;
    }

    // Right after launch, the foreground window can be Crypass's own hidden
    // window. That must never be a fill target.
    let mut process_id = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    if process_id == unsafe { GetCurrentProcessId() } {
        return None;
    }
    Some(Target(hwnd.0 as isize))
}

pub fn target_title(target: Target) -> String {
    let mut buffer = [0u16; 256];
    let length = unsafe { GetWindowTextW(target.hwnd(), &mut buffer) };
    String::from_utf16_lossy(&buffer[..length.max(0) as usize])
}

/// Windows silently blocks input sent to apps running as administrator, so
/// these are detected up front. If elevation can't be read, assume elevated:
/// an unelevated process is normally denied access to an elevated app's token.
pub fn target_is_elevated(target: Target) -> bool {
    unsafe {
        let mut process_id = 0;
        GetWindowThreadProcessId(target.hwnd(), Some(&mut process_id));
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) else {
            return true;
        };

        let mut token = HANDLE::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        let mut elevated = true;
        if opened {
            let mut info = TOKEN_ELEVATION::default();
            let mut returned = 0;
            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut info as *mut _ as *mut _),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .is_ok()
            {
                elevated = info.TokenIsElevated != 0;
            }
            let _ = CloseHandle(token);
        }
        let _ = CloseHandle(process);
        elevated
    }
}

/// The program behind the target window, such as `chrome.exe`.
pub fn target_process_name(target: Target) -> Option<String> {
    unsafe {
        let mut process_id = 0;
        GetWindowThreadProcessId(target.hwnd(), Some(&mut process_id));
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id).ok()?;

        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(process);
        result.ok()?;

        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        path.rsplit('\\').next().map(str::to_string)
    }
}

/// What UI Automation reports about the focused control. Every part is
/// optional because not all apps expose it.
#[derive(Clone, Default)]
pub struct FocusInfo {
    pub is_password: Option<bool>,
    pub url: Option<String>,
}

/// Some apps answer slowly or never, and the shortcut mustn't hang on them.
const INSPECT_TIMEOUT: Duration = Duration::from_millis(500);

pub fn inspect_focus() -> FocusInfo {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(read_focus().unwrap_or_default());
    });
    receiver.recv_timeout(INSPECT_TIMEOUT).unwrap_or_default()
}

fn read_focus() -> windows::core::Result<FocusInfo> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        let automation: IUIAutomation =
            CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?;
        let focused = automation.GetFocusedElement()?;
        Ok(FocusInfo {
            is_password: focused.CurrentIsPassword().ok().map(|value| value.as_bool()),
            url: page_address(&automation, &focused),
        })
    }
}

/// Browsers publish the address of a page as the value of its document. The
/// nearest document is used, so a field in an embedded frame reports the frame's
/// own site: that's the site that would receive the password.
unsafe fn page_address(
    automation: &IUIAutomation,
    focused: &IUIAutomationElement,
) -> Option<String> {
    const MAX_DEPTH: usize = 64;
    let walker = automation.ControlViewWalker().ok()?;
    let mut element = focused.clone();
    for _ in 0..MAX_DEPTH {
        if element.CurrentControlType().ok()? == UIA_DocumentControlTypeId {
            let pattern: IUIAutomationValuePattern =
                element.GetCurrentPatternAs(UIA_ValuePatternId).ok()?;
            let value = pattern.CurrentValue().ok()?.to_string();
            return (!value.is_empty()).then_some(value);
        }
        element = walker.GetParentElement(&element).ok()?;
    }
    None
}

/// How long since the last keyboard or mouse input anywhere on the PC.
pub fn idle_time() -> Option<Duration> {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        if !GetLastInputInfo(&mut info).as_bool() {
            return None;
        }
        // Both counters wrap around after about 49 days.
        let idle_ms = GetTickCount().wrapping_sub(info.dwTime);
        Some(Duration::from_millis(idle_ms as u64))
    }
}

/// True while the input desktop can't be opened: the lock screen, and also
/// Windows security prompts. Locking the vault during a prompt is the safe side.
pub fn session_is_locked() -> bool {
    unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP) {
            Ok(desktop) => {
                let _ = CloseDesktop(desktop);
                false
            }
            Err(_) => true,
        }
    }
}

/// True only for the Windows lock screen. Unlike `session_is_locked`, security
/// prompts don't count, so they don't look like the user coming back to the PC.
pub fn lock_screen_is_up() -> bool {
    unsafe {
        let mut buffer = PWSTR::null();
        let mut returned = 0;
        if WTSQuerySessionInformationW(
            None,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut returned,
        )
        .is_err()
        {
            return false;
        }

        let info = &*(buffer.0 as *const WTSINFOEXW);
        let locked =
            info.Level == 1 && info.Data.WTSInfoExLevel1.SessionFlags as u32 == WTS_SESSIONSTATE_LOCK;
        WTSFreeMemory(buffer.0 as *mut _);
        locked
    }
}

const HELLO_KEY_NAME: &str = "Crypass vault unlock";
/// What Windows Hello signs. RSA signatures of the same data are always the same,
/// so the signature can act as a secret that only appears after a Hello check.
const HELLO_CHALLENGE: &[u8] = b"crypass-quick-unlock-v1";

/// Creates a new Hello key, replacing any earlier one, and returns its secret.
pub fn hello_enrol() -> Result<Vec<u8>, String> {
    let supported = KeyCredentialManager::IsSupportedAsync()
        .and_then(|operation| operation.get())
        .unwrap_or(false);
    if !supported {
        return Err(
            "Windows Hello isn't set up on this PC. Set up a face, fingerprint or PIN in Windows Settings first."
                .into(),
        );
    }
    bring_hello_forward();
    let result = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(HELLO_KEY_NAME),
        KeyCredentialCreationOption::ReplaceExisting,
    )
    .and_then(|operation| operation.get())
    .map_err(hello_error)?;
    check_hello_status(result.Status().map_err(hello_error)?)?;
    sign_challenge(&result.Credential().map_err(hello_error)?)
}

/// Asks Windows Hello for the secret made by `hello_enrol`.
pub fn hello_secret() -> Result<Vec<u8>, String> {
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(HELLO_KEY_NAME))
        .and_then(|operation| operation.get())
        .map_err(hello_error)?;
    check_hello_status(result.Status().map_err(hello_error)?)?;
    bring_hello_forward();
    sign_challenge(&result.Credential().map_err(hello_error)?)
}

pub fn hello_remove() {
    if let Ok(action) = KeyCredentialManager::DeleteAsync(&HSTRING::from(HELLO_KEY_NAME)) {
        let _ = action.get();
    }
}

fn sign_challenge(credential: &KeyCredential) -> Result<Vec<u8>, String> {
    let challenge = CryptographicBuffer::CreateFromByteArray(HELLO_CHALLENGE).map_err(hello_error)?;
    let result = credential
        .RequestSignAsync(&challenge)
        .and_then(|operation| operation.get())
        .map_err(hello_error)?;
    check_hello_status(result.Status().map_err(hello_error)?)?;

    let signature = result.Result().map_err(hello_error)?;
    let mut bytes = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(hello_error)?;
    Ok(bytes.to_vec())
}

fn check_hello_status(status: KeyCredentialStatus) -> Result<(), String> {
    match status {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => {
            Err("Windows Hello was cancelled. You can still use your master password.".into())
        }
        KeyCredentialStatus::NotFound => Err(
            "The Windows Hello key is gone, for example after a PIN reset. Use your master password, then turn Hello on again."
                .into(),
        ),
        _ => Err("Windows Hello didn't work. You can still use your master password.".into()),
    }
}

fn hello_error(error: windows::core::Error) -> String {
    format!("Windows Hello didn't work: {}", error.message())
}

/// A desktop app's Hello window can open behind everything else, leaving only a
/// flashing taskbar icon, so this brings it to the front once it appears.
fn bring_hello_forward() {
    std::thread::spawn(|| {
        for _ in 0..50 {
            sleep(Duration::from_millis(100));
            let window = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), None) };
            if let Ok(window) = window {
                unsafe {
                    let _ = SetForegroundWindow(window);
                }
                return;
            }
        }
    });
}

/// Top-left position (physical pixels) that places the popup at the mouse
/// while keeping it fully inside the monitor's work area.
pub fn popup_position(width: u32, height: u32) -> Option<(i32, i32)> {
    unsafe {
        let mut cursor = POINT::default();
        GetCursorPos(&mut cursor).ok()?;

        let monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut info).as_bool() {
            return Some((cursor.x, cursor.y));
        }

        let area = info.rcWork;
        let x = cursor.x.min(area.right - width as i32).max(area.left);
        let y = cursor.y.min(area.bottom - height as i32).max(area.top);
        Some((x, y))
    }
}

/// Returns focus to the target and waits until Windows confirms it.
pub fn restore_focus(target: Target) -> bool {
    let hwnd = target.hwnd();
    unsafe {
        if !IsWindow(Some(hwnd)).as_bool() {
            return false;
        }
        let _ = SetForegroundWindow(hwnd);
        let deadline = Instant::now() + Duration::from_millis(800);
        while Instant::now() < deadline {
            if GetForegroundWindow() == hwnd {
                // Let the app finish re-activating its text field.
                sleep(Duration::from_millis(60));
                return GetForegroundWindow() == hwnd;
            }
            sleep(Duration::from_millis(10));
        }
    }
    false
}

/// Keys still held from the popup would combine with the typed text, so a
/// held Ctrl could trigger app shortcuts instead of typing.
pub fn wait_for_keys_released() -> bool {
    const KEYS: [VIRTUAL_KEY; 8] = [
        VK_CONTROL, VK_SHIFT, VK_MENU, VK_LWIN, VK_RWIN, VK_RETURN, VK_TAB, VK_SPACE,
    ];
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let held = KEYS
            .iter()
            .any(|key| unsafe { GetAsyncKeyState(key.0 as i32) } as u16 & 0x8000 != 0);
        if !held {
            return true;
        }
        sleep(Duration::from_millis(10));
    }
    false
}

/// Types text as Unicode key events. It doesn't use the clipboard, doesn't
/// depend on the keyboard layout, and stops as soon as focus leaves the target
/// so a secret is never typed into a window that took over.
pub fn type_text(target: Target, text: &str) -> Result<(), String> {
    for unit in text.encode_utf16() {
        if unsafe { GetForegroundWindow() } != target.hwnd() {
            return Err(
                "Stopped typing because the focus changed. Part of the value may have been entered."
                    .into(),
            );
        }

        let inputs = [unicode_input(unit, false), unicode_input(unit, true)];
        let sent = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            return Err("Windows blocked the typed input.".into());
        }
        sleep(Duration::from_millis(3));
    }
    Ok(())
}

fn unicode_input(unit: u16, key_up: bool) -> INPUT {
    let mut flags = KEYEVENTF_UNICODE;
    if key_up {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: unit,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}
