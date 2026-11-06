//! Placeholder until the Linux backend exists.

const MESSAGE: &str = "Filling is not implemented on this platform yet.";

#[derive(Clone, Copy, PartialEq)]
pub struct Target;

#[derive(Clone, Default)]
pub struct FocusInfo {
    pub is_password: Option<bool>,
    pub url: Option<String>,
}

pub fn inspect_focus() -> FocusInfo {
    FocusInfo::default()
}

pub fn target_process_name(_target: Target) -> Option<String> {
    None
}

pub fn capture_target() -> Option<Target> {
    None
}

pub fn target_title(_target: Target) -> String {
    String::new()
}

pub fn target_is_elevated(_target: Target) -> bool {
    false
}

pub fn idle_time() -> Option<std::time::Duration> {
    None
}

pub fn session_is_locked() -> bool {
    false
}

pub fn lock_screen_is_up() -> bool {
    false
}

pub fn hello_enrol() -> Result<Vec<u8>, String> {
    Err("Windows Hello isn't available on this platform.".into())
}

pub fn hello_secret() -> Result<Vec<u8>, String> {
    Err("Windows Hello isn't available on this platform.".into())
}

pub fn hello_remove() {}

pub fn popup_position(_width: u32, _height: u32) -> Option<(i32, i32)> {
    None
}

pub fn restore_focus(_target: Target) -> bool {
    false
}

pub fn wait_for_keys_released() -> bool {
    false
}

pub fn type_text(_target: Target, _text: &str) -> Result<(), String> {
    Err(MESSAGE.into())
}
