const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const el = (id) => document.getElementById(id);

const views = {
  setup: el("view-setup"),
  unlock: el("view-unlock"),
  picker: el("view-picker"),
  form: el("view-form"),
  settings: el("view-settings"),
  password: el("view-password"),
  restore: el("view-restore"),
};

// Screens that stay open if the user switches away, for example to copy a value.
const PINNED_VIEWS = new Set(["form", "settings", "password", "restore"]);
const SECRET_INPUTS = [
  "setup-password",
  "setup-confirm",
  "unlock-password",
  "form-password",
  "password-current",
  "password-new",
  "password-confirm",
  "restore-password",
];

let currentView = null;
let accounts = [];
let matches = [];
let selected = 0;
let field = "username";
let busy = false;
let editingId = null;
let deleteArmed = false;
// Set after a warning, so a second Enter on the same choice goes ahead.
let pendingConfirm = null;
let helloEnabled = false;
// The screen to go back to if a restore is cancelled.
let restoreFrom = "unlock";

function showView(name) {
  currentView = name;
  for (const [key, view] of Object.entries(views)) view.hidden = key !== name;
  // Keep the popup open during form entry so values can be copied from elsewhere.
  invoke("set_pinned", { pinned: PINNED_VIEWS.has(name) });
}

function showMessage(element, message) {
  element.textContent = message;
  element.hidden = !message;
}

function clearSecrets() {
  for (const id of SECRET_INPUTS) el(id).value = "";
  el("form-password").type = "password";
  el("form-show").checked = false;
}

function applyState(view) {
  accounts = view.accounts;
  helloEnabled = view.hello_enabled;
  el("unlock-hello").hidden = !helloEnabled;
  el("settings-hello").textContent = helloEnabled
    ? "Turn off Windows Hello"
    : "Turn on Windows Hello";
}

// Applies the state Rust reports and resets every screen to its starting point.
function render(view) {
  applyState(view);
  clearSecrets();
  showMessage(el("setup-error"), "");
  showMessage(el("unlock-error"), "");
  showMessage(el("error"), "");
  el("setup-hint").textContent = `Use at least ${view.min_password_chars} characters.`;
  el("target").textContent = view.target_title || "No window selected";
  search.value = "";
  field = view.initial_field;
  pendingConfirm = null;
  selected = Math.max(accounts.findIndex((a) => a.id === view.selected_id), 0);

  if (view.status === "setup") {
    showView("setup");
    el("setup-password").focus();
  } else if (view.status === "locked") {
    showView("unlock");
    el("unlock-password").focus();
  } else {
    showPicker();
  }
}

function showPicker() {
  showView("picker");
  clearSecrets();
  renderField();
  renderList();
  search.focus();
}

function renderField() {
  el("field-username").classList.toggle("active", field === "username");
  el("field-password").classList.toggle("active", field === "password");
}

function renderList() {
  const query = search.value.trim().toLowerCase();
  matches = accounts.filter(
    (a) =>
      a.label.toLowerCase().includes(query) ||
      a.username.toLowerCase().includes(query),
  );
  selected = Math.min(selected, Math.max(matches.length - 1, 0));
  el("edit").disabled = matches.length === 0;

  list.replaceChildren(
    ...matches.map((account, index) => {
      const item = document.createElement("li");
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(index === selected));
      item.classList.toggle("selected", index === selected);

      const label = document.createElement("span");
      label.className = "account-label";
      label.textContent = account.label;
      if (account.matched) {
        const matched = document.createElement("span");
        matched.className = "account-matched";
        matched.textContent = "Saved for this site";
        label.append(matched);
      }
      const username = document.createElement("span");
      username.className = "account-username";
      username.textContent = account.username;
      item.append(label, username);

      item.addEventListener("mousedown", (event) => {
        // Keep focus in the search box so the popup doesn't lose it mid-click.
        event.preventDefault();
        selected = index;
        fill();
      });
      return item;
    }),
  );

  if (matches.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent =
      accounts.length === 0 ? "No accounts yet. Press Ctrl+N to add one." : "No accounts found";
    list.append(empty);
  }
  list.children[selected]?.scrollIntoView({ block: "nearest" });
}

function clearConfirm() {
  if (pendingConfirm) {
    pendingConfirm = null;
    showMessage(el("error"), "");
  }
}

async function fill() {
  const account = matches[selected];
  if (!account || busy) return;

  const confirmed = pendingConfirm?.id === account.id && pendingConfirm?.field === field;
  pendingConfirm = null;
  busy = true;
  showMessage(el("error"), "");
  try {
    const outcome = await invoke("fill", { accountId: account.id, field, confirmed });
    if (outcome.status === "confirm") {
      pendingConfirm = { id: account.id, field };
      showMessage(el("error"), outcome.message);
    }
  } catch (message) {
    showMessage(el("error"), String(message));
    search.focus();
  } finally {
    busy = false;
  }
}

function openForm(account) {
  editingId = account ? account.id : null;
  deleteArmed = false;
  el("form-title").textContent = account ? "Edit account" : "Add account";
  el("form-label").value = account ? account.label : "";
  el("form-username").value = account ? account.username : "";
  el("form-password").placeholder = account ? "Leave blank to keep the current password" : "";
  el("form-delete").hidden = !account;
  el("form-delete").textContent = "Delete";
  showMessage(el("form-error"), "");
  renderSites(account);
  showView("form");
  el("form-label").focus();
}

function renderSites(account) {
  const sites = account ? account.sites : [];
  el("form-sites-box").hidden = sites.length === 0;
  el("form-sites").replaceChildren(
    ...sites.map((site) => {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.className = "site-label";
      label.textContent = site.label;
      label.title = site.label;

      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove ${site.label}`);
      remove.addEventListener("click", () => removeSite(account.id, site.key));

      item.append(label, remove);
      return item;
    }),
  );
}

// Leaves the rest of the form as it is, so unsaved edits aren't lost.
function removeSite(id, key) {
  run(el("form-error"), async () => {
    const view = await invoke("remove_site", { id, key });
    accounts = view.accounts;
    renderSites(accounts.find((a) => a.id === id));
    el("form-label").focus();
  });
}

// Runs a slow or failable action once, showing any error on the current screen.
async function run(errorElement, action) {
  if (busy) return;
  busy = true;
  showMessage(errorElement, "");
  try {
    await action();
  } catch (message) {
    showMessage(errorElement, String(message));
  } finally {
    busy = false;
  }
}

function saved(view) {
  applyState(view);
  showPicker();
}

function showSettings(note = "") {
  showView("settings");
  clearSecrets();
  showMessage(el("settings-error"), "");
  showMessage(el("settings-note"), note);
  el("settings-password").focus();
}

function openPasswordForm() {
  showMessage(el("password-error"), "");
  showView("password");
  el("password-current").focus();
}

function focusCurrentView() {
  const first = { setup: "setup-password", unlock: "unlock-password", settings: "settings-password" };
  el(first[currentView]).focus();
}

function startRestore(errorElement) {
  run(errorElement, async () => {
    const name = await invoke("pick_backup");
    if (!name) {
      showView(currentView);
      focusCurrentView();
      return;
    }
    restoreFrom = currentView;
    el("restore-file").textContent = name;
    el("restore-warning").hidden = restoreFrom === "setup";
    showMessage(el("restore-error"), "");
    showView("restore");
    el("restore-password").focus();
  });
}

function cancelRestore() {
  el("restore-password").value = "";
  if (restoreFrom === "settings") {
    showSettings();
  } else {
    showView(restoreFrom);
    focusCurrentView();
  }
}

function unlockWithHello() {
  if (!helloEnabled) return;
  run(el("unlock-error"), async () => render(await invoke("unlock_with_hello")));
}

function toggleHello() {
  const command = helloEnabled ? "disable_hello" : "enable_hello";
  showMessage(el("settings-note"), "");
  run(el("settings-error"), async () => {
    const view = await invoke(command);
    applyState(view);
    showMessage(
      el("settings-note"),
      helloEnabled ? "Windows Hello can now unlock Crypass." : "Windows Hello is off.",
    );
  });
}

function generatePassword() {
  run(el("form-error"), async () => {
    el("form-password").value = await invoke("generate_password");
    // A new password should be seen before it's saved.
    el("form-password").type = "text";
    el("form-show").checked = true;
  });
}

views.setup.addEventListener("submit", (event) => {
  event.preventDefault();
  const password = el("setup-password").value;
  if (password !== el("setup-confirm").value) {
    showMessage(el("setup-error"), "The passwords don't match.");
    return;
  }
  run(el("setup-error"), async () => render(await invoke("create_vault", { password })));
});

views.unlock.addEventListener("submit", (event) => {
  event.preventDefault();
  const input = el("unlock-password");
  run(el("unlock-error"), async () => {
    try {
      render(await invoke("unlock", { password: input.value }));
    } catch (message) {
      input.value = "";
      input.focus();
      throw message;
    }
  });
});

views.form.addEventListener("submit", (event) => {
  event.preventDefault();
  const fields = {
    label: el("form-label").value,
    username: el("form-username").value,
    password: el("form-password").value,
  };
  run(el("form-error"), async () => {
    saved(
      editingId === null
        ? await invoke("add_account", fields)
        : await invoke("update_account", { id: editingId, ...fields }),
    );
  });
});

el("form-delete").addEventListener("click", () => {
  if (!deleteArmed) {
    deleteArmed = true;
    el("form-delete").textContent = "Confirm delete";
    return;
  }
  run(el("form-error"), async () => saved(await invoke("delete_account", { id: editingId })));
});

views.password.addEventListener("submit", (event) => {
  event.preventDefault();
  const current = el("password-current").value;
  const replacement = el("password-new").value;
  if (replacement !== el("password-confirm").value) {
    showMessage(el("password-error"), "The new passwords don't match.");
    return;
  }
  const hadHello = helloEnabled;
  run(el("password-error"), async () => {
    applyState(await invoke("change_master_password", { current, new: replacement }));
    const again = hadHello ? " Windows Hello was turned off, so turn it on again to keep using it." : "";
    showSettings(`Master password changed.${again} Save a new backup.`);
  });
});

views.restore.addEventListener("submit", (event) => {
  event.preventDefault();
  const input = el("restore-password");
  run(el("restore-error"), async () => {
    try {
      render(await invoke("restore_backup", { password: input.value }));
    } catch (message) {
      input.value = "";
      input.focus();
      throw message;
    }
  });
});

el("setup-restore").addEventListener("click", () => startRestore(el("setup-error")));
el("unlock-restore").addEventListener("click", () => startRestore(el("unlock-error")));
el("unlock-hello").addEventListener("click", unlockWithHello);
el("settings").addEventListener("click", () => showSettings());
el("settings-password").addEventListener("click", openPasswordForm);
el("settings-hello").addEventListener("click", toggleHello);
el("settings-restore").addEventListener("click", () => startRestore(el("settings-error")));
el("settings-back").addEventListener("click", showPicker);
el("password-cancel").addEventListener("click", () => showSettings());
el("restore-cancel").addEventListener("click", cancelRestore);
el("form-generate").addEventListener("click", generatePassword);

el("form-show").addEventListener("change", (event) => {
  el("form-password").type = event.target.checked ? "text" : "password";
});

el("form-cancel").addEventListener("click", showPicker);
el("add").addEventListener("click", () => openForm(null));
el("edit").addEventListener("click", () => {
  if (matches[selected]) openForm(matches[selected]);
});

const search = el("search");
const list = el("list");

search.addEventListener("input", () => {
  selected = 0;
  clearConfirm();
  renderList();
});

function handlePickerKey(event) {
  const key = event.key.toLowerCase();
  if (event.ctrlKey && key === "n") {
    event.preventDefault();
    openForm(null);
    return;
  }
  if (event.ctrlKey && key === "e") {
    event.preventDefault();
    if (matches[selected]) openForm(matches[selected]);
    return;
  }
  if (event.ctrlKey && key === ",") {
    event.preventDefault();
    showSettings();
    return;
  }

  switch (event.key) {
    case "ArrowDown":
    case "ArrowUp":
      event.preventDefault();
      if (matches.length > 0) {
        const step = event.key === "ArrowDown" ? 1 : -1;
        selected = (selected + step + matches.length) % matches.length;
        clearConfirm();
        renderList();
      }
      break;
    case "Tab":
      event.preventDefault();
      field = field === "username" ? "password" : "username";
      clearConfirm();
      renderField();
      break;
    case "Enter":
      if (event.target.tagName === "BUTTON") break;
      event.preventDefault();
      if (!event.repeat) fill();
      break;
  }
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.preventDefault();
    if (busy) return;
    if (currentView === "form" || currentView === "settings") showPicker();
    else if (currentView === "password") showSettings();
    else if (currentView === "restore") cancelRestore();
    else invoke("cancel");
    return;
  }
  const key = event.key.toLowerCase();
  if (currentView === "unlock" && event.ctrlKey && key === "h") {
    event.preventDefault();
    unlockWithHello();
    return;
  }
  if (currentView === "form" && event.ctrlKey && key === "g") {
    event.preventDefault();
    generatePassword();
    return;
  }
  if (currentView === "picker") handlePickerKey(event);
});

listen("popup-opened", ({ payload }) => render(payload));
listen("locked", () => {
  clearSecrets();
  accounts = [];
  matches = [];
  list.replaceChildren();
  search.value = "";
  el("form-label").value = "";
  el("form-username").value = "";
});

// The shortcut can open the popup before the listeners above are ready.
invoke("popup_state").then((view) => {
  render(view);
  invoke("page_ready");
});
