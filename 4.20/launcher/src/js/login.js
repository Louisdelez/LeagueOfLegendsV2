function doLogin() {
    const user = document.getElementById('login-username');
    _applyUsername(user);
    _enterMainClient();
}

function doRegister() {
    const user = document.getElementById('register-username');
    _applyUsername(user);
    _enterMainClient();
}

function showRegister() {
    document.querySelector('[data-panel="login"]').style.display = 'none';
    document.querySelector('[data-panel="register"]').style.display = 'flex';
}

function showLogin() {
    document.querySelector('[data-panel="register"]').style.display = 'none';
    document.querySelector('[data-panel="login"]').style.display = 'flex';
}

function _applyUsername(input) {
    if (!input || !input.value.trim()) return;
    const display = document.getElementById('summoner-name-display');
    if (display) display.textContent = input.value.trim();
}

function _enterMainClient() {
    invoke('resize_to_main').finally(() => {
        const screen = document.getElementById('login-screen');
        if (screen) screen.classList.add('hidden');
    });
}
