const { invoke } = window.__TAURI__.core;

function minimizeWindow() { invoke('minimize_window'); }
function closeWindow() { invoke('close_window'); }

function showPage(p) {
    document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
    const pg = document.getElementById('page-' + p);
    if (pg) pg.classList.add('active');

    const shopBtn = document.getElementById('btn-shop');
    if (shopBtn) shopBtn.classList.toggle('active', p === 'store');

    const userBtn = document.getElementById('btn-user');
    if (userBtn) userBtn.classList.toggle('active', p === 'profile');

    const playWrap = document.getElementById('playWrap');
    const arranging = document.getElementById('arrangingBox');
    if (playWrap && arranging) {
        const onTeam = p === 'team';
        playWrap.style.display = onTeam ? 'none' : 'block';
        arranging.style.display = onTeam ? 'flex' : 'none';
    }
}
