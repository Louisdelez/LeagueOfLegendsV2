const { invoke } = window.__TAURI__.core;
let champions=[], spells=[], selectedMap=11;

async function init() {
    try {
        champions = await invoke('get_champions');
        spells = await invoke('get_summoner_spells');
        populateSelects();
    } catch(e) { console.error(e); }
}

function populateSelects() {
    const c = document.getElementById('champion');
    c.innerHTML = '';
    champions.forEach(ch => c.appendChild(new Option(ch.display_name, ch.name)));
    c.value = 'Ezreal';
    const s1 = document.getElementById('spell1'), s2 = document.getElementById('spell2');
    s1.innerHTML = ''; s2.innerHTML = '';
    spells.forEach(s => { s1.appendChild(new Option(s.display_name, s.name)); s2.appendChild(new Option(s.display_name, s.name)); });
    s1.value = 'SummonerFlash'; s2.value = 'SummonerHeal';
}

function showPage(p) {
    document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
    const pg = document.getElementById('page-'+p);
    if(pg) pg.classList.add('active');
    const n = document.getElementById('player-name');
    if(n) document.getElementById('summoner-name-display').textContent = n.value||'Player1';
}

function selectGT(el) { document.querySelectorAll('.gt-item').forEach(e=>e.classList.remove('active')); el.classList.add('active'); }
function selectPM(el,mode) { el.parentElement.querySelectorAll('.pm-item').forEach(e=>e.classList.remove('active')); el.classList.add('active'); }
function selectMapItem(el,id) {
    el.parentElement.querySelectorAll('.pm-item').forEach(e=>e.classList.remove('active'));
    el.classList.add('active');
    selectedMap = id;
    const info = {11:['Summoner\'s Rift','5v5 — Destroy the enemy Nexus.'],10:['Twisted Treeline','3v3 — Fast-paced battles.'],12:['Howling Abyss','ARAM — One lane, all random.']}[id]||['',''];
    document.getElementById('preview-title').textContent = info[0];
    document.getElementById('preview-desc').textContent = info[1];
}

function setStatus(m,err) { const e=document.getElementById('status'); if(e){e.textContent=m; e.style.color=err?'#FF4444':'#0AC8B9';} }

async function launchGame() {
    const btn = document.getElementById('launch-btn');
    btn.disabled = true;
    setStatus('Starting server and game...');
    try {
        const r = await invoke('launch_game', {
            playerName: document.getElementById('player-name').value||'Player1',
            champion: document.getElementById('champion').value,
            mapId: selectedMap,
            summoner1: document.getElementById('spell1').value,
            summoner2: document.getElementById('spell2').value,
            skin: 0,
            minionsEnabled: document.getElementById('minions').checked,
            cooldownsEnabled: document.getElementById('cooldowns').checked,
            manaEnabled: document.getElementById('mana').checked,
        });
        setStatus(r);
        setTimeout(()=>{btn.disabled=false;setStatus('');},15000);
    } catch(e) { setStatus('Error: '+e,true); btn.disabled=false; }
}

document.addEventListener('DOMContentLoaded', init);
