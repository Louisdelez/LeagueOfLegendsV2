const { invoke } = window.__TAURI__.core;

let champions = [];
let maps = [];
let spells = [];
let selectedMap = 11;
let selectedMode = 'CLASSIC';

async function init() {
    try {
        champions = await invoke('get_champions');
        maps = await invoke('get_maps');
        spells = await invoke('get_summoner_spells');
        populateSelects();
        populateChampionsGrid();
    } catch (e) {
        console.error('Init error:', e);
        // Fallback for dev without Tauri
        setStatus('Running in standalone mode', false);
    }
}

function populateSelects() {
    const champSelect = document.getElementById('champion');
    champSelect.innerHTML = '';
    champions.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.name;
        opt.textContent = c.display_name;
        champSelect.appendChild(opt);
    });
    champSelect.value = 'Ezreal';
    champSelect.onchange = () => updateChampionPreview();

    const spell1 = document.getElementById('spell1');
    const spell2 = document.getElementById('spell2');
    spell1.innerHTML = '';
    spell2.innerHTML = '';
    spells.forEach(s => {
        spell1.appendChild(new Option(s.display_name, s.name));
        spell2.appendChild(new Option(s.display_name, s.name));
    });
    spell1.value = 'SummonerFlash';
    spell2.value = 'SummonerHeal';
    spell1.onchange = () => updateSpellPreview();
    spell2.onchange = () => updateSpellPreview();

    updateChampionPreview();
    updateSpellPreview();
}

function populateChampionsGrid() {
    const grid = document.getElementById('champions-grid');
    if (!grid) return;
    grid.innerHTML = '';
    champions.forEach(c => {
        const card = document.createElement('div');
        card.className = 'champ-card';
        card.onclick = () => {
            document.getElementById('champion').value = c.name;
            updateChampionPreview();
            showPage('play');
        };
        card.innerHTML = `
            <div class="champ-icon">${c.display_name.substring(0, 2).toUpperCase()}</div>
            <div class="champ-label">${c.display_name}</div>
        `;
        grid.appendChild(card);
    });
}

function updateChampionPreview() {
    const sel = document.getElementById('champion');
    const opt = sel.options[sel.selectedIndex];
    if (opt) {
        document.getElementById('champ-display').textContent = opt.textContent;
    }
}

function updateSpellPreview() {
    const s1 = document.getElementById('spell1');
    const s2 = document.getElementById('spell2');
    document.getElementById('spell1-display').textContent = s1.options[s1.selectedIndex]?.textContent || '';
    document.getElementById('spell2-display').textContent = s2.options[s2.selectedIndex]?.textContent || '';
}

function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    const pageEl = document.getElementById('page-' + page);
    if (pageEl) pageEl.classList.add('active');
    document.querySelectorAll(`.tab[data-page="${page}"]`).forEach(t => t.classList.add('active'));

    // Update summoner name display
    const name = document.getElementById('player-name')?.value || 'Player1';
    document.getElementById('summoner-name-display').textContent = name;
    const profileName = document.getElementById('profile-name');
    if (profileName) profileName.textContent = name;
}

function selectGameType(el, type) {
    document.querySelectorAll('.game-type-item').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
}

function selectMode(el, mode) {
    document.querySelectorAll('.mode-card').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
    selectedMode = mode;
    if (mode === 'ARAM') {
        selectMapById(12);
    }
}

function selectMap(el, mapId) {
    document.querySelectorAll('.map-card').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
    selectedMap = mapId;
    updateMapPreview(mapId);
}

function selectMapById(id) {
    const cards = document.querySelectorAll('.map-card');
    cards.forEach(c => {
        c.classList.remove('active');
        if (parseInt(c.dataset.map) === id) c.classList.add('active');
    });
    selectedMap = id;
    updateMapPreview(id);
}

function updateMapPreview(mapId) {
    const previews = {
        11: { title: "Summoner's Rift", desc: "Work with your allies to siege the enemy base and destroy their Nexus." },
        10: { title: "Twisted Treeline", desc: "A darker, faster 3v3 map set in the Shadow Isles." },
        12: { title: "Howling Abyss", desc: "All Random All Mid — one lane, random champions, constant teamfights." },
        8: { title: "Crystal Scar", desc: "Capture and hold strategic points across the map to drain the enemy Nexus." },
    };
    const info = previews[mapId] || previews[11];
    document.getElementById('map-preview').innerHTML = `
        <div class="map-preview-title">${info.title}</div>
        <div class="map-preview-desc">${info.desc}</div>
    `;
}

function setStatus(msg, isError = false) {
    const el = document.getElementById('status');
    if (el) {
        el.textContent = msg;
        el.style.color = isError ? '#FF4444' : '#0AC8B9';
    }
}

async function launchGame() {
    const btn = document.getElementById('launch-btn');
    btn.disabled = true;
    setStatus('Starting server and game client...');

    try {
        const result = await invoke('launch_game', {
            playerName: document.getElementById('player-name').value || 'Player1',
            champion: document.getElementById('champion').value,
            mapId: selectedMap,
            summoner1: document.getElementById('spell1').value,
            summoner2: document.getElementById('spell2').value,
            skin: 0,
            minionsEnabled: document.getElementById('minions').checked,
            cooldownsEnabled: document.getElementById('cooldowns').checked,
            manaEnabled: document.getElementById('mana').checked,
        });
        setStatus(result);
        setTimeout(() => { btn.disabled = false; setStatus(''); }, 15000);
    } catch (e) {
        setStatus('Error: ' + e, true);
        btn.disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', init);
