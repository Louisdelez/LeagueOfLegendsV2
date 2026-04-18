const { invoke } = window.__TAURI__.core;

let champions = [];
let maps = [];
let spells = [];

async function init() {
    try {
        champions = await invoke('get_champions');
        maps = await invoke('get_maps');
        spells = await invoke('get_summoner_spells');
        populateSelects();
    } catch (e) {
        setStatus('Error loading data: ' + e, true);
    }
}

function populateSelects() {
    const champSelect = document.getElementById('champion');
    champions.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.name;
        opt.textContent = c.display_name;
        champSelect.appendChild(opt);
    });
    // Default to Ezreal
    champSelect.value = 'Ezreal';

    const mapSelect = document.getElementById('map');
    maps.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = `${m.name} (${m.players})`;
        mapSelect.appendChild(opt);
    });

    const spell1 = document.getElementById('spell1');
    const spell2 = document.getElementById('spell2');
    spells.forEach(s => {
        const opt1 = document.createElement('option');
        opt1.value = s.name;
        opt1.textContent = s.display_name;
        spell1.appendChild(opt1);

        const opt2 = document.createElement('option');
        opt2.value = s.name;
        opt2.textContent = s.display_name;
        spell2.appendChild(opt2);
    });
    spell1.value = 'SummonerFlash';
    spell2.value = 'SummonerHeal';
}

function setStatus(msg, isError = false) {
    const el = document.getElementById('status');
    el.textContent = msg;
    el.style.color = isError ? '#C6443E' : '#0397AB';
}

async function launchGame() {
    const btn = document.getElementById('launch-btn');
    btn.disabled = true;
    setStatus('Launching game...');

    try {
        const result = await invoke('launch_game', {
            playerName: document.getElementById('player-name').value || 'Player1',
            champion: document.getElementById('champion').value,
            mapId: parseInt(document.getElementById('map').value),
            summoner1: document.getElementById('spell1').value,
            summoner2: document.getElementById('spell2').value,
            skin: 0,
            minionsEnabled: document.getElementById('minions').checked,
            cooldownsEnabled: document.getElementById('cooldowns').checked,
            manaEnabled: document.getElementById('mana').checked,
        });
        setStatus(result);
        setTimeout(() => { btn.disabled = false; }, 10000);
    } catch (e) {
        setStatus('Error: ' + e, true);
        btn.disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', init);
