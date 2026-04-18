function showProfileSection(el, section) {
    const page = el.closest('#page-profile');
    if (!page) return;
    page.querySelectorAll('.nav-tabs .nav-tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    page.querySelectorAll('.profile-view').forEach(v => {
        v.style.display = (v.dataset.view === section) ? 'block' : 'none';
    });
}

function selectCat(el) {
    el.parentElement.querySelectorAll('.cat-item').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
}

function selectItemSet(el) {
    const list = el.parentElement;
    list.querySelectorAll('.set-item').forEach(s => s.classList.remove('selected'));
    el.classList.add('selected');
    const title = el.querySelector('.set-name');
    const editor = document.querySelector('.profile-view[data-view="itemsets"] .editor-title');
    if (title && editor) editor.textContent = title.textContent;
}

const MASTERY_DEFAULTS = {
    'icon-sword':  ['Sorcery',            'Increases your ability power and magic damage.'],
    'icon-axe':    ['Brute Force',        'Increases your attack damage.'],
    'icon-fist':   ['Martial Mastery',    'Grants bonus armor penetration.'],
    'icon-bow':    ['Executioner',        'Deal more damage to low health targets.'],
    'icon-magic':  ['Arcane Mastery',     'Grants bonus magic penetration.'],
    'icon-shield': ['Block',              'Reduces incoming damage from champion basic attacks.'],
    'icon-armor':  ['Recovery',           'Regenerate health over time.'],
    'icon-helmet': ['Tough Skin',         'Reduces damage from monsters and champions.'],
    'icon-potion': ["Summoner's Resolve", 'Gain additional benefits from defensive summoner spells.'],
    'icon-heart':  ['Juggernaut',         'Increases your maximum health.'],
    'icon-tower':  ['Reinforced Armor',   'Reduces damage taken from critical strikes.'],
    'icon-eye':    ['Evasive',            'Reduces AoE damage taken.'],
    'icon-leaf':   ["Summoner's Insight", 'Reduces summoner spell cooldowns.'],
    'icon-coin':   ['Greed',              'Generates additional gold over time.'],
    'icon-boot':   ['Swiftness',          'Increases your movement speed.'],
    'icon-scroll': ['Wealth',             'Starts with additional gold at the start of the game.'],
    'icon-mana':   ['Meditation',         'Regenerate mana over time.'],
    'icon-skull':  ['Soul Siphon',        'Increases life steal and spell vamp.']
};

function initMasteryTooltips() {
    const tooltip = document.getElementById('masteryTooltip');
    if (!tooltip) return;
    const titleEl = tooltip.querySelector('.tooltip-title');
    const rankEl = tooltip.querySelector('.tooltip-rank');
    const bodyEl = tooltip.querySelector('.tooltip-body');

    const show = icon => {
        let title = icon.dataset.title, desc = icon.dataset.desc;
        if (!title || !desc) {
            for (const cls of icon.classList) {
                if (MASTERY_DEFAULTS[cls]) {
                    if (!title) title = MASTERY_DEFAULTS[cls][0];
                    if (!desc) desc = MASTERY_DEFAULTS[cls][1];
                    break;
                }
            }
        }
        const rs = icon.querySelector('.mrank');
        titleEl.textContent = title || 'Mastery';
        rankEl.textContent = 'Rank: ' + (rs ? rs.textContent : '0/1');
        bodyEl.textContent = desc || '';
        tooltip.style.display = 'block';
    };

    const hide = () => { tooltip.style.display = 'none'; };

    const move = e => {
        const tw = tooltip.offsetWidth || 260;
        const th = tooltip.offsetHeight || 80;
        let x = e.clientX + 15, y = e.clientY + 15;
        if (x + tw > window.innerWidth - 10) x = e.clientX - tw - 15;
        if (y + th > window.innerHeight - 10) y = e.clientY - th - 15;
        tooltip.style.left = x + 'px';
        tooltip.style.top = y + 'px';
    };

    document.querySelectorAll('.mastery-icon').forEach(icon => {
        icon.addEventListener('mouseenter', () => show(icon));
        icon.addEventListener('mouseleave', hide);
        icon.addEventListener('mousemove', move);
    });
}

function initSpellSelector() {
    const view = document.querySelector('.profile-view[data-view="spells"]');
    if (!view) return;
    const slots = view.querySelectorAll('.spell-slot');
    const bigIcon = view.querySelector('.spell-big-icon');
    const nameEl = view.querySelector('.spell-name');
    const descEl = view.querySelector('.spell-description');
    const cdEl = view.querySelector('.spell-meta-cd');
    const lvlEl = view.querySelector('.spell-meta-lvl');
    const rangeEl = view.querySelector('.spell-meta-range');

    slots.forEach(slot => {
        slot.addEventListener('click', () => {
            slots.forEach(s => s.classList.remove('selected'));
            slot.classList.add('selected');
            const sprite = [...slot.classList].find(c => c.startsWith('sp-'));
            bigIcon.className = 'spell-big-icon ' + sprite;
            nameEl.textContent = slot.dataset.name;
            descEl.textContent = slot.dataset.desc;
            if (cdEl) cdEl.textContent = slot.dataset.cd;
            if (lvlEl) lvlEl.textContent = slot.dataset.lvl;
            if (rangeEl) rangeEl.textContent = slot.dataset.range;
        });
    });
}
