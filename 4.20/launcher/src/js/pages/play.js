function selectModeTab(el) {
    el.parentElement.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('selected'));
    el.classList.add('selected');
}

function selectGameMode(el) {
    _selectInColumn(el);
    _applyPlayPreview({ title: el.dataset.title, subtitle: '', desc: el.dataset.desc, desc2: '' });
}

function selectMapOpt(el) {
    _selectInColumn(el);
}

function selectGameType(el) {
    _selectInColumn(el);
    _applyPlayPreview({
        title: el.dataset.title,
        subtitle: el.dataset.subtitle,
        desc: el.dataset.desc,
        desc2: el.dataset.desc2
    });
}

function _selectInColumn(el) {
    el.parentElement.querySelectorAll('.mode-option').forEach(o => o.classList.remove('selected'));
    el.classList.add('selected');
}

function _applyPlayPreview(d) {
    const fields = {
        playPreviewTitle: d.title,
        playPreviewSubtitle: d.subtitle,
        playPreviewDesc: d.desc,
        playPreviewDesc2: d.desc2
    };
    for (const id in fields) {
        const el = document.getElementById(id);
        if (!el) continue;
        el.textContent = fields[id] || '';
        if (id === 'playPreviewSubtitle' || id === 'playPreviewDesc2') {
            el.style.display = fields[id] ? 'block' : 'none';
        }
    }
}
