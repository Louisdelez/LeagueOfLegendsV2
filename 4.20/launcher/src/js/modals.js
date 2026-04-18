function openOptions()  { _toggleOverlay('optionsOverlay', false); }
function closeOptions() { _toggleOverlay('optionsOverlay', true); }
function openInvites()  { _toggleOverlay('invitesOverlay', false); }
function closeInvites() { _toggleOverlay('invitesOverlay', true); }

function _toggleOverlay(id, hide) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', hide);
}

function addInvitee(btn) {
    const name = btn.previousElementSibling.querySelector('.friend-name-inv').textContent;
    const box = document.getElementById('inviteListBox');
    if (!box || box.querySelector('[data-name="' + name + '"]')) return;

    const row = document.createElement('div');
    row.className = 'friend-row-inv';
    row.dataset.name = name;
    row.innerHTML =
        '<div class="friend-card-inv" style="flex:1;justify-content:center">' +
            '<div class="friend-name-inv">' + name + '</div>' +
        '</div>' +
        '<button class="friend-add-inv" style="background:linear-gradient(to bottom,#C04030,#7A1810);border-color:#2A0808" title="Retirer">&ndash;</button>';
    box.appendChild(row);
    row.querySelector('.friend-add-inv').addEventListener('click', () => {
        row.remove();
        _updateInviteCount();
    });
    _updateInviteCount();
}

function _updateInviteCount() {
    const box = document.getElementById('inviteListBox');
    const title = document.getElementById('inviteListTitle');
    if (!box || !title) return;
    title.textContent = 'Invite List (' + box.children.length + '/15)';
}
