function showStoreSection(el, section) {
    const store = el.closest('.store');
    if (!store) return;
    store.querySelectorAll('.store-menu .menu-item').forEach(m => m.classList.remove('active'));
    el.classList.add('active');
    store.querySelectorAll('.store-view').forEach(v => {
        v.style.display = (v.dataset.view === section) ? 'flex' : 'none';
    });
}

function selectSort(el) {
    el.parentElement.querySelectorAll('.check').forEach(c => c.classList.remove('checked'));
    el.classList.add('checked');
}
