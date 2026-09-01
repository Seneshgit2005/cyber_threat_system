document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.alert.auto-dismiss').forEach(el => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
            bsAlert.close();
        }, 5000);
    });

    document.querySelectorAll('[data-confirm]').forEach(el => {
        el.addEventListener('click', e => {
            if (!confirm(el.dataset.confirm)) e.preventDefault();
        });
    });

    document.querySelectorAll('textarea[data-maxlength]').forEach(ta => {
        const max = parseInt(ta.dataset.maxlength);
        const counter = document.createElement('small');
        counter.className = 'text-cw-muted';
        ta.parentNode.appendChild(counter);
        const update = () => {
            const rem = max - ta.value.length;
            counter.textContent = `${ta.value.length}/${max} characters`;
            counter.style.color = rem < 50 ? 'var(--cw-danger)' : '';
        };
        ta.addEventListener('input', update);
        update();
    });
});
