<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete'])) {
    $bid = filter_input(INPUT_POST, 'blacklistID', FILTER_VALIDATE_INT);
    if ($bid) {
        $pdo->prepare("DELETE FROM blacklist WHERE blacklistID=?")->execute([$bid]);
        redirect(SITE_URL . '/admin/blacklist.php', 'Entry removed from blacklist.', 'success');
    }
}

// Manual add
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['addEntry'])) {
    $url  = sanitise($_POST['urlOrEmail'] ?? '');
    $type = sanitise($_POST['threatType'] ?? '');
    if ($url && in_array($type, ['phishing','malware','spam'])) {
        $pdo->prepare(
            "INSERT INTO blacklist (urlOrEmail, threatType, addedDate, verifiedBy) VALUES (?,?,NOW(),?)"
        )->execute([$url, $type, current_user()['userID']]);
        redirect(SITE_URL . '/admin/blacklist.php', 'Entry added to blacklist.', 'success');
    }
}

$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 20;
$offset  = ($page - 1) * $perPage;
$total   = $pdo->query("SELECT COUNT(*) FROM blacklist")->fetchColumn();
$pages   = (int)ceil($total / $perPage);

$entries = $pdo->prepare(
    "SELECT b.*, u.username FROM blacklist b JOIN users u ON b.verifiedBy=u.userID
     ORDER BY b.addedDate DESC LIMIT {$perPage} OFFSET {$offset}"
);
$entries->execute();
$entries = $entries->fetchAll();

$pageTitle = 'Blacklist Management';
include '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-database me-2"></i>Blacklist <span>Management</span></h1>
    <a href="dashboard.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Dashboard</a>
</div>

<!-- Manual Add -->
<div class="cw-card mb-4">
    <div class="cw-card-header"><i class="bi bi-plus-circle me-1"></i>Manually Add Entry</div>
    <form method="POST" class="row g-2 align-items-end">
        <div class="col-md-6">
            <label class="form-label">URL or Email</label>
            <input type="text" name="urlOrEmail" class="form-control font-mono" placeholder="e.g. scam-site.com" required>
        </div>
        <div class="col-md-3">
            <label class="form-label">Threat Type</label>
            <select name="threatType" class="form-select" required>
                <option value="">— Select —</option>
                <option value="phishing">Phishing</option>
                <option value="malware">Malware</option>
                <option value="spam">Spam</option>
            </select>
        </div>
        <div class="col-md-3">
            <button type="submit" name="addEntry" value="1" class="btn btn-cw-primary w-100">Add to Blacklist</button>
        </div>
    </form>
</div>

<!-- Table -->
<div class="cw-table-wrap mb-3">
    <table class="cw-table">
        <thead>
            <tr><th>#</th><th>URL / Email</th><th>Type</th><th>Verified By</th><th>Date Added</th><th>Remove</th></tr>
        </thead>
        <tbody>
            <?php foreach ($entries as $i => $e): ?>
            <tr>
                <td style="color:var(--cw-muted);font-size:.78rem;"><?= $offset+$i+1 ?></td>
                <td class="font-mono" style="font-size:.8rem;word-break:break-all;"><?= htmlspecialchars($e['urlOrEmail']) ?></td>
                <td><span class="badge bg-<?= threat_badge($e['threatType']) ?>"><?= strtoupper($e['threatType']) ?></span></td>
                <td style="font-size:.82rem;"><?= htmlspecialchars($e['username']) ?></td>
                <td style="font-size:.78rem;color:var(--cw-muted);"><?= fmt_date($e['addedDate']) ?></td>
                <td>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="blacklistID" value="<?= $e['blacklistID'] ?>">
                        <button type="submit" name="delete" value="1"
                                class="btn btn-sm btn-danger py-0 px-2"
                                data-confirm="Remove <?= htmlspecialchars(mb_strimwidth($e['urlOrEmail'],0,30,'…')) ?> from blacklist?">
                            <i class="bi bi-trash"></i>
                        </button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php if ($pages > 1): ?>
<nav><ul class="pagination pagination-sm justify-content-center">
    <?php for ($p = 1; $p <= $pages; $p++): ?>
    <li class="page-item <?= $p===$page?'active':'' ?>">
        <a class="page-link" href="?page=<?= $p ?>"><?= $p ?></a>
    </li>
    <?php endfor; ?>
</ul></nav>
<?php endif; ?>

<?php include '../includes/footer.php'; ?>
