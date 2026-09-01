<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';

$results = [];
$searched = false;
$searchTerm = '';

$raw = $_POST['searchTerm'] ?? $_GET['q'] ?? '';

if ($raw !== '') {
    $searchTerm = sanitise($raw);
    $searched = true;

    if (strlen($searchTerm) >= 3) {
        $stmt = $pdo->prepare(
            "SELECT urlOrEmail, threatType, addedDate
             FROM blacklist
             WHERE LOWER(urlOrEmail) LIKE LOWER(?)
             ORDER BY addedDate DESC
             LIMIT 50"
        );
        $stmt->execute(['%' . $searchTerm . '%']);
        $results = $stmt->fetchAll();
    }
}

$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 15;
$offset = ($page - 1) * $perPage;
$total = $pdo->query("SELECT COUNT(*) FROM blacklist")->fetchColumn();
$pages = (int) ceil($total / $perPage);

$allEntries = $pdo->prepare(
    "SELECT urlOrEmail, threatType, addedDate FROM blacklist ORDER BY addedDate DESC LIMIT ? OFFSET ?"
);
$allEntries->bindValue(1, $perPage, PDO::PARAM_INT);
$allEntries->bindValue(2, $offset, PDO::PARAM_INT);
$allEntries->execute();
$allEntries = $allEntries->fetchAll();

$pageTitle = 'Blacklist Lookup';
include '../includes/header.php';
?>

<h1 class="cw-page-title"><i class="bi bi-search me-2"></i>Blacklist <span>Lookup</span></h1>

<!-- Search Box -->
<div class="cw-search-wrap">
    <p class="text-cw-muted mb-3" style="font-size:.9rem;">
        Enter a URL or email address to check whether it has been verified as a cyber threat by our administrators.
    </p>
    <form method="POST">
        <div class="cw-search-group">
            <input type="text" name="searchTerm" class="form-control font-mono"
                value="<?= htmlspecialchars($searchTerm) ?>" placeholder="e.g. suspicious-site.com or scammer@email.ru"
                minlength="3" required>
            <button type="submit" class="btn btn-cw-primary px-4">
                <i class="bi bi-search me-1"></i>Check
            </button>
        </div>
        <?php if ($searched && strlen($searchTerm) < 3): ?>
            <small class="text-danger mt-1 d-block">Please enter at least 3 characters.</small>
        <?php endif; ?>
    </form>
</div>

<!-- Search Results -->
<?php if ($searched && strlen($searchTerm) >= 3): ?>
    <div class="mb-4">
        <?php if (count($results) > 0): ?>
            <div class="cw-result-threat mb-3">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-exclamation-triangle-fill text-danger" style="font-size:1.4rem;"></i>
                    <strong style="color:var(--cw-danger);font-size:1.05rem;">
                        <?= count($results) ?> threat match<?= count($results) > 1 ? 'es' : '' ?> found
                    </strong>
                </div>
                <p class="mb-2" style="font-size:.9rem;color:var(--cw-muted);">
                    The following entries in our blacklist match "<strong><?= htmlspecialchars($searchTerm) ?></strong>". Do not
                    interact with them.
                </p>
                <div class="cw-table-wrap">
                    <table class="cw-table">
                        <thead>
                            <tr>
                                <th>URL / Email</th>
                                <th>Threat Type</th>
                                <th>Verified Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($results as $r): ?>
                                <tr>
                                    <td class="font-mono" style="font-size:.82rem;word-break:break-all;">
                                        <?= htmlspecialchars($r['urlOrEmail']) ?>
                                    </td>
                                    <td><span
                                            class="badge bg-<?= threat_badge($r['threatType'] ?? 'unknown') ?>"><?= strtoupper($r['threatType'] ?? 'unknown') ?></span>
                                    </td>
                                    <td style="font-size:.82rem;color:var(--cw-muted);"><?= fmt_date($r['addedDate']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php else: ?>
            <div class="cw-result-safe">
                <i class="bi bi-shield-check"
                    style="font-size:2rem;color:var(--cw-success);display:block;margin-bottom:.5rem;"></i>
                <strong style="color:var(--cw-success);">No matches found</strong>
                <p class="mb-2" style="font-size:.88rem;color:var(--cw-muted);margin-top:.25rem;">
                    "<strong><?= htmlspecialchars($searchTerm) ?></strong>" is not in our blacklist.
                </p>
                <p style="font-size:.82rem;color:var(--cw-muted);">
                    If you still find it suspicious, please
                    <?php if (is_logged_in()): ?>
                        <a href="submit_report.php?url=<?= urlencode($searchTerm) ?>" class="text-accent">submit a report</a>.
                    <?php else: ?>
                        <a href="../register.php" class="text-accent">register</a> and submit a report.
                    <?php endif; ?>
                </p>
            </div>
        <?php endif; ?>
    </div>
<?php endif; ?>

<!-- Full Blacklist Table -->
<div class="cw-card">
    <div class="cw-card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-database me-1"></i>Community Blacklist</span>
        <span style="font-size:.8rem;color:var(--cw-muted);"><?= number_format($total) ?> verified entries</span>
    </div>
    <?php if ($allEntries): ?>
        <div class="cw-table-wrap">
            <table class="cw-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>URL / Email</th>
                        <th>Type</th>
                        <th>Verified</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($allEntries as $i => $r): ?>
                        <tr>
                            <td style="font-size:.78rem;color:var(--cw-muted);"><?= $offset + $i + 1 ?></td>
                            <td class="font-mono" style="font-size:.82rem;word-break:break-all;">
                                <?= htmlspecialchars($r['urlOrEmail']) ?></td>
                            <td><span
                                    class="badge bg-<?= threat_badge($r['threatType'] ?? 'unknown') ?>"><?= strtoupper($r['threatType'] ?? 'unknown') ?></span>
                            </td>
                            <td style="font-size:.82rem;color:var(--cw-muted);"><?= fmt_date($r['addedDate']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <!-- Pagination -->
        <?php if ($pages > 1): ?>
            <nav class="mt-3">
                <ul class="pagination pagination-sm justify-content-center mb-0">
                    <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                        <a class="page-link" href="?page=<?= $page - 1 ?>">‹ Prev</a>
                    </li>
                    <?php for ($p = max(1, $page - 2); $p <= min($pages, $page + 2); $p++): ?>
                        <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                            <a class="page-link" href="?page=<?= $p ?>"><?= $p ?></a>
                        </li>
                    <?php endfor; ?>
                    <li class="page-item <?= $page >= $pages ? 'disabled' : '' ?>">
                        <a class="page-link" href="?page=<?= $page + 1 ?>">Next ›</a>
                    </li>
                </ul>
            </nav>
        <?php endif; ?>
    <?php else: ?>
        <p class="text-cw-muted text-center py-3">No blacklist entries yet.</p>
    <?php endif; ?>
</div>

<?php include '../includes/footer.php'; ?>