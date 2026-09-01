<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

$status  = sanitise($_GET['status'] ?? '');
$type    = sanitise($_GET['type']   ?? '');
$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 15;
$offset  = ($page - 1) * $perPage;

$where  = [];
$params = [];
if (in_array($status, ['pending','approved','rejected'])) {
    $where[]  = "tr.status = ?";
    $params[] = $status;
}
if (in_array($type, ['phishing','malware','spam'])) {
    $where[]  = "tr.threatType = ?";
    $params[] = $type;
}
$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$countStmt = $pdo->prepare("SELECT COUNT(*) FROM threat_reports tr $whereSQL");
$countStmt->execute($params);
$total = $countStmt->fetchColumn();
$pages = (int)ceil($total / $perPage);

$dataParams = array_merge($params, [$perPage, $offset]);
$stmt = $pdo->prepare(
    "SELECT tr.reportID, tr.urlOrEmail, tr.threatType, tr.status, tr.submittedAt, u.username,
            tr.attachment_name
     FROM threat_reports tr JOIN users u ON tr.userID=u.userID
     $whereSQL ORDER BY tr.submittedAt DESC LIMIT {$perPage} OFFSET {$offset}"
);
$stmt->execute($params);
$reports = $stmt->fetchAll();

$pageTitle = 'All Reports';
include '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-flag me-2"></i>All <span>Reports</span></h1>
    <a href="dashboard.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Dashboard</a>
</div>

<!-- Filters -->
<form method="GET" class="d-flex gap-2 mb-4 flex-wrap">
    <select name="status" class="form-select form-select-sm" style="width:auto;">
        <option value="">All Statuses</option>
        <?php foreach (['pending','approved','rejected'] as $s): ?>
        <option value="<?= $s ?>" <?= $status === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
        <?php endforeach; ?>
    </select>
    <select name="type" class="form-select form-select-sm" style="width:auto;">
        <option value="">All Types</option>
        <?php foreach (['phishing','malware','spam'] as $t): ?>
        <option value="<?= $t ?>" <?= $type === $t ? 'selected' : '' ?>><?= ucfirst($t) ?></option>
        <?php endforeach; ?>
    </select>
    <button type="submit" class="btn btn-cw-primary btn-sm">Filter</button>
    <a href="reports.php" class="btn btn-cw-ghost btn-sm">Reset</a>
</form>

<div class="cw-table-wrap mb-3">
    <table class="cw-table">
        <thead>
            <tr><th>#</th><th>URL / Email</th><th>Type</th><th>Reporter</th><th>Status</th><th>Att.</th><th>Date</th><th>Actions</th></tr>
        </thead>
        <tbody>
            <?php if ($reports): ?>
            <?php foreach ($reports as $i => $r): ?>
            <tr>
                <td style="color:var(--cw-muted);font-size:.78rem;"><?= $offset + $i + 1 ?></td>
                <td class="font-mono" style="font-size:.78rem;max-width:180px;word-break:break-all;">
                    <?= htmlspecialchars(mb_strimwidth($r['urlOrEmail'], 0, 40, '…')) ?>
                </td>
                <td>
                    <?php if (!empty($r['threatType'])): ?>
                    <span class="badge bg-<?= threat_badge($r['threatType']) ?>"><?= strtoupper($r['threatType']) ?></span>
                    <?php else: ?>
                    <span class="badge bg-secondary">UNKNOWN</span>
                    <?php endif; ?>
                </td>
                <td style="font-size:.82rem;"><?= htmlspecialchars($r['username']) ?></td>
                <td><span class="badge bg-<?= status_badge($r['status']) ?>"><?= strtoupper($r['status']) ?></span></td>
                <td style="text-align:center;">
                    <?php if (!empty($r['attachment_name'])): ?>
                    <span title="<?= htmlspecialchars($r['attachment_name']) ?>" style="color:var(--cw-accent);font-size:1rem;"><i class="bi bi-paperclip"></i></span>
                    <?php else: ?>
                    <span style="color:var(--cw-muted);font-size:.8rem;">—</span>
                    <?php endif; ?>
                </td>
                <td style="font-size:.78rem;color:var(--cw-muted);"><?= fmt_date($r['submittedAt']) ?></td>
                <td>
                    <a href="report_detail.php?id=<?= $r['reportID'] ?>" class="btn btn-sm btn-cw-ghost py-0 px-2">
                        <i class="bi bi-eye"></i>
                    </a>
                    <?php if ($r['status'] === 'pending'): ?>
                    <form method="POST" action="approve.php" class="d-inline ms-1">
                        <input type="hidden" name="reportID" value="<?= $r['reportID'] ?>">
                        <input type="hidden" name="action"   value="approve">
                        <button class="btn btn-sm btn-success py-0 px-2" data-confirm="Approve?"><i class="bi bi-check-lg"></i></button>
                    </form>
                    <form method="POST" action="approve.php" class="d-inline ms-1">
                        <input type="hidden" name="reportID" value="<?= $r['reportID'] ?>">
                        <input type="hidden" name="action"   value="reject">
                        <button class="btn btn-sm btn-danger py-0 px-2" data-confirm="Reject?"><i class="bi bi-x-lg"></i></button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php else: ?>
            <tr><td colspan="8" class="text-center text-cw-muted py-4">No reports found.</td></tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>

<?php if ($pages > 1): ?>
<nav><ul class="pagination pagination-sm justify-content-center">
    <?php for ($p = 1; $p <= $pages; $p++): ?>
    <li class="page-item <?= $p === $page ? 'active' : '' ?>">
        <a class="page-link" href="?page=<?= $p ?>&status=<?= urlencode($status) ?>&type=<?= urlencode($type) ?>"><?= $p ?></a>
    </li>
    <?php endfor; ?>
</ul></nav>
<?php endif; ?>

<?php include '../includes/footer.php'; ?>
