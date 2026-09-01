<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_login();

$userID = current_user()['userID'];
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 10;
$offset = ($page - 1) * $perPage;

$total = $pdo->prepare("SELECT COUNT(*) FROM threat_reports WHERE userID=?");
$total->execute([$userID]);
$total = $total->fetchColumn();
$pages = (int) ceil($total / $perPage);

$stmt = $pdo->prepare(
    "SELECT reportID, urlOrEmail, threatType, description, dateReported, status, submittedAt,
            attachment_name
     FROM threat_reports WHERE userID=?
     ORDER BY submittedAt DESC LIMIT ? OFFSET ?"
);
$stmt->bindValue(1, $userID, PDO::PARAM_INT);
$stmt->bindValue(2, $perPage, PDO::PARAM_INT);
$stmt->bindValue(3, $offset, PDO::PARAM_INT);
$stmt->execute();
$reports = $stmt->fetchAll();

$pageTitle = 'My Reports';
include '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-list-ul me-2"></i>My <span>Reports</span></h1>
    <a href="submit_report.php" class="btn btn-cw-primary btn-sm">
        <i class="bi bi-plus me-1"></i>New Report
    </a>
</div>

<?php if ($reports): ?>
    <div class="cw-table-wrap">
        <table class="cw-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>URL / Email</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Attachment</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($reports as $i => $r): ?>
                    <tr>
                        <td style="color:var(--cw-muted);font-size:.8rem;"><?= $offset + $i + 1 ?></td>
                        <td class="font-mono" style="font-size:.8rem;max-width:200px;word-break:break-all;"
                            title="<?= htmlspecialchars($r['urlOrEmail']) ?>">
                            <?= htmlspecialchars(mb_strimwidth($r['urlOrEmail'], 0, 40, '…')) ?>
                        </td>
                        <td>
                            <?php if (!empty($r['threatType'])): ?>
                                <span
                                    class="badge bg-<?= threat_badge($r['threatType']) ?>"><?= strtoupper($r['threatType']) ?></span>
                            <?php else: ?>
                                <span class="badge bg-secondary">UNKNOWN</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size:.82rem;color:var(--cw-muted);max-width:250px;">
                            <?= htmlspecialchars(mb_strimwidth($r['description'], 0, 80, '…')) ?>
                        </td>
                        <td><span class="badge bg-<?= status_badge($r['status']) ?>"><?= strtoupper($r['status']) ?></span></td>
                        <td style="font-size:.8rem;text-align:center;">
                            <?php if (!empty($r['attachment_name'])): ?>
                                <a href="download_attachment.php?id=<?= $r['reportID'] ?>" class="btn btn-sm py-0 px-2"
                                    style="border:1px solid rgba(240,165,0,.4);color:var(--cw-accent);font-size:.75rem;"
                                    title="<?= htmlspecialchars($r['attachment_name']) ?>">
                                    <i
                                        class="bi bi-paperclip me-1"></i><?= htmlspecialchars(mb_strimwidth($r['attachment_name'], 0, 20, '…')) ?>
                                </a>
                            <?php else: ?>
                                <span style="color:var(--cw-muted);font-size:.75rem;">—</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size:.8rem;color:var(--cw-muted);white-space:nowrap;"><?= fmt_date($r['submittedAt']) ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if ($pages > 1): ?>
        <nav class="mt-3">
            <ul class="pagination pagination-sm justify-content-center mb-0">
                <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                    <a class="page-link" href="?page=<?= $page - 1 ?>">‹</a>
                </li>
                <?php for ($p = 1; $p <= $pages; $p++): ?>
                    <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                        <a class="page-link" href="?page=<?= $p ?>"><?= $p ?></a>
                    </li>
                <?php endfor; ?>
                <li class="page-item <?= $page >= $pages ? 'disabled' : '' ?>">
                    <a class="page-link" href="?page=<?= $page + 1 ?>">›</a>
                </li>
            </ul>
        </nav>
    <?php endif; ?>

<?php else: ?>
    <div class="cw-card text-center py-5">
        <i class="bi bi-inbox" style="font-size:3rem;color:var(--cw-muted);display:block;margin-bottom:1rem;"></i>
        <p class="text-cw-muted mb-3">You haven't submitted any reports yet.</p>
        <a href="submit_report.php" class="btn btn-cw-primary">
            <i class="bi bi-flag me-2"></i>Submit Your First Report
        </a>
    </div>
<?php endif; ?>

<?php include '../includes/footer.php'; ?>