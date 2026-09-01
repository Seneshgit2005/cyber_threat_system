<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_login();

$user = current_user();

$myTotal = $pdo->prepare("SELECT COUNT(*) FROM threat_reports WHERE userID=?");
$myTotal->execute([$user['userID']]);
$myTotal = $myTotal->fetchColumn();

$myApproved = $pdo->prepare("SELECT COUNT(*) FROM threat_reports WHERE userID=? AND status='approved'");
$myApproved->execute([$user['userID']]);
$myApproved = $myApproved->fetchColumn();

$myPending = $pdo->prepare("SELECT COUNT(*) FROM threat_reports WHERE userID=? AND status='pending'");
$myPending->execute([$user['userID']]);
$myPending = $myPending->fetchColumn();

$recentQ = $pdo->prepare(
    "SELECT reportID, urlOrEmail, threatType, status, submittedAt
     FROM threat_reports WHERE userID=? ORDER BY submittedAt DESC LIMIT 5"
);
$recentQ->execute([$user['userID']]);
$recent = $recentQ->fetchAll();

$globalBlacklist = $pdo->query("SELECT COUNT(*) FROM blacklist")->fetchColumn();

$pageTitle = 'Dashboard';
include '../includes/header.php';
?>

<h1 class="cw-page-title">
    <i class="bi bi-grid me-2"></i>Dashboard
    <span style="font-size:.9rem;font-weight:400;color:var(--cw-muted);font-family:var(--font-main);"> — Welcome,
        <?= htmlspecialchars($user['username']) ?></span>
</h1>

<!-- Stats -->
<div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
        <div class="cw-stat">
            <div class="cw-stat-number"><?= $myTotal ?></div>
            <div class="cw-stat-label">My Reports</div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="cw-stat success">
            <div class="cw-stat-number"><?= $myApproved ?></div>
            <div class="cw-stat-label">Approved</div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="cw-stat danger">
            <div class="cw-stat-number"><?= $myPending ?></div>
            <div class="cw-stat-label">Pending Review</div>
        </div>
    </div>
    <div class="col-6 col-md-3">
        <div class="cw-stat info">
            <div class="cw-stat-number"><?= $globalBlacklist ?></div>
            <div class="cw-stat-label">Global Blacklist</div>
        </div>
    </div>
</div>

<!-- Quick actions + recent -->
<div class="row g-4">
    <div class="col-lg-4">
        <div class="cw-card h-100">
            <div class="cw-card-header"><i class="bi bi-lightning me-1"></i>Quick Actions</div>
            <div class="d-grid gap-2">
                <a href="submit_report.php" class="btn btn-cw-primary">
                    <i class="bi bi-flag me-2"></i>Submit New Report
                </a>
                <a href="lookup.php" class="btn btn-cw-ghost">
                    <i class="bi bi-search me-2"></i>Check URL / Email
                </a>
                <a href="my_reports.php" class="btn btn-cw-ghost">
                    <i class="bi bi-list-ul me-2"></i>View All My Reports
                </a>
            </div>
        </div>
    </div>
    <div class="col-lg-8">
        <div class="cw-card">
            <div class="cw-card-header d-flex justify-content-between align-items-center">
                <span><i class="bi bi-clock-history me-1"></i>Recent Submissions</span>
                <a href="my_reports.php" class="text-accent" style="font-size:.8rem;">View all →</a>
            </div>
            <?php if ($recent): ?>
                <div class="cw-table-wrap">
                    <table class="cw-table">
                        <thead>
                            <tr>
                                <th>URL / Email</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recent as $r): ?>
                                <tr>
                                    <td class="font-mono" style="font-size:.8rem;max-width:220px;"
                                        title="<?= htmlspecialchars($r['urlOrEmail']) ?>">
                                        <?= htmlspecialchars(mb_strimwidth($r['urlOrEmail'], 0, 35, '…')) ?>
                                    </td>
                                    <td><span
                                            class="badge bg-<?= threat_badge($r['threatType']) ?>"><?= strtoupper($r['threatType']) ?></span>
                                    </td>
                                    <td><span
                                            class="badge bg-<?= status_badge($r['status']) ?>"><?= strtoupper($r['status']) ?></span>
                                    </td>
                                    <td style="font-size:.8rem;color:var(--cw-muted);"><?= fmt_date($r['submittedAt']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="text-center py-4 text-cw-muted">
                    <i class="bi bi-inbox" style="font-size:2rem;display:block;margin-bottom:.5rem;"></i>
                    No reports yet. <a href="submit_report.php" class="text-accent">Submit your first report →</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php include '../includes/footer.php'; ?>