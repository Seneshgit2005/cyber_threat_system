<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

$stats = [
    'pending'   => $pdo->query("SELECT COUNT(*) FROM threat_reports WHERE status='pending'")->fetchColumn(),
    'approved'  => $pdo->query("SELECT COUNT(*) FROM threat_reports WHERE status='approved'")->fetchColumn(),
    'rejected'  => $pdo->query("SELECT COUNT(*) FROM threat_reports WHERE status='rejected'")->fetchColumn(),
    'blacklist' => $pdo->query("SELECT COUNT(*) FROM blacklist")->fetchColumn(),
    'users'     => $pdo->query("SELECT COUNT(*) FROM users WHERE role='user'")->fetchColumn(),
];

$pending = $pdo->query(
    "SELECT tr.reportID, tr.urlOrEmail, tr.threatType, tr.description,
            tr.dateReported, tr.submittedAt, u.username
     FROM threat_reports tr
     JOIN users u ON tr.userID = u.userID
     WHERE tr.status='pending'
     ORDER BY tr.submittedAt ASC
     LIMIT 20"
)->fetchAll();

$chartRows = $pdo->query(
    "SELECT DATE_FORMAT(dateReported,'%b %Y') AS mo,
            DATE_FORMAT(dateReported,'%Y-%m') AS sort_key,
            COUNT(*) AS cnt
     FROM threat_reports
     WHERE dateReported >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
     GROUP BY mo, sort_key ORDER BY sort_key ASC"
)->fetchAll();
$chartLabels = array_column($chartRows, 'mo');
$chartData   = array_column($chartRows, 'cnt');

$pageTitle = 'Admin Dashboard';
include '../includes/header.php';
?>

<h1 class="cw-page-title"><i class="bi bi-speedometer2 me-2"></i>Admin <span>Dashboard</span></h1>

<!-- Stats -->
<div class="row g-3 mb-4">
    <div class="col-6 col-md-2-custom">
        <div class="cw-stat danger">
            <div class="cw-stat-number"><?= $stats['pending'] ?></div>
            <div class="cw-stat-label">Pending</div>
        </div>
    </div>
    <div class="col-6 col-md-2-custom">
        <div class="cw-stat success">
            <div class="cw-stat-number"><?= $stats['approved'] ?></div>
            <div class="cw-stat-label">Approved</div>
        </div>
    </div>
    <div class="col-6 col-md-2-custom">
        <div class="cw-stat">
            <div class="cw-stat-number"><?= $stats['rejected'] ?></div>
            <div class="cw-stat-label">Rejected</div>
        </div>
    </div>
    <div class="col-6 col-md-2-custom">
        <div class="cw-stat info">
            <div class="cw-stat-number"><?= $stats['blacklist'] ?></div>
            <div class="cw-stat-label">Blacklist</div>
        </div>
    </div>
    <div class="col-6 col-md-2-custom">
        <div class="cw-stat">
            <div class="cw-stat-number"><?= $stats['users'] ?></div>
            <div class="cw-stat-label">Users</div>
        </div>
    </div>
</div>

<style>
@media (min-width:768px) { .col-md-2-custom { flex:0 0 auto; width:20%; } }
</style>

<!-- Quick nav -->
<div class="d-flex gap-2 mb-4 flex-wrap">
    <a href="reports.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-flag me-1"></i>All Reports</a>
    <a href="blacklist.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-database me-1"></i>Blacklist</a>
    <a href="users.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-people me-1"></i>Users</a>
    <a href="awareness.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-bar-chart me-1"></i>Awareness Reports</a>
</div>

<div class="row g-4">
    <!-- Pending Reports -->
    <div class="col-lg-8">
        <div class="cw-card">
            <div class="cw-card-header d-flex justify-content-between align-items-center">
                <span><i class="bi bi-clock me-1"></i>Pending Reports</span>
                <a href="reports.php?status=pending" class="text-accent" style="font-size:.8rem;">View all →</a>
            </div>

            <?php if ($pending): ?>
            <div class="cw-table-wrap">
                <table class="cw-table">
                    <thead>
                        <tr><th>URL / Email</th><th>Type</th><th>Reporter</th><th>Date</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                        <?php foreach ($pending as $r): ?>
                        <tr>
                            <td style="max-width:200px;">
                                <span class="font-mono" style="font-size:.78rem;word-break:break-all;" title="<?= htmlspecialchars($r['urlOrEmail']) ?>">
                                    <?= htmlspecialchars(mb_strimwidth($r['urlOrEmail'], 0, 35, '…')) ?>
                                </span>
                                <div style="font-size:.75rem;color:var(--cw-muted);"><?= htmlspecialchars(mb_strimwidth($r['description'], 0, 50, '…')) ?></div>
                            </td>
                            <td><span class="badge bg-<?= threat_badge($r['threatType']) ?>"><?= strtoupper($r['threatType']) ?></span></td>
                            <td style="font-size:.82rem;"><?= htmlspecialchars($r['username']) ?></td>
                            <td style="font-size:.78rem;color:var(--cw-muted);white-space:nowrap;"><?= fmt_date($r['submittedAt']) ?></td>
                            <td>
                                <form method="POST" action="approve.php" class="d-inline">
                                    <input type="hidden" name="reportID" value="<?= $r['reportID'] ?>">
                                    <input type="hidden" name="action"   value="approve">
                                    <button type="submit" class="btn btn-sm btn-success py-0 px-2"
                                            data-confirm="Approve and add to blacklist?">
                                        <i class="bi bi-check-lg"></i>
                                    </button>
                                </form>
                                <form method="POST" action="approve.php" class="d-inline ms-1">
                                    <input type="hidden" name="reportID" value="<?= $r['reportID'] ?>">
                                    <input type="hidden" name="action"   value="reject">
                                    <button type="submit" class="btn btn-sm btn-danger py-0 px-2"
                                            data-confirm="Reject this report?">
                                        <i class="bi bi-x-lg"></i>
                                    </button>
                                </form>
                                <a href="report_detail.php?id=<?= $r['reportID'] ?>" class="btn btn-sm btn-cw-ghost py-0 px-2 ms-1">
                                    <i class="bi bi-eye"></i>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php else: ?>
            <div class="text-center py-4 text-cw-muted">
                <i class="bi bi-check-circle" style="font-size:2rem;color:var(--cw-success);display:block;margin-bottom:.5rem;"></i>
                All reports have been reviewed. No pending items.
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Chart -->
    <div class="col-lg-4">
        <div class="cw-card h-100">
            <div class="cw-card-header"><i class="bi bi-bar-chart me-1"></i>Reports (Last 6 Months)</div>
            <canvas id="reportChart" height="220"></canvas>
        </div>
    </div>
</div>

<script>
const ctx = document.getElementById('reportChart').getContext('2d');
new Chart(ctx, {
    type: 'bar',
    data: {
        labels: <?= json_encode($chartLabels) ?>,
        datasets: [{
            label: 'Reports',
            data: <?= json_encode($chartData) ?>,
            backgroundColor: 'rgba(240,165,0,.7)',
            borderColor: '#f0a500',
            borderWidth: 1,
            borderRadius: 4,
        }]
    },
    options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#30363d' } },
            y: { ticks: { color: '#8b949e', font: { size: 10 }, stepSize: 1 }, grid: { color: '#30363d' } }
        }
    }
});
</script>

<?php include '../includes/footer.php'; ?>
