<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $month = (int)($_GET['month'] ?? date('n'));
    $year  = (int)($_GET['year']  ?? date('Y'));

    $rows = $pdo->prepare(
        "SELECT urlOrEmail, threatType, description, dateReported, status, submittedAt, u.username
         FROM threat_reports tr JOIN users u ON tr.userID=u.userID
         WHERE MONTH(tr.dateReported)=? AND YEAR(tr.dateReported)=?
         ORDER BY tr.dateReported DESC"
    );
    $rows->execute([$month, $year]);
    $data = $rows->fetchAll();

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="awareness_report_' . $year . '_' . str_pad($month,2,'0',STR_PAD_LEFT) . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['URL/Email','Threat Type','Description','Date Reported','Status','Submitted By','Submitted At']);
    foreach ($data as $row) {
        fputcsv($out, [
            $row['urlOrEmail'], $row['threatType'], $row['description'],
            $row['dateReported'], $row['status'], $row['username'], $row['submittedAt']
        ]);
    }
    fclose($out);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate'])) {
    $month = (int)($_POST['month'] ?? date('n'));
    $year  = (int)($_POST['year']  ?? date('Y'));

    $total = $pdo->prepare(
        "SELECT COUNT(*) FROM threat_reports WHERE MONTH(dateReported)=? AND YEAR(dateReported)=?"
    );
    $total->execute([$month, $year]); $total = $total->fetchColumn();

    $byType = $pdo->prepare(
        "SELECT threatType, COUNT(*) AS cnt FROM threat_reports
         WHERE MONTH(dateReported)=? AND YEAR(dateReported)=? GROUP BY threatType"
    );
    $byType->execute([$month, $year]);
    $chartData = [];
    foreach ($byType->fetchAll() as $row) { $chartData[$row['threatType']] = (int)$row['cnt']; }

    // Upsert
    $pdo->prepare(
        "INSERT INTO awareness_reports (month, year, totalReports, chartData, generatedAt, generatedBy)
         VALUES (?,?,?,?,NOW(),?)
         ON DUPLICATE KEY UPDATE totalReports=VALUES(totalReports), chartData=VALUES(chartData), generatedAt=NOW(), generatedBy=VALUES(generatedBy)"
    )->execute([$month, $year, $total, json_encode($chartData), current_user()['userID']]);

    redirect(SITE_URL . "/admin/awareness.php?month=$month&year=$year", "Awareness report for " . date('F Y', mktime(0,0,0,$month,1,$year)) . " generated.", 'success');
}

// Delete report
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_report'])) {
    $reportID = filter_input(INPUT_POST, 'reportID', FILTER_VALIDATE_INT);
    if ($reportID) {
        $pdo->prepare("DELETE FROM awareness_reports WHERE reportID=?")->execute([$reportID]);
        redirect(SITE_URL . '/admin/awareness.php', 'Saved report deleted.', 'success');
    }
}

// Current month stats
$selMonth = (int)($_GET['month'] ?? date('n'));
$selYear  = (int)($_GET['year']  ?? date('Y'));

$monthlyStats = $pdo->prepare(
    "SELECT threatType, COUNT(*) AS cnt FROM threat_reports
     WHERE MONTH(dateReported)=? AND YEAR(dateReported)=? GROUP BY threatType"
);
$monthlyStats->execute([$selMonth, $selYear]);
$monthlyStats = $monthlyStats->fetchAll(PDO::FETCH_KEY_PAIR);

$monthlyTotal = array_sum($monthlyStats);

// Last 12 months trend
$trend = $pdo->query(
    "SELECT DATE_FORMAT(dateReported,'%b %Y') AS mo,
            DATE_FORMAT(dateReported,'%Y-%m') AS sort_key,
            COUNT(*) AS cnt
     FROM threat_reports WHERE dateReported >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
     GROUP BY mo, sort_key ORDER BY sort_key ASC"
)->fetchAll();

// Saved reports
$saved = $pdo->query(
    "SELECT ar.*, u.username FROM awareness_reports ar JOIN users u ON ar.generatedBy=u.userID
     ORDER BY ar.year DESC, ar.month DESC"
)->fetchAll();

$pageTitle = 'Awareness Reports';
include '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-bar-chart me-2"></i>Awareness <span>Reports</span></h1>
    <a href="dashboard.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Dashboard</a>
</div>

<!-- Generate form -->
<div class="cw-card mb-4">
    <div class="cw-card-header"><i class="bi bi-gear me-1"></i>Generate Report</div>
    <form method="POST" class="row g-2 align-items-end">
        <div class="col-md-3">
            <label class="form-label">Month</label>
            <select name="month" class="form-select">
                <?php for ($m = 1; $m <= 12; $m++): ?>
                <option value="<?= $m ?>" <?= $m === $selMonth ? 'selected' : '' ?>><?= date('F', mktime(0,0,0,$m,1)) ?></option>
                <?php endfor; ?>
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label">Year</label>
            <select name="year" class="form-select">
                <?php for ($y = date('Y'); $y >= date('Y')-2; $y--): ?>
                <option value="<?= $y ?>" <?= $y === $selYear ? 'selected' : '' ?>><?= $y ?></option>
                <?php endfor; ?>
            </select>
        </div>
        <div class="col-md-3">
            <button type="submit" name="generate" value="1" class="btn btn-cw-primary w-100">
                <i class="bi bi-arrow-clockwise me-1"></i>Generate &amp; Save
            </button>
        </div>
        <div class="col-md-3">
            <a href="?export=csv&month=<?= $selMonth ?>&year=<?= $selYear ?>" class="btn btn-cw-ghost w-100">
                <i class="bi bi-download me-1"></i>Export CSV
            </a>
        </div>
    </form>
</div>

<!-- Charts Row -->
<div class="row g-4 mb-4">
    <!-- Trend -->
    <div class="col-lg-8">
        <div class="cw-card">
            <div class="cw-card-header"><i class="bi bi-graph-up me-1"></i>12-Month Submission Trend</div>
            <canvas id="trendChart" height="120"></canvas>
        </div>
    </div>
    <!-- Breakdown -->
    <div class="col-lg-4">
        <div class="cw-card">
            <div class="cw-card-header"><i class="bi bi-pie-chart me-1"></i><?= date('F Y', mktime(0,0,0,$selMonth,1,$selYear)) ?> Breakdown</div>
            <div class="text-center mb-2">
                <span class="font-mono" style="font-size:2rem;color:var(--cw-accent);"><?= $monthlyTotal ?></span>
                <div style="font-size:.8rem;color:var(--cw-muted);">total reports</div>
            </div>
            <canvas id="pieChart" height="160"></canvas>
            <div class="mt-3">
                <?php foreach (['phishing'=>'danger','malware'=>'warning','spam'=>'secondary'] as $t => $c): ?>
                <div class="d-flex justify-content-between align-items-center py-1" style="border-bottom:1px solid var(--cw-border);font-size:.85rem;">
                    <span><span class="badge bg-<?= $c ?> me-2"><?= strtoupper($t) ?></span></span>
                    <span><?= $monthlyStats[$t] ?? 0 ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

<!-- Saved Reports -->
<div class="cw-card">
    <div class="cw-card-header"><i class="bi bi-archive me-1"></i>Saved Reports</div>
    <?php if ($saved): ?>
    <div class="cw-table-wrap">
        <table class="cw-table">
            <thead>
                <tr><th>Period</th><th>Total Reports</th><th>Generated By</th><th>Generated At</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <?php foreach ($saved as $s): ?>
                <tr>
                    <td><?= date('F Y', mktime(0,0,0,$s['month'],1,$s['year'])) ?></td>
                    <td><strong><?= $s['totalReports'] ?></strong></td>
                    <td style="font-size:.85rem;"><?= htmlspecialchars($s['username']) ?></td>
                    <td style="font-size:.82rem;color:var(--cw-muted);"><?= $s['generatedAt'] ?></td>
                    <td>
                        <a href="?export=csv&month=<?= $s['month'] ?>&year=<?= $s['year'] ?>"
                           class="btn btn-sm btn-cw-ghost py-0 px-2" title="Export CSV">
                            <i class="bi bi-download"></i>
                        </a>
                        <form method="POST" class="d-inline ms-1 shadow-none">
                            <input type="hidden" name="reportID" value="<?= $s['reportID'] ?>">
                            <button type="submit" name="delete_report" value="1" 
                                    class="btn btn-sm btn-outline-danger py-0 px-2" 
                                    data-confirm="Delete this saved report?">
                                <i class="bi bi-trash"></i>
                            </button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php else: ?>
    <p class="text-cw-muted text-center py-3">No saved reports yet. Generate one above.</p>
    <?php endif; ?>
</div>

<script>
// Trend chart
const trendCtx = document.getElementById('trendChart').getContext('2d');
new Chart(trendCtx, {
    type: 'line',
    data: {
        labels: <?= json_encode(array_column($trend, 'mo')) ?>,
        datasets: [{
            label: 'Reports',
            data: <?= json_encode(array_column($trend, 'cnt')) ?>,
            borderColor: '#f0a500',
            backgroundColor: 'rgba(240,165,0,.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointBackgroundColor: '#f0a500',
            pointRadius: 4,
        }]
    },
    options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#30363d' } },
            y: { ticks: { color: '#8b949e', font:{size:10}, stepSize:1 }, grid: { color: '#30363d' } }
        }
    }
});

// Pie chart
const pieCtx = document.getElementById('pieChart').getContext('2d');
new Chart(pieCtx, {
    type: 'doughnut',
    data: {
        labels: ['Phishing', 'Malware', 'Spam'],
        datasets: [{
            data: [
                <?= $monthlyStats['phishing'] ?? 0 ?>,
                <?= $monthlyStats['malware']  ?? 0 ?>,
                <?= $monthlyStats['spam']     ?? 0 ?>
            ],
            backgroundColor: ['#f85149','#d29922','#8b949e'],
            borderWidth: 0,
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { display: false },
        },
        cutout: '65%',
    }
});
</script>

<?php include '../includes/footer.php'; ?>
