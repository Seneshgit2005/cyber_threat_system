<?php
session_start();
require 'config/db.php';
require 'includes/auth_check.php';
require 'includes/helpers.php';

$pageTitle = 'Home';

$stats = [];
$stats['total'] = $pdo->query("SELECT COUNT(*) FROM blacklist")->fetchColumn();
$stats['phishing'] = $pdo->query("SELECT COUNT(*) FROM blacklist WHERE threatType='phishing'")->fetchColumn();
$stats['malware'] = $pdo->query("SELECT COUNT(*) FROM blacklist WHERE threatType='malware'")->fetchColumn();
$stats['reports'] = $pdo->query("SELECT COUNT(*) FROM threat_reports")->fetchColumn();

$recent = $pdo->query(
    "SELECT urlOrEmail, threatType, addedDate
     FROM blacklist ORDER BY addedDate DESC LIMIT 5"
)->fetchAll();

include 'includes/header.php';
?>

<!-- Hero -->
<section class="cw-hero">
    <div class="container">
        <h1>Protect Your Community<br>From <span>Cyber Threats</span></h1>
        <p>Report suspicious URLs and emails, check our verified blacklist, and stay aware of the latest threats — all
            in one accessible platform.</p>
        <div class="cw-hero-actions">
            <a href="pages/lookup.php" class="btn btn-cw-primary px-4 py-2">
                <i class="bi bi-search me-2"></i>Check a URL or Email
            </a>
            <?php if (!is_logged_in()): ?>
                <a href="register.php" class="btn btn-cw-ghost px-4 py-2">
                    <i class="bi bi-person-plus me-2"></i>Create Account
                </a>
            <?php else: ?>
                <a href="pages/submit_report.php" class="btn btn-cw-ghost px-4 py-2">
                    <i class="bi bi-flag me-2"></i>Report a Threat
                </a>
            <?php endif; ?>
        </div>
    </div>
</section>

<!-- Stats Row -->
<section class="mb-5">
    <div class="container">
        <div class="row g-3">
            <div class="col-6 col-md-3">
                <div class="cw-stat">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="cw-stat-number"><?= number_format($stats['total']) ?></div>
                            <div class="cw-stat-label">Verified Threats</div>
                        </div>
                        <i class="bi bi-shield-x cw-stat-icon"></i>
                    </div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="cw-stat danger">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="cw-stat-number"><?= number_format($stats['phishing']) ?></div>
                            <div class="cw-stat-label">Phishing Sites</div>
                        </div>
                        <i class="bi bi-hook cw-stat-icon"></i>
                    </div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="cw-stat info">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="cw-stat-number"><?= number_format($stats['malware']) ?></div>
                            <div class="cw-stat-label">Malware Sources</div>
                        </div>
                        <i class="bi bi-bug cw-stat-icon"></i>
                    </div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="cw-stat success">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="cw-stat-number"><?= number_format($stats['reports']) ?></div>
                            <div class="cw-stat-label">Reports Submitted</div>
                        </div>
                        <i class="bi bi-flag cw-stat-icon"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Quick Lookup & Recent Threats -->
<section class="mb-5">
    <div class="container">
        <div class="row g-4">
            <!-- Quick Lookup -->
            <div class="col-lg-7">
                <div class="cw-card h-100">
                    <div class="cw-card-header"><i class="bi bi-search me-1"></i> Quick Blacklist Check</div>
                    <p class="text-cw-muted mb-3" style="font-size:.9rem;">Enter a URL or email address to check if it
                        has been verified as a threat.</p>
                    <form method="POST" action="pages/lookup.php">
                        <div class="cw-search-group">
                            <input type="text" name="searchTerm" class="form-control"
                                placeholder="e.g. suspicious-site.com or phish@email.ru" required>
                            <button type="submit" class="btn btn-cw-primary">
                                <i class="bi bi-search me-1"></i>Check
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Recent Verified Threats -->
            <div class="col-lg-5">
                <div class="cw-card h-100">
                    <div class="cw-card-header"><i class="bi bi-clock-history me-1"></i> Recently Verified Threats</div>
                    <?php if ($recent): ?>
                        <ul class="list-unstyled mb-0">
                            <?php foreach ($recent as $r): ?>
                                <li class="d-flex align-items-center gap-2 py-2"
                                    style="border-bottom:1px solid var(--cw-border);">
                                    <span
                                        class="badge bg-<?= threat_badge($r['threatType'] ?? 'unknown') ?>"><?= strtoupper($r['threatType'] ?? 'unknown') ?></span>
                                    <span class="font-mono text-truncate" style="font-size:.8rem;flex:1;"
                                        title="<?= htmlspecialchars($r['urlOrEmail']) ?>">
                                        <?= htmlspecialchars(mb_strimwidth($r['urlOrEmail'], 0, 38, '…')) ?>
                                    </span>
                                    <span class="text-cw-muted"
                                        style="font-size:.75rem;white-space:nowrap;"><?= date('d M', strtotime($r['addedDate'])) ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                        <div class="mt-3">
                            <a href="pages/lookup.php" class="btn btn-cw-ghost btn-sm w-100">View Full Blacklist</a>
                        </div>
                    <?php else: ?>
                        <p class="text-cw-muted">No verified threats yet.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- How It Works -->
<section class="mb-5">
    <div class="container">
        <h2 class="cw-page-title">How It <span>Works</span></h2>
        <div class="row g-3">
            <?php
            $steps = [
                ['bi-person-plus', 'Register', 'Create a free account to start submitting and tracking threat reports.'],
                ['bi-flag', 'Report', 'Submit a suspicious URL or email with details about what you encountered.'],
                ['bi-shield-check', 'Verified', 'Administrators review and verify each report before it enters the blacklist.'],
                ['bi-bell', 'Community Alert', 'Verified threats are shared with all users to protect the whole community.'],
            ];
            foreach ($steps as $i => [$icon, $title, $desc]): ?>
                <div class="col-6 col-md-3">
                    <div class="cw-card text-center h-100">
                        <div style="font-size:2rem;color:var(--cw-accent);margin-bottom:.5rem;"><i
                                class="bi bi-<?= $icon ?>"></i></div>
                        <div class="font-mono" style="font-size:.75rem;color:var(--cw-muted);margin-bottom:.25rem;">STEP
                            <?= $i + 1 ?>
                        </div>
                        <div class="fw-600" style="font-size:.95rem;margin-bottom:.5rem;"><?= $title ?></div>
                        <div style="font-size:.82rem;color:var(--cw-muted);"><?= $desc ?></div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<!-- System Guide Banner Section -->
<section class="mb-5">
    <div class="container">
        <div class="cw-card"
            style="background: linear-gradient(135deg, var(--cw-surface) 0%, var(--cw-surface2) 100%); border-color: rgba(240, 165, 0, 0.3);">
            <div class="row align-items-center g-4">
                <div class="col-lg-8">
                    <div class="d-flex align-items-center gap-2 mb-2 text-warning fw-bold font-mono"
                        style="font-size: .85rem;">
                        <i class="bi bi-book-half"></i> NEED HELP GETTING STARTED?
                    </div>
                    <h3 class="fw-bold mb-2 text-white">Full System &amp; User Guide</h3>
                    <p class="text-cw-muted mb-0" style="font-size: .95rem; line-height: 1.6;">
                        Explore our comprehensive role-based guide detailing how to report threats, forward emails
                        safely, track your reports, and manage verified blacklist entries.
                    </p>
                </div>
                <div class="col-lg-4 text-lg-end">
                    <a href="pages/guide.php" class="btn btn-cw-primary px-4 py-2">
                        <i class="bi bi-journal-text me-2"></i>Read Full Guide
                    </a>
                </div>
            </div>
        </div>
    </div>
</section>

<?php include 'includes/footer.php'; ?>