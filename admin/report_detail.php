<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$id)
    redirect(SITE_URL . '/admin/reports.php', 'Invalid report.', 'error');

$stmt = $pdo->prepare(
    "SELECT tr.*, u.username, u.email AS userEmail
     FROM threat_reports tr JOIN users u ON tr.userID=u.userID
     WHERE tr.reportID=?"
);
$stmt->execute([$id]);
$report = $stmt->fetch();
if (!$report)
    redirect(SITE_URL . '/admin/reports.php', 'Report not found.', 'error');

$pageTitle = 'Report #' . $id;
include '../includes/header.php';

function fmt_bytes(int $bytes): string
{
    if ($bytes < 1024)
        return $bytes . ' B';
    if ($bytes < 1048576)
        return round($bytes / 1024, 1) . ' KB';
    return round($bytes / 1048576, 2) . ' MB';
}
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-file-text me-2"></i>Report <span>#<?= $id ?></span></h1>
    <a href="reports.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Back</a>
</div>

<div class="row g-4">
    <div class="col-lg-8">
        <div class="cw-card mb-4">
            <div class="cw-card-header"><i class="bi bi-info-circle me-1"></i>Report Details</div>
            <dl class="row mb-0" style="font-size:.9rem;">
                <dt class="col-sm-3 text-cw-muted">URL / Email</dt>
                <dd class="col-sm-9 font-mono" style="word-break:break-all;">
                    <?= htmlspecialchars($report['urlOrEmail']) ?></dd>
                <dt class="col-sm-3 text-cw-muted">Threat Type</dt>
                <dd class="col-sm-9">
                    <?php if (!empty($report['threatType'])): ?>
                        <span
                            class="badge bg-<?= threat_badge($report['threatType']) ?>"><?= strtoupper($report['threatType']) ?></span>
                    <?php else: ?>
                        <span class="badge bg-secondary">UNCLASSIFIED</span>
                        <small class="text-cw-muted ms-1">(Admin will classify during review)</small>
                    <?php endif; ?>
                </dd>
                <dt class="col-sm-3 text-cw-muted">Status</dt>
                <dd class="col-sm-9"><span
                        class="badge bg-<?= status_badge($report['status']) ?>"><?= strtoupper($report['status']) ?></span>
                </dd>
                <dt class="col-sm-3 text-cw-muted">Date of Incident</dt>
                <dd class="col-sm-9"><?= fmt_date($report['dateReported']) ?></dd>
                <dt class="col-sm-3 text-cw-muted">Submitted At</dt>
                <dd class="col-sm-9"><?= $report['submittedAt'] ?></dd>
                <dt class="col-sm-3 text-cw-muted">Description</dt>
                <dd class="col-sm-9" style="white-space:pre-line;">
                    <?php if (!empty($report['description'])): ?>
                        <?= htmlspecialchars($report['description']) ?>
                    <?php else: ?>
                        <em class="text-cw-muted">No description provided.</em>
                    <?php endif; ?>
                </dd>
            </dl>
        </div>

        <!-- Email Forward Section -->
        <?php if (!empty($report['forward_token'])): ?>
            <div class="cw-card mb-4" style="border-color:rgba(13, 202, 240, 0.3);">
                <div class="cw-card-header text-info"><i class="bi bi-envelope-check me-1"></i>Email Forward Evidence</div>
                <p class="mb-2" style="font-size:.9rem;">
                    The reporter opted to forward the suspicious email to the system inbox (<strong><?= SYSTEM_REPORT_EMAIL?></strong>).
                </p>
                <div class="p-3 rounded"
                    style="background:rgba(13, 202, 240, 0.05); border:1px solid rgba(13, 202, 240, 0.2);">
                    <div class="text-cw-muted mb-1" style="font-size:.8rem;">Check the system inbox for an email with the
                        subject:</div>
                    <div class="font-mono fw-bold fs-5 text-info user-select-all">
                        <?= htmlspecialchars($report['forward_token'] . '_' . ($report['threatType'] ? ucfirst($report['threatType']) : 'Report')) ?>
                    </div>
                </div>
                <div class="mt-3 p-2 rounded"
                    style="background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);font-size:.78rem;color:#fca5a5;">
                    <i class="bi bi-exclamation-triangle me-1"></i>
                    <strong>Security reminder:</strong> Handle the forwarded email cautiously. Open attachments or links
                    within that forwarded email only in an isolated environment.
                </div>
            </div>
        <?php endif; ?>

        <!-- Attachment Section -->
        <?php if (!empty($report['attachment_path'])): ?>
            <div class="cw-card" style="border-color:rgba(240,165,0,.3);">
                <div class="cw-card-header"><i class="bi bi-paperclip me-1"></i>Evidence Attachment</div>
                <div class="d-flex align-items-center gap-3 flex-wrap">
                    <div class="attach-admin-icon">
                        <?php
                        $ext = strtolower(pathinfo($report['attachment_name'], PATHINFO_EXTENSION));
                        $iconMap = [
                            'eml' => 'bi-envelope-at',
                            'msg' => 'bi-envelope-arrow-up',
                            'pdf' => 'bi-file-earmark-pdf',
                            'txt' => 'bi-file-earmark-text',
                            'png' => 'bi-file-earmark-image',
                            'jpg' => 'bi-file-earmark-image',
                            'jpeg' => 'bi-file-earmark-image',
                        ];
                        $icon = $iconMap[$ext] ?? 'bi-file-earmark';
                        ?>
                        <i class="bi <?= $icon ?>"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div style="font-weight:500;font-size:.92rem;"><?= htmlspecialchars($report['attachment_name']) ?>
                        </div>
                        <div style="font-size:.78rem;color:var(--cw-muted);">
                            <?= htmlspecialchars($report['attachment_mime'] ?? 'Unknown type') ?>
                            &nbsp;·&nbsp;
                            <?= $report['attachment_size'] ? fmt_bytes((int) $report['attachment_size']) : 'Unknown size' ?>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <a href="<?= SITE_URL ?>/pages/download_attachment.php?id=<?= $id ?>"
                            class="btn btn-cw-ghost btn-sm d-flex align-items-center gap-1">
                            <i class="bi bi-download"></i> Download
                        </a>
                    </div>
                </div>

                <?php if (!empty($report['attachment_hash'])): ?>
                    <div class="mt-3 p-3 rounded" style="background:rgba(255,255,255,.03);border:1px solid var(--cw-border);">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="text-cw-muted" style="font-size:.78rem;"><i class="bi bi-hash me-1"></i>SHA-256
                                Fingerprint</span>
                            <span class="badge bg-dark font-mono"
                                style="font-size:.7rem;border:1px solid var(--cw-border);">AUTOMATED HASH</span>
                        </div>
                        <div class="font-mono mb-3" style="font-size:.82rem;word-break:break-all;color:var(--cw-accent);">
                            <?= $report['attachment_hash'] ?></div>

                        <div class="d-flex flex-wrap gap-2">
                            <a href="https://www.virustotal.com/gui/file/<?= $report['attachment_hash'] ?>" target="_blank"
                                class="btn btn-sm btn-outline-info" style="font-size:.75rem;">
                                <i class="bi bi-search me-1"></i> Search VirusTotal
                            </a>
                            <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A<?= $report['attachment_hash'] ?>"
                                target="_blank" class="btn btn-sm btn-outline-warning"
                                style="font-size:.75rem;color:#f0a30a;border-color:#f0a30a;">
                                <i class="bi bi-search me-1"></i> Search MalwareBazaar
                            </a>
                        </div>
                    </div>
                <?php endif; ?>
                <div class="mt-3 p-2 rounded"
                    style="background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);font-size:.78rem;color:#fca5a5;">
                    <i class="bi bi-exclamation-triangle me-1"></i>
                    <strong>Security reminder:</strong> This file was submitted by a user. Treat it as potentially
                    malicious.
                    Open it only in a sandboxed or isolated environment, never on a production machine.
                </div>
            </div>

            <style>
                .attach-admin-icon {
                    width: 52px;
                    height: 52px;
                    background: rgba(240, 165, 0, .1);
                    border: 1px solid rgba(240, 165, 0, .3);
                    border-radius: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 1.6rem;
                    color: var(--cw-accent);
                    flex-shrink: 0;
                }
            </style>

        <?php elseif (empty($report['forward_token'])): ?>
            <div class="cw-card" style="border-color:rgba(255,255,255,.07);opacity:.7;">
                <div class="cw-card-header"><i class="bi bi-paperclip me-1"></i>Evidence Attachment</div>
                <p class="mb-0 text-cw-muted" style="font-size:.88rem;">
                    <i class="bi bi-dash-circle me-1"></i>No attachment was included with this report.
                </p>
            </div>
        <?php endif; ?>
    </div>

    <div class="col-lg-4">
        <div class="cw-card mb-3">
            <div class="cw-card-header"><i class="bi bi-person me-1"></i>Reporter</div>
            <p class="mb-1" style="font-size:.9rem;"><?= htmlspecialchars($report['username']) ?></p>
            <p class="mb-0 text-cw-muted" style="font-size:.82rem;"><?= htmlspecialchars($report['userEmail']) ?></p>
        </div>

        <?php if ($report['status'] === 'pending'): ?>
            <div class="cw-card" style="border-color:rgba(240,165,0,.3);">
                <div class="cw-card-header"><i class="bi bi-check2-circle me-1"></i>Actions</div>
                <form method="POST" action="approve.php" class="mb-2">
                    <input type="hidden" name="reportID" value="<?= $id ?>">
                    <input type="hidden" name="action" value="approve">
                    <button type="submit" class="btn btn-success w-100" data-confirm="Approve and add to blacklist?">
                        <i class="bi bi-check-lg me-1"></i>Approve &amp; Blacklist
                    </button>
                </form>
                <form method="POST" action="approve.php">
                    <input type="hidden" name="reportID" value="<?= $id ?>">
                    <input type="hidden" name="action" value="reject">
                    <button type="submit" class="btn btn-danger w-100" data-confirm="Reject this report?">
                        <i class="bi bi-x-lg me-1"></i>Reject Report
                    </button>
                </form>
            </div>
        <?php else: ?>
            <div class="alert alert-<?= $report['status'] === 'approved' ? 'success' : 'danger' ?>">
                This report has been <strong><?= $report['status'] ?></strong>.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php include '../includes/footer.php'; ?>