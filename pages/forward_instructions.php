<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_login();

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$id)
    redirect(SITE_URL . '/pages/my_reports.php', 'Invalid report.', 'error');

$stmt = $pdo->prepare("SELECT * FROM threat_reports WHERE reportID = ? AND userID = ?");
$stmt->execute([$id, current_user()['userID']]);
$report = $stmt->fetch();

if (!$report || empty($report['forward_token'])) {
    redirect(SITE_URL . '/pages/my_reports.php', 'Invalid report or no forwarding token found.', 'error');
}

$pageTitle = 'Forwarding Instructions';
include '../includes/header.php';

$subject = $report['forward_token'] . '_' . ($report['threatType'] ? ucfirst($report['threatType']) : 'Report');
$systemEmail = SYSTEM_REPORT_EMAIL;
?>

<div class="row justify-content-center">
    <div class="col-lg-8">

        <!-- Header confirmation badge -->
        <div class="p-3 mb-4 rounded-3 d-flex align-items-center gap-3"
            style="background: rgba(63, 185, 80, 0.1); border: 1px solid rgba(63, 185, 80, 0.3);">
            <i class="bi bi-check-circle-fill text-success fs-2 flex-shrink-0"></i>
            <div>
                <h5 class="mb-1 fw-bold text-success">Report Registered (#<?= $id ?>)</h5>
                <p class="mb-0 text-cw-muted" style="font-size: 0.88rem;">
                    Your report details are saved. Follow the simple steps below to safely forward the suspicious email.
                </p>
            </div>
        </div>

        <div class="cw-card">
            <div class="cw-card-header d-flex align-items-center justify-content-between">
                <span><i class="bi bi-envelope-arrow-up me-2"></i>Email Forwarding Guide</span>
                <span class="badge bg-warning text-dark font-mono">TOKEN:
                    <?= htmlspecialchars($report['forward_token']) ?></span>
            </div>

            <div class="py-2">

                <!-- STEP 1 -->
                <div class="cw-step-item">
                    <div class="d-flex align-items-start gap-3">
                        <div class="cw-step-num">01</div>
                        <div class="flex-grow-1">
                            <h6 class="fw-bold mb-1" style="color: var(--cw-text);">Open the Suspicious Email</h6>
                            <p class="text-cw-muted mb-2" style="font-size: 0.88rem;">
                                Go to your email client (Gmail, Outlook, Yahoo, etc.) and locate the threat message.
                            </p>
                            <!-- Warning with Step 1 without alert tag -->
                            <div class="p-2 px-3 rounded d-flex align-items-center gap-2"
                                style="background: rgba(248, 81, 73, 0.08); border: 1px solid rgba(248, 81, 73, 0.25); color: #ff7b72; font-size: 0.83rem;">
                                <i class="bi bi-shield-slash-fill fs-6 text-danger flex-shrink-0"></i>
                                <span><strong>Safety Warning:</strong> Do not click any links or download/open
                                    attachments inside the suspicious email!</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="cw-step-divider"></div>

                <!-- STEP 2 -->
                <div class="cw-step-item">
                    <div class="d-flex align-items-start gap-3">
                        <div class="cw-step-num">02</div>
                        <div class="flex-grow-1">
                            <h6 class="fw-bold mb-1" style="color: var(--cw-text);">Click Forward</h6>
                            <p class="text-cw-muted mb-0" style="font-size: 0.88rem;">
                                Hit the <strong>Forward</strong> button in your email reader to start creating the
                                message.
                            </p>
                        </div>
                    </div>
                </div>

                <div class="cw-step-divider"></div>

                <!-- STEP 3 -->
                <div class="cw-step-item">
                    <div class="d-flex align-items-start gap-3">
                        <div class="cw-step-num">03</div>
                        <div class="flex-grow-1">
                            <h6 class="fw-bold mb-1" style="color: var(--cw-text);">Enter Recipient Email Address</h6>
                            <p class="text-cw-muted mb-2" style="font-size: 0.88rem;">
                                In your email client's <strong>To</strong> field, enter our secure analysis recipient:
                            </p>
                            <div class="input-group" style="max-width: 440px;">
                                <input type="text" class="form-control font-mono" id="copyEmail"
                                    value="<?= htmlspecialchars($systemEmail) ?>" readonly
                                    style="background: var(--cw-surface2); color: var(--cw-text);">
                                <button class="btn btn-cw-ghost" type="button"
                                    onclick="copyToClipboard('copyEmail', this)">
                                    <i class="bi bi-clipboard me-1"></i> Copy Email
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="cw-step-divider"></div>

                <!-- STEP 4 -->
                <div class="cw-step-item">
                    <div class="d-flex align-items-start gap-3">
                        <div class="cw-step-num">04</div>
                        <div class="flex-grow-1">
                            <h6 class="fw-bold mb-1" style="color: var(--cw-text);">Replace the Email Subject</h6>
                            <p class="text-cw-muted mb-2" style="font-size: 0.88rem;">
                                Clear the existing subject line and replace it completely with this unique tracking
                                token:
                            </p>
                            <div class="input-group mb-2" style="max-width: 440px;">
                                <input type="text" class="form-control font-mono fw-bold text-cw-accent"
                                    id="copySubject" value="<?= htmlspecialchars($subject) ?>" readonly
                                    style="background: var(--cw-surface2);">
                                <button class="btn btn-cw-primary" type="button"
                                    onclick="copyToClipboard('copySubject', this)">
                                    <i class="bi bi-clipboard me-1"></i> Copy Subject
                                </button>
                            </div>

                            <!-- Prominently highlighted notice -->
                            <div class="p-3 rounded mt-2"
                                style="background: rgba(240, 165, 0, 0.1); border: 1px solid rgba(240, 165, 0, 0.35); box-shadow: 0 0 15px rgba(240, 165, 0, 0.05);">
                                <div class="d-flex align-items-center gap-2 text-warning fw-bold mb-1"
                                    style="font-size: 0.88rem;">
                                    <i class="bi bi-exclamation-triangle-fill"></i> CRITICAL: Exact Subject Required
                                </div>
                                <div style="color: #ffd166; font-size: 0.83rem; line-height: 1.5;">
                                    If you do not use this exact subject line, the system cannot link the forwarded
                                    email to your threat report (#<?= $id ?>).
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="cw-step-divider"></div>

                <!-- STEP 5 -->
                <div class="cw-step-item">
                    <div class="d-flex align-items-start gap-3">
                        <div class="cw-step-num">05</div>
                        <div class="flex-grow-1">
                            <h6 class="fw-bold mb-1" style="color: var(--cw-text);">Send the Email</h6>
                            <p class="text-cw-muted mb-0" style="font-size: 0.88rem;">
                                Click <strong>Send</strong>. Once received, our administrators will inspect the message
                                in the secure inbox and review your report!
                            </p>
                        </div>
                    </div>
                </div>

            </div>

            <div class="d-flex gap-2 pt-4 border-top border-cw mt-3">
                <a href="my_reports.php" class="btn btn-cw-primary">
                    <i class="bi bi-list-check me-2"></i>Go to My Reports
                </a>
                <a href="submit_report.php" class="btn btn-cw-ghost">
                    Submit Another Report
                </a>
            </div>
        </div>
    </div>
</div>

<style>
    .cw-step-num {
        width: 38px;
        height: 38px;
        background: rgba(240, 165, 0, 0.12);
        border: 1px solid rgba(240, 165, 0, 0.3);
        color: var(--cw-accent);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: var(--font-mono);
        font-weight: 700;
        font-size: 0.95rem;
        flex-shrink: 0;
    }

    .cw-step-item {
        padding: 0.5rem 0.25rem;
    }

    .cw-step-divider {
        width: 95%;
        height: 1px;
        margin: 1.2rem auto;
        background: rgba(255, 255, 255, 0.07);
    }
</style>

<script>
    function copyToClipboard(elementId, btnElement) {
        var copyText = document.getElementById(elementId);
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(copyText.value).then(function () {
            var originalHtml = btnElement.innerHTML;
            btnElement.innerHTML = '<i class="bi bi-check2 me-1"></i> Copied!';
            btnElement.classList.add('btn-success');
            btnElement.classList.remove('btn-cw-primary', 'btn-cw-ghost');
            setTimeout(function () {
                btnElement.innerHTML = originalHtml;
                btnElement.classList.remove('btn-success');
                if (elementId === 'copyEmail') {
                    btnElement.classList.add('btn-cw-ghost');
                } else {
                    btnElement.classList.add('btn-cw-primary');
                }
            }, 2000);
        });
    }
</script>

<?php include '../includes/footer.php'; ?>