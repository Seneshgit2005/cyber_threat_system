<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_login();

$max_reports_per_month = 5;
$current_user_id = current_user()['userID'];

$stmt = $pdo->prepare("
    SELECT COUNT(*) as report_count 
    FROM threat_reports 
    WHERE userID = ? 
    AND MONTH(submittedAt) = MONTH(CURRENT_DATE()) 
    AND YEAR(submittedAt) = YEAR(CURRENT_DATE())
");
$stmt->execute([$current_user_id]);
$usage_data = $stmt->fetch();
$current_usage = $usage_data['report_count'] ?? 0;

$limit_reached = ($current_usage >= $max_reports_per_month);

const ATTACH_MAX_BYTES = 10 * 1024 * 1024;
const ATTACH_ALLOWED_EXTS = ['eml', 'msg', 'txt', 'pdf', 'png', 'jpg', 'jpeg'];
const ATTACH_ALLOWED_MIME = [
    'message/rfc822',
    'application/vnd.ms-outlook',
    'application/octet-stream',
    'text/plain',
    'application/pdf',
    'image/png',
    'image/jpeg',
];

$errors = [];
$old = [];
$allowedTypes = ['phishing', 'malware', 'spam'];

function is_email_target(string $val, string $threatType): bool
{
    return filter_var($val, FILTER_VALIDATE_EMAIL) !== false
        || strpos($val, '@') !== false
        || $threatType === 'spam';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($limit_reached) {
        $errors[] = 'You have reached your maximum limit of ' . $max_reports_per_month . ' reports for this month. Please try again next month.';
    }

    $old['urlOrEmail'] = sanitise($_POST['urlOrEmail'] ?? '');
    $old['threatType'] = sanitise($_POST['threatType'] ?? '');
    $old['description'] = sanitise($_POST['description'] ?? '');
    $old['dateReported'] = sanitise($_POST['dateReported'] ?? '');
    $old['evidenceMethod'] = sanitise($_POST['evidenceMethod'] ?? 'forward');

    if (empty($old['urlOrEmail']))
        $errors[] = 'URL or email address is required.';
    elseif (strlen($old['urlOrEmail']) > 500)
        $errors[] = 'URL/email must be under 500 characters.';

    if (!empty($old['threatType']) && !in_array($old['threatType'], $allowedTypes))
        $errors[] = 'Please select a valid threat type.';

    if (!empty($old['description']) && strlen($old['description']) > 1000)
        $errors[] = 'Description must be under 1000 characters.';

    if (empty($old['dateReported']))
        $errors[] = 'Incident date is required.';
    elseif (strtotime($old['dateReported']) > time())
        $errors[] = 'Incident date cannot be in the future.';

    // ── Evidence / Attachment validation ─────────────────────
    $isEmail = is_email_target($old['urlOrEmail'], $old['threatType']);
    $attachPath = null;
    $attachName = null;
    $attachSize = null;
    $attachMime = null;
    $attachHash = null;
    $forwardToken = null;

    if ($isEmail) {
        // For email threats, user MUST choose either 'forward' or 'upload'
        if ($old['evidenceMethod'] === 'forward') {
            $forwardToken = 'CW-' . strtoupper(bin2hex(random_bytes(4)));
        } elseif ($old['evidenceMethod'] === 'upload') {
            if (!isset($_FILES['attachment']) || $_FILES['attachment']['error'] === UPLOAD_ERR_NO_FILE) {
                $errors[] = 'For email threat reports with file upload, an email evidence file (.eml, .msg, .pdf, etc.) is required.';
            }
        } else {
            $errors[] = 'Please select an evidence method for the email threat.';
        }
    }

    // Process file upload if provided (either for URL report or email upload)
    if (!$errors && isset($_FILES['attachment']) && $_FILES['attachment']['error'] !== UPLOAD_ERR_NO_FILE && (!$isEmail || $old['evidenceMethod'] === 'upload')) {
        $file = $_FILES['attachment'];

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $uploadErrors = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds server upload limit.',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form upload limit.',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded.',
                UPLOAD_ERR_NO_TMP_DIR => 'Server temporary directory missing.',
                UPLOAD_ERR_CANT_WRITE => 'Server failed to write file.',
                UPLOAD_ERR_EXTENSION => 'A PHP extension blocked the upload.',
            ];
            $errors[] = $uploadErrors[$file['error']] ?? 'Unknown upload error.';
        } else {
            // Size check
            if ($file['size'] > ATTACH_MAX_BYTES)
                $errors[] = 'Attachment must be under 10 MB.';

            // Extension whitelist
            $origName = basename($file['name']);
            $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
            if (!in_array($ext, ATTACH_ALLOWED_EXTS))
                $errors[] = 'Only .eml, .msg, .txt, .pdf, .png, .jpg and .jpeg attachments are accepted.';

            // MIME check via finfo (server-side, ignores client hint)
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $detectedMime = $finfo->file($file['tmp_name']);

            // .msg files are compound documents — allow common detections
            $isMsgLikeMime = in_array($detectedMime, [
                'application/vnd.ms-office',
                'application/CDFV2',
                'application/CDFV2-corrupt',
                'application/CDFV2-encrypted',
                'application/x-ole-storage',
                'application/msword',
            ]);

            if (!in_array($detectedMime, ATTACH_ALLOWED_MIME) && !$isMsgLikeMime)
                $errors[] = 'File content does not match an allowed type. Upload cancelled for security.';

            // Move file
            if (!$errors) {
                $uploadDir = __DIR__ . '/../uploads/attachments/';
                if (!is_dir($uploadDir)) {
                    if (!mkdir($uploadDir, 0777, true)) {
                        $errors[] = 'Could not create upload directory. Please check folder permissions.';
                    }
                }

                if (!$errors) {
                    if (!is_writable($uploadDir)) {
                        @chmod($uploadDir, 0777);
                    }

                    if (!is_writable($uploadDir)) {
                        $errors[] = 'Upload directory is not writable. Please check folder permissions.';
                    } else {
                        $storedName = bin2hex(random_bytes(16)) . '_' . time() . '.' . $ext;
                        $destPath = $uploadDir . $storedName;

                        if (!move_uploaded_file($file['tmp_name'], $destPath)) {
                            $errors[] = 'Could not save attachment. Please try again.';
                        } else {
                            $attachPath = $storedName;
                            $attachName = $origName;
                            $attachSize = $file['size'];
                            $attachMime = $detectedMime;
                            $attachHash = hash_file('sha256', $destPath);
                        }
                    }
                }
            }
        }
    }

    if (!$errors) {
        $stmt = $pdo->prepare(
            "INSERT INTO threat_reports
             (userID, urlOrEmail, threatType, description, dateReported, status, submittedAt,
              attachment_path, attachment_name, attachment_size, attachment_mime, attachment_hash, forward_token)
             VALUES (?, ?, ?, ?, ?, 'pending', NOW(), ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            current_user()['userID'],
            $old['urlOrEmail'],
            (!empty($old['threatType']) ? $old['threatType'] : null),
            (!empty($old['description']) ? $old['description'] : null),
            $old['dateReported'],
            $attachPath,
            $attachName,
            $attachSize,
            $attachMime,
            $attachHash,
            $forwardToken
        ]);

        $reportId = $pdo->lastInsertId();

        if ($forwardToken) {
            redirect(SITE_URL . '/pages/forward_instructions.php?id=' . $reportId);
        } else {
            redirect(
                SITE_URL . '/pages/my_reports.php',
                'Report submitted successfully. It will be reviewed by an administrator.',
                'success'
            );
        }
    }
}

$pageTitle = 'Submit Threat Report';
include '../includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-lg-8">

        <h1 class="cw-page-title"><i class="bi bi-flag me-2"></i>Submit a <span>Threat Report</span></h1>

        <?php if ($errors): ?>
            <div class="alert alert-danger mb-4">
                <strong><i class="bi bi-exclamation-triangle me-1"></i>Please fix the following:</strong>
                <ul class="mb-0 mt-1 ps-3">
                    <?php foreach ($errors as $e): ?>
                        <li><?= htmlspecialchars($e) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if ($limit_reached): ?>
            <div class="alert alert-danger mb-4 shadow-sm border-0">
                <div class="d-flex align-items-center mb-2">
                    <i class="bi bi-x-circle-fill fs-4 me-2"></i>
                    <h5 class="mb-0 fw-bold">Monthly Limit Reached</h5>
                </div>
                You have submitted <strong><?= $current_usage ?></strong> out of your
                <strong><?= $max_reports_per_month ?></strong> allowed reports this month. You cannot submit any more
                reports until next month. Thank you for your contributions!
            </div>
        <?php else: ?>
            <div class="alert alert-info mb-4 shadow-sm border-0"
                style="background-color: rgba(88, 166, 255, 0.08); border-left: 4px solid var(--cw-info) !important;">
                <div class="d-flex align-items-center mb-1">
                    <i class="bi bi-info-circle-fill me-2 text-info"></i>
                    <strong class="text-info">Monthly Usage Status</strong>
                </div>
                <div class="ms-4 text-cw-muted" style="font-size: 0.9rem;">
                    You have submitted <strong class="text-white"><?= $current_usage ?></strong> of <strong
                        class="text-white"><?= $max_reports_per_month ?></strong> allowed reports this month.
                </div>
            </div>
        <?php endif; ?>

        <div class="cw-card">
            <div class="cw-card-header"><i class="bi bi-pencil me-1"></i>Report Details</div>
            <form method="POST" enctype="multipart/form-data" novalidate id="reportForm">

                <div class="mb-3">
                    <label class="form-label">Suspicious URL or Email Address <span class="text-danger">*</span></label>
                    <input type="text" name="urlOrEmail" id="urlOrEmailInput" class="form-control font-mono"
                        value="<?= htmlspecialchars($old['urlOrEmail'] ?? '') ?>"
                        placeholder="e.g. http://fake-login.com or phisher@scam.ru" required>
                    <small class="text-cw-muted">Paste the exact URL or email address you encountered.</small>
                </div>

                <div class="mb-3">
                    <label class="form-label d-flex align-items-center gap-2">
                        Threat Type
                        <span class="badge bg-secondary" style="font-size:.7rem;font-weight:500;">Optional</span>
                    </label>
                    <select name="threatType" id="threatTypeSelect" class="form-select">
                        <option value="">— Not sure / Select if known —</option>
                        <option value="phishing" <?= ($old['threatType'] ?? '') === 'phishing' ? 'selected' : '' ?>>
                            Phishing – Fake login pages, credential harvesting
                        </option>
                        <option value="malware" <?= ($old['threatType'] ?? '') === 'malware' ? 'selected' : '' ?>>
                            Malware – Malicious downloads, exploits
                        </option>
                        <option value="spam" <?= ($old['threatType'] ?? '') === 'spam' ? 'selected' : '' ?>>
                            Spam – Bulk unsolicited emails, scam offers
                        </option>
                    </select>
                    <small class="text-cw-muted">Don't know the type? Leave it blank — an admin will classify it during
                        review.</small>
                </div>

                <div class="mb-3">
                    <label class="form-label d-flex align-items-center gap-2">
                        Description
                        <span class="badge bg-secondary" style="font-size:.7rem;font-weight:500;">Optional</span>
                    </label>
                    <textarea name="description" class="form-control" rows="4" data-maxlength="1000"
                        placeholder="Describe what you encountered (optional) — e.g. how did you find this? What did it ask for?"><?= htmlspecialchars($old['description'] ?? '') ?></textarea>
                    <small class="text-cw-muted">Any extra context helps, but you can leave this blank if
                        unsure.</small>
                </div>

                <div class="mb-3">
                    <label class="form-label">Date of Incident <span class="text-danger">*</span></label>
                    <input type="date" name="dateReported" class="form-control"
                        value="<?= htmlspecialchars($old['dateReported'] ?? date('Y-m-d')) ?>"
                        max="<?= date('Y-m-d') ?>" required>
                </div>

                <!-- EVIDENCE SECTION -->

                <!-- 1. EMAIL THREAT EVIDENCE BLOCK (Auto-shown if email is detected) -->
                <div id="emailEvidenceBlock" class="mb-4 d-none">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <label class="form-label mb-0 fw-semibold" style="color: var(--cw-text);">
                            <i class="bi bi-shield-lock text-warning me-1"></i>Email Evidence Method <span
                                class="text-danger">*</span>
                        </label>
                        <span class="badge bg-warning text-dark"><i class="bi bi-exclamation-circle me-1"></i>Required
                            for Email Threats</span>
                    </div>

                    <div class="row g-3 mb-3">
                        <!-- Option 1: Forward Email (Default) -->
                        <div class="col-md-6">
                            <label class="cw-option-card h-100" for="methodForward" id="cardForward">
                                <div class="d-flex align-items-start gap-2">
                                    <input class="form-check-input mt-1" type="radio" name="evidenceMethod"
                                        id="methodForward" value="forward" <?= ($old['evidenceMethod'] ?? 'forward') === 'forward' ? 'checked' : '' ?>>
                                    <div>
                                        <div class="fw-bold" style="color: var(--cw-accent); font-size: 0.95rem;">
                                            <i class="bi bi-envelope-arrow-up me-1"></i>Forward Email
                                        </div>
                                        <span class="badge bg-success text-dark my-1"
                                            style="font-size: 0.65rem;">RECOMMENDED</span>
                                        <p class="mb-0 text-cw-muted" style="font-size: 0.8rem; line-height: 1.4;">
                                            Safely forward the spam mail directly from your inbox to our secure system.
                                            Avoids storing malware on your computer.
                                        </p>
                                    </div>
                                </div>
                            </label>
                        </div>

                        <!-- Option 2: Upload File -->
                        <div class="col-md-6">
                            <label class="cw-option-card h-100" for="methodUpload" id="cardUpload">
                                <div class="d-flex align-items-start gap-2">
                                    <input class="form-check-input mt-1" type="radio" name="evidenceMethod"
                                        id="methodUpload" value="upload" <?= ($old['evidenceMethod'] ?? '') === 'upload' ? 'checked' : '' ?>>
                                    <div>
                                        <div class="fw-bold" style="color: var(--cw-text); font-size: 0.95rem;">
                                            <i class="bi bi-file-earmark-arrow-up me-1"></i>Upload Email File
                                        </div>
                                        <span class="badge bg-secondary my-1" style="font-size: 0.65rem;">FILE
                                            REQUIRED</span>
                                        <p class="mb-0 text-cw-muted" style="font-size: 0.8rem; line-height: 1.4;">
                                            Upload a downloaded .eml / .msg file or screenshot if you have already
                                            safely extracted it.
                                        </p>
                                    </div>
                                </div>
                            </label>
                        </div>
                    </div>

                    <!-- Forwarding Preview Info -->
                    <div id="forwardInfoNotice" class="p-3 rounded mb-3"
                        style="background: rgba(240, 165, 0, 0.06); border: 1px solid rgba(240, 165, 0, 0.25);">
                        <div class="d-flex align-items-center gap-2 mb-1"
                            style="color: var(--cw-accent); font-weight: 600; font-size: 0.88rem;">
                            <i class="bi bi-info-circle-fill"></i> How Forwarding Works:
                        </div>
                        <div class="text-cw-muted" style="font-size: 0.82rem; line-height: 1.5;">
                            When you submit this form, we will generate a <strong>unique subject tracking token</strong>
                            and display the system recipient email. You can then simply open your email client, paste
                            the subject, and hit Forward!
                        </div>
                    </div>
                </div>

                <!-- 2. NON-EMAIL / URL EVIDENCE HEADER (Auto-shown if URL/website is detected) -->
                <div id="urlEvidenceHeader" class="mb-2">
                    <label class="form-label d-flex align-items-center gap-2 mb-0">
                        <i class="bi bi-paperclip text-cw-accent"></i>
                        Evidence Attachment
                        <span class="badge bg-secondary" style="font-size:.7rem;font-weight:500;">Optional</span>
                    </label>
                    <small class="text-cw-muted d-block mt-1">Optional: Attach a screenshot or proof if available (max
                        10 MB).</small>
                </div>

                <!-- 3. SHARED DROPZONE SECTION -->
                <div id="dropzoneContainer" class="mb-4">
                    <div class="attach-dropzone" id="attachDropzone">
                        <div class="attach-icon"><i class="bi bi-cloud-arrow-up"></i></div>
                        <p class="attach-prompt">
                            Drag &amp; drop your evidence file here, or <span class="attach-browse">browse</span>
                        </p>
                        <p class="attach-hint">
                            Accepted: <strong>.eml</strong>, <strong>.msg</strong>, <strong>.txt</strong>,
                            <strong>.pdf</strong>, <strong>.png</strong>, <strong>.jpg</strong> &mdash; max 10 MB
                        </p>
                        <input type="file" name="attachment" id="attachInput"
                            accept=".eml,.msg,.txt,.pdf,.png,.jpg,.jpeg" class="attach-file-input">
                    </div>

                    <!-- Selected-file preview chip -->
                    <div id="attachPreview" class="attach-preview d-none mt-2">
                        <span class="attach-preview-icon"><i class="bi bi-file-earmark-text"
                                id="attachPreviewIcon"></i></span>
                        <span class="attach-preview-name text-white" id="attachPreviewName"></span>
                        <span class="attach-preview-size text-cw-muted" id="attachPreviewSize"></span>
                        <button type="button" class="attach-remove btn btn-sm" id="attachRemove"
                            title="Remove attachment">
                            <i class="bi bi-x-lg"></i>
                        </button>
                    </div>

                    <div class="mt-2" style="font-size:.8rem;color:var(--cw-muted);">
                        <i class="bi bi-shield-lock me-1 text-cw-accent"></i>
                        Files are stored in an isolated, access-controlled directory and are never publicly accessible.
                    </div>
                </div>

                <div class="d-flex gap-2 pt-2">
                    <button type="submit" class="btn btn-cw-primary" id="submitBtn" <?= $limit_reached ? 'disabled' : '' ?>>
                        <i class="bi bi-send me-2"></i>Submit Report
                    </button>
                    <a href="dashboard.php" class="btn btn-cw-ghost">Cancel</a>
                </div>
            </form>
        </div>

        <div class="cw-card mt-3" style="border-color:rgba(240,165,0,.2);background:rgba(240,165,0,.04);">
            <div style="font-size:.85rem;color:var(--cw-muted);">
                <strong style="color:var(--cw-accent);"><i class="bi bi-info-circle me-1"></i>What happens
                    next?</strong><br>
                Your report will be placed in a <em>pending</em> queue for administrator review. Once verified, it will
                be added to the community blacklist. You can track your submission on the
                <a href="my_reports.php" class="text-accent">My Reports</a> page.
            </div>
        </div>

    </div>
</div>

<style>
    .cw-option-card {
        display: block;
        background: var(--cw-surface2);
        border: 1px solid var(--cw-border);
        border-radius: 10px;
        padding: 1rem;
        cursor: pointer;
        transition: all 0.2s ease;
    }

    .cw-option-card:hover {
        border-color: rgba(240, 165, 0, 0.4);
        background: rgba(255, 255, 255, 0.03);
    }

    .cw-option-card.active {
        border-color: var(--cw-accent) !important;
        background: rgba(240, 165, 0, 0.08) !important;
        box-shadow: 0 0 0 1px var(--cw-accent);
    }

    .attach-dropzone {
        position: relative;
        border: 2px dashed rgba(240, 165, 0, .35);
        border-radius: 10px;
        padding: 1.75rem 1.5rem;
        text-align: center;
        cursor: pointer;
        background: rgba(240, 165, 0, .02);
        transition: border-color .2s, background .2s;
    }

    .attach-dropzone:hover,
    .attach-dropzone.drag-over {
        border-color: var(--cw-accent);
        background: rgba(240, 165, 0, .07);
    }

    .attach-dropzone .attach-icon {
        font-size: 2rem;
        color: var(--cw-accent);
        margin-bottom: .4rem;
        transition: transform .2s;
    }

    .attach-dropzone:hover .attach-icon {
        transform: translateY(-3px);
    }

    .attach-prompt {
        margin-bottom: .25rem;
        font-size: .92rem;
        color: var(--cw-text, #e2e8f0);
    }

    .attach-browse {
        color: var(--cw-accent);
        font-weight: 600;
        text-decoration: underline;
        cursor: pointer;
    }

    .attach-hint {
        font-size: .78rem;
        color: var(--cw-muted);
        margin-bottom: 0;
    }

    .attach-file-input {
        position: absolute;
        inset: 0;
        width: 100%;
        height: 100%;
        opacity: 0;
        cursor: pointer;
    }

    .attach-preview {
        display: flex;
        align-items: center;
        gap: .6rem;
        background: rgba(255, 255, 255, .06);
        border: 1px solid rgba(240, 165, 0, .3);
        border-radius: 8px;
        padding: .55rem .85rem;
    }

    .attach-preview-icon {
        font-size: 1.4rem;
        color: var(--cw-accent);
        flex-shrink: 0;
    }

    .attach-preview-name {
        font-size: .85rem;
        font-weight: 500;
        flex: 1;
        word-break: break-all;
    }

    .attach-preview-size {
        font-size: .75rem;
        white-space: nowrap;
    }

    .attach-remove {
        background: transparent;
        border: none;
        color: var(--cw-muted);
        padding: 0 .2rem;
        line-height: 1;
        transition: color .15s;
    }

    .attach-remove:hover {
        color: #ef4444;
    }
</style>

<script>
    (function () {
        const urlInput = document.getElementById('urlOrEmailInput');
        const threatSelect = document.getElementById('threatTypeSelect');
        const emailBlock = document.getElementById('emailEvidenceBlock');
        const urlHeader = document.getElementById('urlEvidenceHeader');
        const dropzoneContainer = document.getElementById('dropzoneContainer');
        const forwardNotice = document.getElementById('forwardInfoNotice');
        const dropzone = document.getElementById('attachDropzone');
        const fileInput = document.getElementById('attachInput');
        const preview = document.getElementById('attachPreview');
        const prevName = document.getElementById('attachPreviewName');
        const prevSize = document.getElementById('attachPreviewSize');
        const prevIcon = document.getElementById('attachPreviewIcon');
        const removeBtn = document.getElementById('attachRemove');
        const radioForward = document.getElementById('methodForward');
        const radioUpload = document.getElementById('methodUpload');
        const cardForward = document.getElementById('cardForward');
        const cardUpload = document.getElementById('cardUpload');
        const MAX_BYTES = 10 * 1024 * 1024;

        // Check if current input represents an email threat
        function isEmailThreat() {
            const val = (urlInput.value || '').trim();
            const type = (threatSelect.value || '');
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            const containsAt = val.includes('@');
            return containsAt || emailRegex.test(val) || type === 'spam';
        }

        function updateEvidenceUI() {
            const isEmail = isEmailThreat();

            if (isEmail) {
                emailBlock.classList.remove('d-none');
                urlHeader.classList.add('d-none');

                if (radioForward.checked) {
                    cardForward.classList.add('active');
                    cardUpload.classList.remove('active');
                    forwardNotice.classList.remove('d-none');
                    dropzoneContainer.classList.add('d-none');
                } else {
                    cardUpload.classList.add('active');
                    cardForward.classList.remove('active');
                    forwardNotice.classList.add('d-none');
                    dropzoneContainer.classList.remove('d-none');
                }
            } else {
                emailBlock.classList.add('d-none');
                urlHeader.classList.remove('d-none');
                forwardNotice.classList.add('d-none');
                dropzoneContainer.classList.remove('d-none');
            }
        }

        urlInput.addEventListener('input', updateEvidenceUI);
        threatSelect.addEventListener('change', updateEvidenceUI);
        radioForward.addEventListener('change', updateEvidenceUI);
        radioUpload.addEventListener('change', updateEvidenceUI);

        // Run on initial page load
        updateEvidenceUI();

        // Attachment handling
        const iconMap = {
            eml: 'bi-envelope-at',
            msg: 'bi-envelope-arrow-up',
            pdf: 'bi-file-earmark-pdf',
            txt: 'bi-file-earmark-text',
            png: 'bi-file-earmark-image',
            jpg: 'bi-file-earmark-image',
            jpeg: 'bi-file-earmark-image',
        };

        function fmtSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / 1048576).toFixed(2) + ' MB';
        }

        function showFile(file) {
            if (!file) return;
            const ext = file.name.split('.').pop().toLowerCase();
            const icon = iconMap[ext] || 'bi-file-earmark';

            if (file.size > MAX_BYTES) {
                alert('Attachment exceeds the 10 MB limit. Please choose a smaller file.');
                clearFile(); return;
            }

            prevIcon.className = 'bi ' + icon;
            prevName.textContent = file.name;
            prevSize.textContent = fmtSize(file.size);
            preview.classList.remove('d-none');
            dropzone.style.display = 'none';
        }

        function clearFile() {
            fileInput.value = '';
            preview.classList.add('d-none');
            dropzone.style.display = '';
        }

        fileInput.addEventListener('change', () => showFile(fileInput.files[0]));
        removeBtn.addEventListener('click', clearFile);

        dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
        dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
        dropzone.addEventListener('drop', e => {
            e.preventDefault();
            dropzone.classList.remove('drag-over');
            const dt = e.dataTransfer;
            if (dt && dt.files.length) {
                const transfer = new DataTransfer();
                transfer.items.add(dt.files[0]);
                fileInput.files = transfer.files;
                showFile(dt.files[0]);
            }
        });
    })();
</script>

<?php include '../includes/footer.php'; ?>