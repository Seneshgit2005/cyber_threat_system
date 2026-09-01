<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';

$pageTitle = 'System Guide & Usage';
include '../includes/header.php';

$currentRole = 'guest';
if (is_logged_in()) {
    $currentRole = is_admin() ? 'admin' : 'user';
}

$viewRole = $_GET['role'] ?? $currentRole;
if (!in_array($viewRole, ['guest', 'user', 'admin'])) {
    $viewRole = $currentRole;
}
?>

<div class="row justify-content-center">
    <div class="col-lg-10">

        <!-- Header Title -->
        <div
            class="d-flex flex-column flex-md-row align-items-md-center justify-content-md-between mb-4 pb-2 border-bottom border-cw">
            <div>
                <h1 class="cw-page-title mb-1"><i class="bi bi-journal-text me-2"></i>System <span>Guide</span></h1>
                <p class="text-cw-muted mb-0" style="font-size: .9rem;">
                    Step-by-step instructions on how to use, navigate, and interact with the CyberWatch Threat Platform.
                </p>
            </div>

            <!-- Role Selector Tabs -->
            <div class="mt-3 mt-md-0">
                <div class="btn-group btn-group-sm cw-role-switcher" role="group">
                    <a href="?role=guest" class="btn <?= $viewRole === 'guest' ? 'btn-cw-primary' : 'btn-cw-ghost' ?>">
                        <i class="bi bi-eye me-1"></i> Guest View
                    </a>
                    <a href="?role=user" class="btn <?= $viewRole === 'user' ? 'btn-cw-primary' : 'btn-cw-ghost' ?>">
                        <i class="bi bi-person me-1"></i> User View
                    </a>
                    <a href="?role=admin" class="btn <?= $viewRole === 'admin' ? 'btn-cw-primary' : 'btn-cw-ghost' ?>">
                        <i class="bi bi-shield-lock me-1"></i> Admin View
                    </a>
                </div>
            </div>
        </div>

        <!-- Role Banner Indicator -->
        <div class="p-3 mb-4 rounded-3 d-flex align-items-center justify-content-between" style="background: <?php
        echo $viewRole === 'admin' ? 'rgba(210,153,34,.12); border: 1px solid rgba(210,153,34,.3);' :
            ($viewRole === 'user' ? 'rgba(63,185,80,.12); border: 1px solid rgba(63,185,80,.3);' :
                'rgba(88,166,255,.12); border: 1px solid rgba(88,166,255,.3);');
        ?>">
            <div class="d-flex align-items-center gap-3">
                <div class="fs-2">
                    <?php if ($viewRole === 'admin'): ?>
                        <i class="bi bi-speedometer2 text-warning"></i>
                    <?php elseif ($viewRole === 'user'): ?>
                        <i class="bi bi-person-badge text-success"></i>
                    <?php else: ?>
                        <i class="bi bi-globe text-info"></i>
                    <?php endif; ?>
                </div>
                <div>
                    <h5 class="mb-0 fw-bold <?php
                    echo $viewRole === 'admin' ? 'text-warning' : ($viewRole === 'user' ? 'text-success' : 'text-info');
                    ?>">
                        <?php if ($viewRole === 'admin'): ?>
                            Administrator Privileges & Operating Guide
                        <?php elseif ($viewRole === 'user'): ?>
                            Registered User Privileges & Operating Guide
                        <?php else: ?>
                            Public Guest Access & System Introduction
                        <?php endif; ?>
                    </h5>
                    <div class="text-cw-muted" style="font-size: .85rem;">
                        <?php if ($viewRole === 'admin'): ?>
                            Full control over threat reviews, blacklist approvals, system analytics, awareness reports, and
                            user management.
                        <?php elseif ($viewRole === 'user'): ?>
                            Ability to submit threat reports, choose evidence methods, forward emails safely, and track
                            report status.
                        <?php else: ?>
                            Public search access to check URLs/emails against the verified threat blacklist.
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php if ($currentRole === $viewRole): ?>
                <span class="badge bg-secondary font-mono display-desktop-only">YOUR CURRENT ROLE</span>
            <?php endif; ?>
        </div>

        <!-- Global Overview Box -->
        <div class="cw-card mb-4">
            <div class="cw-card-header"><i class="bi bi-info-circle me-1"></i> About CyberWatch</div>
            <p class="mb-0 text-cw-muted" style="font-size: .9rem; line-height: 1.6;">
                <strong>CyberWatch</strong> is a community-driven Cyber Threat Reporting and Awareness System. It allows
                internet users to safely report phishing links, malicious websites, and spam emails. Every report is
                reviewed by administrators before being added to a public blacklist to warn and protect the entire
                community.
            </p>
        </div>

        <!-- GUEST GUIDE -->
        <?php if ($viewRole === 'guest'): ?>
            <div class="d-flex flex-column gap-4">

                <!-- Feature 1: Blacklist Search -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-info">
                        <i class="bi bi-search fs-5"></i> 1. Checking URLs & Emails in Blacklist
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        As a visitor, you can search our community blacklist to check if a website, link, or email address
                        has been flagged as a malicious threat.
                    </p>

                    <div class="cw-guide-steps">
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num">1</span>
                            <div>
                                <strong style="color: var(--cw-text);">Access Search:</strong> Click <a href="lookup.php"
                                    class="text-accent">Check URL/Email</a> in the top navigation bar or use the search bar
                                on the Home page.
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num">2</span>
                            <div>
                                <strong style="color: var(--cw-text);">Enter Target:</strong> Type at least 3 characters of
                                the domain, URL, or email address (e.g. <code>suspicious-login.com</code> or
                                <code>scam@mail.ru</code>).
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start">
                            <span class="cw-step-num">3</span>
                            <div>
                                <strong style="color: var(--cw-text);">Interpret Results:</strong>
                                <ul class="mb-0 mt-1 text-cw-muted" style="font-size: .85rem;">
                                    <li><strong class="text-danger">Threat Match Found:</strong> The item is verified as
                                        dangerous. Do not interact with it!</li>
                                    <li><strong class="text-success">No Matches Found:</strong> The item is not in our
                                        database. If you suspect it's dangerous, register to submit a report!</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 2: Browse Community Blacklist -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-info">
                        <i class="bi bi-database fs-5"></i> 2. Browsing Verified Community Blacklist
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        The full verified threat list is publicly accessible at the bottom of the <a href="lookup.php"
                            class="text-accent">Lookup Page</a>. You can browse recent threats, view threat classifications
                        (Phishing, Malware, Spam), and see when they were verified.
                    </p>
                </div>

                <!-- Feature 3: Registration CTA -->
                <div class="cw-card" style="border-color: rgba(240,165,0,.4); background: rgba(240,165,0,.03);">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-warning">
                        <i class="bi bi-person-plus fs-5"></i> 3. How to Register & Unlock Full Features
                    </div>
                    <p class="text-cw-muted mb-3" style="font-size: .9rem;">
                        To prevent malicious spam submissions, only registered users can report threats. Creating an account
                        takes less than a minute!
                    </p>
                    <div class="d-flex gap-2">
                        <a href="../register.php" class="btn btn-cw-primary"><i class="bi bi-person-plus me-1"></i>Create
                            Account</a>
                        <a href="../login.php" class="btn btn-cw-ghost"><i
                                class="bi bi-box-arrow-in-right me-1"></i>Login</a>
                    </div>
                </div>

            </div>
        <?php endif; ?>


        <!-- USER GUIDE -->
        <?php if ($viewRole === 'user'): ?>
            <div class="d-flex flex-column gap-4">

                <!-- Feature 1: Submitting Reports & Smart Detection -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-success">
                        <i class="bi bi-flag fs-5"></i> 1. Submitting Threat Reports & Smart Evidence Detection
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        Registered users can report suspicious links and emails. The form automatically detects whether your
                        target is an <strong>Email</strong> or <strong>Website/URL</strong> and prompts you for the right
                        evidence.
                    </p>

                    <div class="cw-guide-steps">
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num bg-success text-dark">1</span>
                            <div>
                                <strong style="color: var(--cw-text);">Fill Details:</strong> Navigate to <a
                                    href="submit_report.php" class="text-accent">Report Threat</a>. Enter the suspicious URL
                                or email, select an optional Threat Type (Phishing, Malware, Spam), add a brief description,
                                and set the incident date.
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num bg-success text-dark">2</span>
                            <div>
                                <strong style="color: var(--cw-text);">Automatic Detection:</strong>
                                <div class="p-2 px-3 rounded mt-1 text-cw-muted"
                                    style="background: var(--cw-surface2); font-size: .85rem;">
                                    🧠 <strong>Smart Logic:</strong> If you enter an email address (containing
                                    <code>@</code>) or choose "Spam", the system requires you to choose an <strong>Email
                                        Evidence Method</strong>. If it's a URL, a standard optional file upload dropzone is
                                    provided.
                                </div>
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num bg-success text-dark">3</span>
                            <div>
                                <strong style="color: var(--cw-text);">Monthly Limit Tracking:</strong> Each user has a
                                quota of <strong>5 reports per calendar month</strong>. Your usage counter is prominently
                                displayed on the form.
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 2: Email Forwarding Workflow -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-success">
                        <i class="bi bi-envelope-arrow-up fs-5"></i> 2. Secure Email Forwarding Feature
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        To protect your computer from downloading risky malware attachments, CyberWatch allows you to
                        forward spam mail directly from your inbox to our system!
                    </p>

                    <div class="row g-3 mb-2">
                        <div class="col-md-6">
                            <div class="p-3 rounded h-100"
                                style="background: var(--cw-surface2); border: 1px solid var(--cw-border);">
                                <div class="fw-bold text-accent mb-1"><i class="bi bi-check-circle me-1"></i>How to Forward:
                                </div>
                                <ol class="ps-3 mb-0 text-cw-muted" style="font-size: .83rem; line-height: 1.5;">
                                    <li>Select <strong>Forward Email (Recommended)</strong> when submitting an email report.
                                    </li>
                                    <li>Upon submission, you will receive a unique tracking token (e.g.
                                        <code>CW-4A7F921B_Spam</code>) and system inbox address
                                        (<code>reports@cyberwatch.local</code>).
                                    </li>
                                    <li>Open your email client, click <strong>Forward</strong>, set the recipient, and
                                        <strong>replace the subject with the exact token</strong>.
                                    </li>
                                    <li>Click <strong>Send</strong>.</li>
                                </ol>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="p-3 rounded h-100"
                                style="background: rgba(248,81,73,.08); border: 1px solid rgba(248,81,73,.25);">
                                <div class="fw-bold text-danger mb-1"><i class="bi bi-shield-slash-fill me-1"></i>Safety
                                    Instructions:</div>
                                <ul class="ps-3 mb-0 text-danger" style="font-size: .83rem; line-height: 1.5;">
                                    <li><strong>Never click links</strong> inside a suspicious email!</li>
                                    <li><strong>Never open attachments</strong> inside the suspicious email!</li>
                                    <li>Always copy &amp; paste the exact subject token, otherwise the system cannot link
                                        the email to your report.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 3: My Reports & Download -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-success">
                        <i class="bi bi-list-ul fs-5"></i> 3. Tracking Submission Status & Downloads
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        Go to <a href="my_reports.php" class="text-accent">My Reports</a> to view all your past submissions.
                    </p>
                    <ul class="text-cw-muted mb-0" style="font-size: .85rem; line-height: 1.6;">
                        <li><span class="badge bg-warning text-dark">PENDING</span> — Report is queued for administrator
                            review.</li>
                        <li><span class="badge bg-success">APPROVED</span> — Verified by admin and added to the community
                            blacklist!</li>
                        <li><span class="badge bg-danger">REJECTED</span> — Reviewed and deemed unverified or safe.</li>
                        <li><strong>Attachments:</strong> You can download evidence attachments you uploaded previously at
                            any time.</li>
                    </ul>
                </div>

            </div>
        <?php endif; ?>


        <!-- ADMIN GUIDE -->
        <?php if ($viewRole === 'admin'): ?>
            <div class="d-flex flex-column gap-4">

                <!-- Feature 1: Admin Dashboard & Queue -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-warning">
                        <i class="bi bi-speedometer2 fs-5"></i> 1. Admin Dashboard & Pending Queue
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        Navigate to <a href="../admin/dashboard.php" class="text-warning">Admin Dashboard</a> to oversee
                        platform statistics:
                    </p>
                    <div class="row g-3 mb-2">
                        <div class="col-md-4">
                            <div class="p-2 px-3 rounded"
                                style="background: var(--cw-surface2); border-left: 3px solid var(--cw-warning);">
                                <strong class="text-warning">Live Stat Counters</strong>
                                <div class="text-cw-muted" style="font-size: .8rem;">Pending, Approved, Rejected, Blacklist
                                    total, and User accounts.</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="p-2 px-3 rounded"
                                style="background: var(--cw-surface2); border-left: 3px solid var(--cw-info);">
                                <strong class="text-info">6-Month Trend Chart</strong>
                                <div class="text-cw-muted" style="font-size: .8rem;">Visual Chart.js graph tracking monthly
                                    threat reporting volume.</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="p-2 px-3 rounded"
                                style="background: var(--cw-surface2); border-left: 3px solid var(--cw-danger);">
                                <strong class="text-danger">Pending Queue</strong>
                                <div class="text-cw-muted" style="font-size: .8rem;">Quick table listing submitted threats
                                    awaiting moderation.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 2: Moderating Reports -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-warning">
                        <i class="bi bi-check2-square fs-5"></i> 2. Reviewing, Approving & Blacklisting Reports
                    </div>
                    <p class="text-cw-muted" style="font-size: .9rem;">
                        Go to <a href="../admin/reports.php" class="text-warning">Admin → Reports</a> and click any report
                        to open its detail page:
                    </p>
                    <div class="cw-guide-steps">
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num bg-warning text-dark">1</span>
                            <div>
                                <strong style="color: var(--cw-text);">Verify Evidence:</strong>
                                <ul class="mb-0 text-cw-muted" style="font-size: .85rem;">
                                    <li><strong>If Email Forwarding:</strong> Check the system inbox for an email matching
                                        the displayed subject token (e.g. <code>CW-4A7F921B_Spam</code>).</li>
                                    <li><strong>If Uploaded File:</strong> Safely download the attachment, inspect the
                                        computed <strong>SHA-256 hash</strong>, or click the direct <strong>Search
                                            MalwareBazaar</strong> link.</li>
                                </ul>
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start mb-3">
                            <span class="cw-step-num bg-warning text-dark">2</span>
                            <div>
                                <strong style="color: var(--cw-text);">Approve &amp; Blacklist:</strong> Click <span
                                    class="badge bg-success">Approve &amp; Blacklist</span>. The report status updates to
                                <code>approved</code>, and the URL/email is automatically inserted into the public community
                                blacklist!
                            </div>
                        </div>
                        <div class="d-flex gap-3 align-items-start">
                            <span class="cw-step-num bg-warning text-dark">3</span>
                            <div>
                                <strong style="color: var(--cw-text);">Reject Report:</strong> Click <span
                                    class="badge bg-danger">Reject</span> if the submission is unverified or benign. It is
                                marked as <code>rejected</code> without entering the blacklist.
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Feature 3: Blacklist, Awareness & Users -->
                <div class="cw-card">
                    <div class="d-flex align-items-center gap-2 cw-card-header text-warning">
                        <i class="bi bi-gear fs-5"></i> 3. Blacklist Management, Awareness Reports &amp; User Management
                    </div>
                    <div class="row g-3">
                        <div class="col-md-4">
                            <div class="p-3 rounded h-100" style="background: var(--cw-surface2);">
                                <div class="fw-bold text-cw-text mb-1"><i
                                        class="bi bi-database me-1 text-warning"></i>Blacklist Control</div>
                                <div class="text-cw-muted" style="font-size: .82rem;">
                                    Navigate to <a href="../admin/blacklist.php" class="text-accent">Admin → Blacklist</a>
                                    to directly view or delete entries if needed.
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="p-3 rounded h-100" style="background: var(--cw-surface2);">
                                <div class="fw-bold text-cw-text mb-1"><i
                                        class="bi bi-bar-chart-line me-1 text-info"></i>Awareness Reports</div>
                                <div class="text-cw-muted" style="font-size: .82rem;">
                                    Navigate to <a href="../admin/awareness.php" class="text-accent">Admin → Awareness</a>
                                    to generate monthly statistics and <strong>Export CSV</strong> files.
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="p-3 rounded h-100" style="background: var(--cw-surface2);">
                                <div class="fw-bold text-cw-text mb-1"><i class="bi bi-people me-1 text-success"></i>User
                                    Management</div>
                                <div class="text-cw-muted" style="font-size: .82rem;">
                                    Navigate to <a href="../admin/users.php" class="text-accent">Admin → Users</a> to view
                                    all registered users, roles, and join dates.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        <?php endif; ?>

        <!-- Footer Note -->
        <div class="text-center mt-5 text-cw-muted" style="font-size: .85rem;">
            CyberWatch Cyber Threat Reporting System &bull; University Assignment Project Guidelines
        </div>

    </div>
</div>

<style>
    .cw-role-switcher .btn {
        padding: .4rem .9rem;
        font-size: .82rem;
    }

    .cw-step-num {
        width: 28px;
        height: 28px;
        background: var(--cw-info);
        color: #0d1117;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: var(--font-mono);
        font-weight: 700;
        font-size: .85rem;
        flex-shrink: 0;
    }

    @media (max-width: 767px) {
        .display-desktop-only {
            display: none !important;
        }
    }
</style>

<?php include '../includes/footer.php'; ?>