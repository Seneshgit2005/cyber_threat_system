<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect(SITE_URL . '/admin/dashboard.php');
}

$reportID = filter_input(INPUT_POST, 'reportID', FILTER_VALIDATE_INT);
$action   = sanitise($_POST['action'] ?? '');
$redirect = SITE_URL . '/admin/reports.php';

if (!$reportID || !in_array($action, ['approve', 'reject'])) {
    redirect($redirect, 'Invalid request.', 'error');
}

$fetch = $pdo->prepare(
    "SELECT reportID, urlOrEmail, threatType, status, attachment_hash FROM threat_reports WHERE reportID=?"
);
$fetch->execute([$reportID]);
$report = $fetch->fetch();

if (!$report) {
    redirect($redirect, 'Report not found.', 'error');
}
if ($report['status'] !== 'pending') {
    redirect($redirect, 'This report has already been processed.', 'warning');
}

if ($action === 'approve') {
    $pdo->prepare("UPDATE threat_reports SET status='approved' WHERE reportID=?")
        ->execute([$reportID]);

    $pdo->prepare(
        "INSERT INTO blacklist (urlOrEmail, threatType, addedDate, verifiedBy, attachment_hash)
         VALUES (?, ?, NOW(), ?, ?)"
    )->execute([
        $report['urlOrEmail'],
        $report['threatType'],
        current_user()['userID'],
        $report['attachment_hash'],
    ]);

    redirect($redirect, 'Report approved and added to the blacklist.', 'success');

} else {
    $pdo->prepare("UPDATE threat_reports SET status='rejected' WHERE reportID=?")
        ->execute([$reportID]);
    redirect($redirect, 'Report rejected.', 'success');
}
