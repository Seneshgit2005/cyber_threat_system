<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_login();

$reportID = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$reportID) {
    http_response_code(400);
    exit('Invalid request.');
}

$stmt = $pdo->prepare(
    "SELECT userID, attachment_path, attachment_name, attachment_mime
     FROM threat_reports WHERE reportID = ?"
);
$stmt->execute([$reportID]);
$report = $stmt->fetch();

if (!$report || !$report['attachment_path']) {
    http_response_code(404);
    exit('Attachment not found.');
}

$me = current_user();
if ((int) $report['userID'] !== (int) $me['userID'] && !is_admin()) {
    http_response_code(403);
    exit('Access denied.');
}

$uploadBase = realpath(__DIR__ . '/../uploads/attachments');
$filePath = realpath($uploadBase . '/' . $report['attachment_path']);

if (!$filePath || strpos($filePath, $uploadBase) !== 0 || !is_file($filePath)) {
    http_response_code(404);
    exit('File not found on server.');
}

$safeName = preg_replace('/[^A-Za-z0-9_.\-]/', '_', $report['attachment_name']);
$mime = $report['attachment_mime'] ?: 'application/octet-stream';

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $safeName . '"');
header('Content-Length: ' . filesize($filePath));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

readfile($filePath);
exit;
