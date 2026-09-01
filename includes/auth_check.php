<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function require_login()
{
    if (empty($_SESSION['userID'])) {
        header('Location: ' . SITE_URL . '/login.php?reason=auth');
        exit;
    }
}

function require_role(string $role)
{
    require_login();
    if (($_SESSION['role'] ?? '') !== $role) {
        header('Location: ' . SITE_URL . '/pages/dashboard.php?reason=forbidden');
        exit;
    }
}

function is_logged_in(): bool
{
    return !empty($_SESSION['userID']);
}

function is_admin(): bool
{
    return ($_SESSION['role'] ?? '') === 'admin';
}

function current_user(): array
{
    return [
        'userID' => $_SESSION['userID'] ?? null,
        'username' => $_SESSION['username'] ?? '',
        'role' => $_SESSION['role'] ?? 'user',
    ];
}
