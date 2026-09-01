<?php

function sanitise(string $input): string
{
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function redirect(string $url, string $message = '', string $type = 'success'): void
{
    if ($message) {
        $_SESSION['flash'] = ['msg' => $message, 'type' => $type];
    }
    header("Location: $url");
    exit;
}

function get_flash(): array
{
    $flash = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $flash;
}

function show_flash(): void
{
    $flash = get_flash();
    if (!$flash)
        return;
    $type = $flash['type'] === 'error' ? 'danger' : htmlspecialchars($flash['type']);
    $msg = htmlspecialchars($flash['msg']);
    echo "<div class=\"alert alert-{$type} alert-dismissible fade show\" role=\"alert\">
            {$msg}
            <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\"></button>
          </div>";
}

function fmt_date(string $dt): string
{
    return date('d M Y', strtotime($dt));
}

function threat_badge(string $type): string
{
    return match ($type) {
        'phishing' => 'danger',
        'malware' => 'warning text-dark',
        'spam' => 'secondary',
        default => 'info',
    };
}

function status_badge(string $status): string
{
    return match ($status) {
        'approved' => 'success',
        'rejected' => 'danger',
        'pending' => 'warning text-dark',
        default => 'secondary',
    };
}

