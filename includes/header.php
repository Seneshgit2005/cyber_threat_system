<?php
$pageTitle = $pageTitle ?? 'CyberWatch';
$flash = get_flash();
$user = current_user();
$nav_base = SITE_URL;
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?> | CyberWatch</title>
    <!-- Favicon -->
    <link rel="icon" href="<?= $nav_base ?>/assets/img/logo.png" type="image/png">

    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link
        href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Sora:wght@300;400;600;700&display=swap"
        rel="stylesheet">
    <!-- Custom CSS -->
    <link href="<?= $nav_base ?>/assets/css/style.css" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>

<body>

    <nav class="navbar navbar-expand-lg navbar-dark cw-navbar sticky-top">
        <div class="container">
            <a class="navbar-brand fw-bold d-flex align-items-center gap-2" href="<?= $nav_base ?>/index.php">
                <span class="cw-logo-icon"><i class="bi bi-shield-shaded"></i></span>
                <span>Cyber<span class="text-warning">Watch</span></span>
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="mainNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link" href="<?= $nav_base ?>/index.php"><i class="bi bi-house me-1"></i>Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?= $nav_base ?>/pages/lookup.php"><i
                                class="bi bi-search me-1"></i>Check URL/Email</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?= $nav_base ?>/pages/guide.php"><i
                                class="bi bi-journal-text me-1"></i>User Guide</a>
                    </li>
                    <?php if (is_logged_in()): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= $nav_base ?>/pages/submit_report.php"><i
                                    class="bi bi-flag me-1"></i>Report Threat</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= $nav_base ?>/pages/my_reports.php"><i
                                    class="bi bi-list-ul me-1"></i>My Reports</a>
                        </li>
                        <?php if (is_admin()): ?>
                            <li class="nav-item">
                                <a class="nav-link text-warning" href="<?= $nav_base ?>/admin/dashboard.php"><i
                                        class="bi bi-speedometer2 me-1"></i>Admin</a>
                            </li>
                        <?php endif; ?>
                    <?php endif; ?>
                </ul>
                <ul class="navbar-nav ms-auto">
                    <?php if (is_logged_in()): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle d-flex align-items-center gap-1" href="#"
                                data-bs-toggle="dropdown">
                                <span class="cw-avatar"><i class="bi bi-person-circle"></i></span>
                                <?= htmlspecialchars($user['username']) ?>
                                <?php if (is_admin()): ?>
                                    <span class="badge bg-warning text-dark ms-1" style="font-size:.65rem;">ADMIN</span>
                                <?php endif; ?>
                            </a>
                            <ul class="dropdown-menu dropdown-menu-end cw-dropdown">
                                <li><a class="dropdown-item" href="<?= $nav_base ?>/pages/dashboard.php"><i
                                            class="bi bi-grid me-2"></i>Dashboard</a></li>
                                <li>
                                    <hr class="dropdown-divider">
                                </li>
                                <li><a class="dropdown-item text-danger" href="<?= $nav_base ?>/logout.php"><i
                                            class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
                            </ul>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= $nav_base ?>/login.php">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="btn btn-warning btn-sm ms-2" href="<?= $nav_base ?>/register.php">Register</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <main class="py-4">
        <div class="container">
            <?php if ($flash): ?>
                <div class="alert alert-<?= $flash['type'] === 'error' ? 'danger' : htmlspecialchars($flash['type']) ?> alert-dismissible fade show"
                    role="alert">
                    <?= htmlspecialchars($flash['msg']) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>