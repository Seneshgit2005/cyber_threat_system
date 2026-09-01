<?php
session_start();
require 'config/db.php';
require 'includes/auth_check.php';
require 'includes/helpers.php';

if (is_logged_in()) {
    redirect(SITE_URL . '/pages/dashboard.php');
}

$errors = [];
$old = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $old['username'] = sanitise($_POST['username'] ?? '');
    $old['email'] = sanitise($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm'] ?? '';

    if (empty($old['username']))
        $errors[] = 'Username is required.';
    elseif (strlen($old['username']) < 3)
        $errors[] = 'Username must be at least 3 characters.';

    if (empty($old['email']))
        $errors[] = 'Email address is required.';
    elseif (!filter_var($old['email'], FILTER_VALIDATE_EMAIL))
        $errors[] = 'Invalid email address.';

    if (empty($password))
        $errors[] = 'Password is required.';
    elseif (strlen($password) < 8)
        $errors[] = 'Password must be at least 8 characters.';

    if ($password !== $confirm)
        $errors[] = 'Passwords do not match.';

    if (!$errors) {
        $chk = $pdo->prepare("SELECT userID FROM users WHERE email = ?");
        $chk->execute([$old['email']]);
        if ($chk->rowCount() > 0) {
            $errors[] = 'An account with this email already exists.';
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $ins = $pdo->prepare(
                "INSERT INTO users (username, email, passwordHash, role, createdAt)
                 VALUES (?, ?, ?, 'user', NOW())"
            );
            $ins->execute([$old['username'], $old['email'], $hash]);
            redirect(SITE_URL . '/login.php', 'Registration successful! Please log in.', 'success');
        }
    }
}

$pageTitle = 'Register';
include 'includes/header.php';
?>

<div class="cw-auth-wrap">
    <div class="cw-auth-box">
        <div class="cw-auth-logo">
            <i class="bi bi-shield-shaded"></i>
            Cyber<span style="color:var(--cw-accent)">Watch</span>
        </div>
        <h2 class="text-center mb-4" style="font-size:1.1rem;color:var(--cw-muted);">Create your account</h2>

        <?php if ($errors): ?>
            <div class="alert alert-danger">
                <ul class="mb-0 ps-3">
                    <?php foreach ($errors as $e): ?>
                        <li><?= htmlspecialchars($e) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="POST" novalidate>
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" name="username" class="form-control"
                    value="<?= htmlspecialchars($old['username'] ?? '') ?>" placeholder="e.g. john_doe" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Email Address</label>
                <input type="email" name="email" class="form-control"
                    value="<?= htmlspecialchars($old['email'] ?? '') ?>" placeholder="you@example.com" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password <span style="font-size:.78rem;color:var(--cw-muted);">(min. 8
                        characters)</span></label>
                <input type="password" name="password" class="form-control" placeholder="••••••••" required>
            </div>
            <div class="mb-4">
                <label class="form-label">Confirm Password</label>
                <input type="password" name="confirm" class="form-control" placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn btn-cw-primary w-100">
                <i class="bi bi-person-plus me-2"></i>Create Account
            </button>
        </form>
        <p class="text-center mt-3 mb-0" style="font-size:.85rem;color:var(--cw-muted);">
            Already have an account? <a href="login.php" class="text-accent">Sign in</a>
        </p>
    </div>
</div>

<?php include 'includes/footer.php'; ?>