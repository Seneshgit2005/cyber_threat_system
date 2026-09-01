<?php
session_start();
require 'config/db.php';
require 'includes/auth_check.php';
require 'includes/helpers.php';

if (is_logged_in()) {
    redirect(SITE_URL . '/pages/dashboard.php');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = sanitise($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $error = 'Email and password are required.';
    } else {
        $stmt = $pdo->prepare(
            "SELECT userID, username, passwordHash, role FROM users WHERE email = ?"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['passwordHash'])) {
            session_regenerate_id(true);
            $_SESSION['userID'] = $user['userID'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            $dest = $user['role'] === 'admin'
                ? SITE_URL . '/admin/dashboard.php'
                : SITE_URL . '/pages/dashboard.php';
            redirect($dest, 'Welcome back, ' . $user['username'] . '!', 'success');
        } else {
            $error = 'Invalid email or password.';
        }
    }
}

$pageTitle = 'Login';
include 'includes/header.php';
?>

<div class="cw-auth-wrap">
    <div class="cw-auth-box">
        <div class="cw-auth-logo">
            <i class="bi bi-shield-shaded"></i>
            Cyber<span style="color:var(--cw-accent)">Watch</span>
        </div>
        <h2 class="text-center mb-4" style="font-size:1.1rem;color:var(--cw-muted);">Sign in to your account</h2>

        <?php if (!empty($_GET['reason']) && $_GET['reason'] === 'auth'): ?>
            <div class="alert alert-warning">Please log in to access that page.</div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" novalidate>
            <div class="mb-3">
                <label class="form-label">Email Address</label>
                <input type="email" name="email" class="form-control" placeholder="you@example.com" required autofocus>
            </div>
            <div class="mb-4">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" placeholder="*******" required>
            </div>
            <button type="submit" class="btn btn-cw-primary w-100">
                <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
            </button>
        </form>
        <p class="text-center mt-3 mb-0" style="font-size:.85rem;color:var(--cw-muted);">
            Don't have an account? <a href="register.php" class="text-accent">Register</a>
        </p>
    </div>
</div>

<?php include 'includes/footer.php'; ?>