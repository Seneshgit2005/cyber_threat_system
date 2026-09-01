<?php
session_start();
require '../config/db.php';
require '../includes/auth_check.php';
require '../includes/helpers.php';
require_role('admin');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggleRole'])) {
    $uid = filter_input(INPUT_POST, 'userID', FILTER_VALIDATE_INT);
    if ($uid && $uid !== current_user()['userID']) {
        $cur = $pdo->prepare("SELECT role FROM users WHERE userID=?");
        $cur->execute([$uid]); $cur = $cur->fetchColumn();
        $new = $cur === 'admin' ? 'user' : 'admin';
        $pdo->prepare("UPDATE users SET role=? WHERE userID=?")->execute([$new, $uid]);
        redirect(SITE_URL . '/admin/users.php', "User role updated to $new.", 'success');
    }
}

$users = $pdo->query(
    "SELECT u.userID, u.username, u.email, u.role, u.createdAt,
            COUNT(tr.reportID) AS reportCount
     FROM users u
     LEFT JOIN threat_reports tr ON u.userID=tr.userID
     GROUP BY u.userID ORDER BY u.createdAt DESC"
)->fetchAll();

$pageTitle = 'Manage Users';
include '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="cw-page-title mb-0"><i class="bi bi-people me-2"></i>Manage <span>Users</span></h1>
    <a href="dashboard.php" class="btn btn-cw-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Dashboard</a>
</div>

<div class="cw-table-wrap">
    <table class="cw-table">
        <thead>
            <tr><th>#</th><th>Username</th><th>Email</th><th>Role</th><th>Reports</th><th>Joined</th><th>Action</th></tr>
        </thead>
        <tbody>
            <?php foreach ($users as $i => $u): ?>
            <tr>
                <td style="color:var(--cw-muted);font-size:.78rem;"><?= $i+1 ?></td>
                <td style="font-size:.88rem;"><?= htmlspecialchars($u['username']) ?></td>
                <td style="font-size:.82rem;color:var(--cw-muted);"><?= htmlspecialchars($u['email']) ?></td>
                <td>
                    <span class="badge bg-<?= $u['role'] === 'admin' ? 'warning text-dark' : 'secondary' ?>">
                        <?= strtoupper($u['role']) ?>
                    </span>
                </td>
                <td style="font-size:.88rem;"><?= $u['reportCount'] ?></td>
                <td style="font-size:.78rem;color:var(--cw-muted);"><?= fmt_date($u['createdAt']) ?></td>
                <td>
                    <?php if ($u['userID'] !== current_user()['userID']): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="userID" value="<?= $u['userID'] ?>">
                        <button type="submit" name="toggleRole" value="1"
                                class="btn btn-sm btn-cw-ghost py-0 px-2"
                                data-confirm="Toggle role for <?= htmlspecialchars($u['username']) ?>?">
                            <?= $u['role'] === 'admin' ? 'Demote' : 'Promote' ?>
                        </button>
                    </form>
                    <?php else: ?>
                    <span class="text-cw-muted" style="font-size:.78rem;">You</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php include '../includes/footer.php'; ?>
