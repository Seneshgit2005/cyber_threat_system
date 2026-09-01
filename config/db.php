<?php
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'cyber_threat_db');
define('DB_USER', 'root');
define('DB_PASS', 'Sewick197427');
define('DB_PORT', '3306');

define('SITE_NAME', 'CyberWatch');
define('SITE_URL', 'http://localhost/cyber_threat_system');
define('SYSTEM_REPORT_EMAIL', 'reports@cyberwatch.local');

try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST
        . ";port=" . DB_PORT
        . ";dbname=" . DB_NAME
        . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    die(json_encode([
        'error' => true,
        'message' => 'Database connection failed. Please check your configuration.'
    ]));
}

