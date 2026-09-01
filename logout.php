<?php
session_start();
session_unset();
session_destroy();
header('Location: ' . 'http://localhost/cyber_threat_system/login.php');
exit;
