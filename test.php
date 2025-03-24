<?php
include('vulnerabilities.php');

$stats = get_vulnerability_statistics(5);
header('Content-Type: application/json');
echo json_encode($stats, JSON_PRETTY_PRINT);
