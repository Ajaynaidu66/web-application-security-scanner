<?php
session_start();

// Include utils.php for vulnerability detection functions
include('utils.php');

// Process scan request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
    $url = $_POST['url'];
    
    // Validate URL format
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        $_SESSION['scan_message'] = "Invalid URL format. Please enter a valid URL including http:// or https://";
        $_SESSION['scan_message_type'] = "danger";
        header('Location: index.php');
        exit;
    }
    
    // Perform the vulnerability scan
    $scan_results = scan_website($url);
    
    // Save results in session to display in results page
    $_SESSION['scan_results'] = $scan_results;
    
    // Log vulnerability findings
    if (file_exists('vulnerabilities.php')) {
        include('vulnerabilities.php');
        log_vulnerability($url, $scan_results);
    }
    
    // Redirect to scan results page
    header('Location: scan_results.php');
    exit;
} else {
    // If accessed directly without POST data
    $_SESSION['scan_message'] = "Invalid request. Please submit the scan form.";
    $_SESSION['scan_message_type'] = "danger";
    header('Location: index.php');
    exit;
}
?>