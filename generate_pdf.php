<?php
require 'vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

session_start();

// Check if scan results exist in session
if (!isset($_SESSION['scan_results'])) {
    error_log("Scan results not found in session."); // Debugging line
    $_SESSION['scan_message'] = "No scan results found. Please perform a scan first.";
    $_SESSION['scan_message_type'] = "warning";
    header('Location: index.php');
    exit;
}

// Get scan results from session
$scan_results = $_SESSION['scan_results'];
$url = $scan_results['scanned_url'];
$vulnerabilities = $scan_results['vulnerabilities'];
$vulnerability_details = $scan_results['details'];
$security_rating = $scan_results['security_rating'];

// Initialize Dompdf
$options = new Options();
$options->set('defaultFont', 'Poppins');
$dompdf = new Dompdf($options);

// Generate HTML for the PDF
$html = '
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .header { text-align: center; font-size: 20px; font-weight: bold; margin-bottom: 20px; }
        .section { margin-bottom: 15px; }
        .title { font-weight: bold; color: #4a6cf7; }
        .vulnerabilities { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">Web Vulnerability Scan Report</div>
    
    <div class="section">
        <span class="title">Scanned URL:</span> ' . htmlspecialchars($url) . '
    </div>

    <div class="section">
        <span class="title">Security Rating:</span> ' . htmlspecialchars($security_rating['level']) . ' (' . htmlspecialchars($security_rating['score']) . ')
    </div>

    <div class="section">
        <span class="title">Vulnerabilities Found:</span> ' . count($vulnerabilities) . '
    </div>';

if (!empty($vulnerabilities)) {
    $html .= '<div class="section title">Vulnerability Details:</div><ul>';
    foreach ($vulnerability_details as $vuln) {
        $html .= '<li class="vulnerabilities">' . htmlspecialchars($vuln['type']) . ': ' . htmlspecialchars($vuln['description']) . '</li>';
    }
    $html .= '</ul>';
} else {
    $html .= '<div class="section">No vulnerabilities were detected. Your website appears to be secure.</div>';
}

$html .= '</body></html>';

// Load HTML into Dompdf
$dompdf->loadHtml($html);

// Set paper size
$dompdf->setPaper('A4', 'portrait');

// Render PDF
$dompdf->render();

// Output PDF for download
$dompdf->stream("Scan_Report.pdf", ["Attachment" => true]);
?>