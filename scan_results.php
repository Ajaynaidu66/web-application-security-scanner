<?php
session_start();

// Check if scan results exist in session
if (!isset($_SESSION['scan_results'])) {
    // Redirect to index if no results available
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

// Clean up session after retrieving results
unset($_SESSION['scan_results']);
echo '<pre>';
print_r($_SESSION['scan_results']);
echo '</pre>';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results | Web Vulnerability Scanner</title>
    <!-- Add Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Add Font Awesome for Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- Custom CSS for Styling -->
    <style>
        :root {
            --primary-color: #4a6cf7;
            --secondary-color: #6c757d;
            --success-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;
            --bg-color: #f9fafb;
            --card-bg: #ffffff;
            --text-color: #27272e;
            --shadow: 0 10px 30px rgba(0, 0, 0, 0.05);
        }
        
        body {
            background-color: var(--bg-color);
            font-family: 'Poppins', sans-serif;
            color: var(--text-color);
        }
        
        .container {
            margin-top: 50px;
            margin-bottom: 50px;
        }
        
        .results-box {
            background: var(--card-bg);
            padding: 40px;
            border-radius: 16px;
            box-shadow: var(--shadow);
            transition: transform 0.3s ease;
        }
        
        .header-icon {
            font-size: 40px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .results-title {
            font-weight: 600;
            font-size: 28px;
            margin-bottom: 30px;
            color: var(--text-color);
        }
        
        .url-display {
            background-color: #f8fafc;
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            border-left: 4px solid var(--primary-color);
            word-break: break-all;
        }
        
        .url-label {
            font-weight: 500;
            color: var(--secondary-color);
            margin-bottom: 5px;
            display: block;
        }
        
        .url-value {
            font-family: monospace;
            font-size: 14px;
            color: var(--text-color);
        }
        
        .success-message {
            background-color: rgba(16, 185, 129, 0.1);
            color: var(--success-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
        }
        
        .success-icon {
            font-size: 24px;
            margin-right: 15px;
        }
        
        .vulnerability-list {
            list-style-type: none;
            padding: 0;
            margin-bottom: 25px;
        }
        
        .vulnerability-item {
            background-color: rgba(239, 68, 68, 0.1);
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 10px;
            border-left: 4px solid var(--danger-color);
            transition: transform 0.2s ease;
        }
        
        .vulnerability-item:hover {
            transform: translateX(5px);
        }
        
        .vulnerability-title {
            color: var(--danger-color);
            display: flex;
            align-items: center;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .vulnerability-icon {
            margin-right: 10px;
        }
        
        .btn-back {
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            color: white;
            border-radius: 10px;
            font-weight: 500;
            padding: 12px 25px;
            border: none;
            transition: all 0.3s ease;
            box-shadow: 0 8px 15px rgba(74, 108, 247, 0.15);
            margin-top: 10px;
        }
        
        .btn-back:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(74, 108, 247, 0.2);
            color: white;
        }
        
        .security-rating {
            text-align: center;
            margin-bottom: 25px;
        }
        
        .rating-title {
            font-weight: 500;
            margin-bottom: 10px;
            color: var(--secondary-color);
        }
        
        .rating-value {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 0;
        }
        
        .safe-rating {
            color: var(--success-color);
        }
        
        .warning-rating {
            color: var(--warning-color);
        }
        
        .danger-rating {
            color: var(--danger-color);
        }
        
        .results-summary {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .results-divider {
            height: 1px;
            background-color: #e2e8f0;
            margin: 25px 0;
        }
        
        .rating-badge {
            display: inline-block;
            font-size: 24px;
            font-weight: 700;
            width: 50px;
            height: 50px;
            line-height: 50px;
            border-radius: 50%;
            text-align: center;
            margin-bottom: 15px;
            color: white;
        }
        
        .badge-success {
            background-color: var(--success-color);
        }
        
        .badge-warning {
            background-color: var(--warning-color);
        }
        
        .badge-danger {
            background-color: var(--danger-color);
        }
        
        .pdf-report-btn {
            background-color: #dc3545;
            color: white;
            border-radius: 10px;
            font-weight: 500;
            padding: 10px 20px;
            border: none;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            margin-right: 10px;
        }
        
        .pdf-report-btn i {
            margin-right: 8px;
        }
        
        .pdf-report-btn:hover {
            background-color: #c82333;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 results-box">
                <div class="text-center">
                    <div class="header-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h2 class="results-title">Web Vulnerability Scan Results</h2>
                </div>
                
                <div class="url-display">
                    <span class="url-label">Target URL:</span>
                    <span class="url-value"><?php echo htmlspecialchars($url); ?></span>
                </div>
                
                <div class="success-message">
                    <i class="fas fa-check-circle success-icon"></i>
                    <span>Scan Completed Successfully!</span>
                </div>
                
                <div class="results-summary">
                    <div class="rating-badge badge-<?php echo $security_rating['color']; ?>">
                        <?php echo $security_rating['score']; ?>
                    </div>
                    <h3 class="rating-title">Security Rating</h3>
                    <p class="rating-value <?php echo $security_rating['color']; ?>-rating">
                        <?php echo $security_rating['level']; ?>
                    </p>
                    <p class="mt-3">
                        <?php 
                        if (empty($vulnerabilities)) {
                            echo 'No vulnerabilities were detected. Your website appears to be secure.';
                        } else {
                            echo count($vulnerabilities) . ' vulnerability types detected. See details below.';
                        }
                        ?>
                    </p>
                </div>

                <div class="results-divider"></div>

                <?php if (empty($vulnerabilities)): ?>
                <div class="text-center p-4">
                    <i class="fas fa-check-circle text-success" style="font-size: 48px;"></i>
                    <h4 class="mt-3">No Vulnerabilities Detected</h4>
                    <p>Your website passed all security checks. Keep up the good security practices!</p>
                </div>
                <?php else: ?>
                <h4 class="mb-3">Vulnerability Details:</h4>
                <ul class="vulnerability-list">
                    <?php foreach ($vulnerability_details as $vuln): ?>
                    <li class="vulnerability-item">
                        <div class="vulnerability-title">
                            <i class="fas fa-exclamation-triangle vulnerability-icon"></i>
                            <?php echo htmlspecialchars($vuln['type']); ?>
                        </div>
                        <p><strong>Description:</strong> <?php echo htmlspecialchars($vuln['description']); ?></p>
                        <p><strong>Affected URL:</strong> <?php echo htmlspecialchars($vuln['url']); ?></p>
                    </li>
                    <?php endforeach; ?>
                </ul>
                <?php endif; ?>
                <div class="d-flex justify-content-between mt-4">
                    <a href="index.php" class="btn btn-back">Back to Scanner</a>
                    <a href="generate_pdf.php" class="btn pdf-report-btn">Download PDF Report</a>
                </div>
                
                <div class="mt-4 text-center">
                    <p class="footer-text">
                        <small>This scan provides an overview of potential vulnerabilities. 
                        For a comprehensive security assessment, consider professional penetration testing.</small>
                    </p>
                </div>
            </div>
        </div>
    </div>
    

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Script to enable dismissible alerts
        document.addEventListener('DOMContentLoaded', function() {
            var alertList = document.querySelectorAll('.alert');
            alertList.forEach(function(alert) {
                new bootstrap.Alert(alert);
            });
        });
    </script>
</body>
</html>