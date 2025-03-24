<?php

session_start();

// Define SECURE_ACCESS to include other files securely
define('SECURE_ACCESS', true);

// Include vulnerability statistics if available
$show_stats = false;
$stats = [];
if (file_exists('vulnerabilities.php')) {
    include('vulnerabilities.php');
    
    // Only show stats if we have scan data
    $stats = get_vulnerability_statistics(5);
    $show_stats = ($stats['total_scans'] > 0);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scanner</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #4a6cf7;
            --secondary-color: #6c757d;
            --bg-color: #f9fafb;
            --card-bg: #ffffff;
            --text-color: #27272e;
            --shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            --success-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;
        }
        
        body {
            background-color: var(--bg-color);
            font-family: 'Poppins', sans-serif;
            color: var(--text-color);
        }
        
        .container {
            margin-top: 60px;
            margin-bottom: 60px;
        }
        
        .scanner-box {
            background: var(--card-bg);
            padding: 40px;
            border-radius: 20px;
            box-shadow: var(--shadow);
            transition: transform 0.3s ease;
            margin-bottom: 30px;
        }
        
        .scanner-box:hover {
            transform: translateY(-5px);
        }
        
        .logo-container {
            margin-bottom: 30px;
            text-align: center;
        }
        
        .logo-icon {
            font-size: 60px;
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 15px;
        }
        
        .h1-custom {
            font-weight: 700;
            font-size: 32px;
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .form-control {
            border: 1px solid #e1e5ea;
            border-radius: 10px;
            padding: 14px 20px;
            font-size: 16px;
            transition: all 0.3s ease;
            box-shadow: none;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(74, 108, 247, 0.1);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--secondary-color);
            margin-bottom: 10px;
        }
        
        .btn-custom {
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            color: white;
            border-radius: 10px;
            font-weight: 600;
            padding: 12px 25px;
            border: none;
            transition: all 0.3s ease;
            box-shadow: 0 8px 15px rgba(74, 108, 247, 0.15);
        }
        
        .btn-custom:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(74, 108, 247, 0.2);
            color: white;
        }
        
        .footer-text {
            text-align: center;
            margin-top:  30px;
            color: var(--secondary-color);
            font-size: 14px;
        }

        .alert {
            margin-top: 20px;
            border-radius: 10px;
        }
        
        .features-box {
            background: var(--card-bg);
            border-radius: 20px;
            box-shadow: var(--shadow);
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .feature-item {
            display: flex;
            align-items: flex-start;
            margin-bottom: 20px;
        }
        
        .feature-icon {
            font-size: 24px;
            background: linear-gradient(135deg, #4a6cf7, #8a7fff);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-right: 15px;
            margin-top: 2px;
        }
        
        .feature-text h5 {
            font-weight: 600;
            font-size: 18px;
            margin-bottom: 5px;
        }
        
        .feature-text p {
            color: var(--secondary-color);
            font-size: 15px;
            margin-bottom: 0;
        }
        
        .stats-box {
            background: var(--card-bg);
            border-radius: 20px;
            box-shadow: var(--shadow);
            padding: 30px;
        }
        
        .stats-title {
            font-weight: 600;
            font-size: 24px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background-color: #f8fafc;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 3px solid var(--primary-color);
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 14px;
            color: var(--secondary-color);
        }
        
        .recent-scan {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .recent-scan:last-child {
            border-bottom: none;
        }
        
        .scan-url {
            font-size: 16px;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 220px;
        }
        
        .scan-rating {
            font-size: 14px;
            padding: 4px 10px;
            border-radius: 20px;
            color: white;
        }
        
        .rating-success {
            background-color: var(--success-color);
        }
        
        .rating-warning {
            background-color: var(--warning-color);
        }
        
        .rating-danger {
            background-color: var(--danger-color);
        }
        
        .scan-help {
            padding: 15px;
            margin-top: 20px;
            background-color: rgba(74, 108, 247, 0.1);
            border-radius: 10px;
        }
        
        .scan-help h5 {
            font-weight: 600;
            font-size: 16px;
            color: var(--primary-color);
            margin-bottom: 10px;
        }
        
        .scan-help p {
            font-size: 14px;
            margin-bottom: 0;
        }
        
        .advanced-options {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .advanced-options .form-check {
            margin-bottom: 10px;
        }
        
        .badge-group {
            margin-top: 15px;
        }
        
        .badge-scan-type {
            background-color: #e1e5ea;
            color: var(--secondary-color);
            font-weight: 500;
            font-size: 12px;
            padding: 6px 10px;
            border-radius: 6px;
            margin-right: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .badge-scan-type:hover, .badge-scan-type.active {
            background-color: var(--primary-color);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row">
            <div class="col-lg-6">
                <div class="scanner-box">
                    <div class="logo-container">
                        <div class="logo-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h1 class="h1-custom">Web Vulnerability Scanner</h1>
                    </div>
                    <form action="scan.php" method="POST">
                        <div class="mb-4">
                            <label for="url" class="form-label">Enter URL to scan</label>
                            <div class="input-group">
                                <span class="input-group-text bg-white border-end-0" style="border-radius: 10px 0 0 10px;">
                                    <i class="fas fa-globe" style="color: var(--primary-color);"></i>
                                </span>
                                <input type="url" class="form-control border-start-0" name="url" id="url" placeholder="http://example.com" required>
                            </div>
                        </div>

                        <div class="mb-4">
                            <label for="scanType" class="form-label">Select Scan Type</label>
                            <select class="form-control" name="scanType" id="scanType">
                                <option value="basic">Basic Scan</option>
                                <option value="advanced">Advanced Scan</option>
                            </select>
                        </div>

                        <div class="mb-4 advanced-options">
                            <label class="form-label">Advanced Options</label>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="1" id="includeCookies" name="includeCookies">
                                <label class="form-check-label" for="includeCookies">
                                    Include Cookies in Scan
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="1" id="scanSubdomains" name="scanSubdomains">
                                <label class="form-check-label" for="scanSubdomains">
                                    Scan Subdomains
                                </label>
                            </div>
                        </div>

                        <button type="submit" class="btn-custom w-100">Start Scan</button>
                    </form>
                </div>

            </div>

            <div class="col-lg-6">
                <div class="features-box">
                    <h3 class="h1-custom">Key Features</h3>

                    <div class="feature-item">
                        <div class="feature-icon">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <div class="feature-text">
                            <h5>Comprehensive Vulnerability Scanning</h5>
                            <p>Detects various security flaws, including XSS, SQL Injection, CSRF, and more.</p>
                        </div>
                    </div>

                    <div class="feature-item">
                        <div class="feature-icon">
                            <i class="fas fa-rocket"></i>
                        </div>
                        <div class="feature-text">
                            <h5>Fast and Efficient</h5>
                            <p>Optimized for quick scanning without sacrificing accuracy, ensuring timely results.</p>
                        </div>
                    </div>

                    <div class="feature-item">
                        <div class="feature-icon">
                            <i class="fas fa-cogs"></i>
                        </div>
                        <div class="feature-text">
                            <h5>Customizable Scan Options</h5>
                            <p>Switch between <strong>Basic</strong> and <strong>Advanced</strong> scans, 
                            include cookies for better authentication-based analysis, and 
                            optionally scan subdomains for a broader security assessment.</p>
                        </div>
                    </div>

                </div>
                <?php if ($show_stats && !empty($stats['recent_scans'])): ?>
                    <div class="stats-box mt-5">
                        <h3 class="stats-title">Recent Scans</h3>
                        <?php foreach ($stats['recent_scans'] as $scan): ?>
                            <div class="recent-scan">
                                <div class="scan-url"><?php echo htmlspecialchars($scan['url']); ?></div>
                                <div class="scan-rating <?php echo isset($scan['rating']) ? htmlspecialchars($scan['rating']) : 'unknown'; ?>">
                                    <?php echo isset($scan['rating_label']) ? htmlspecialchars($scan['rating_label']) : 'Unknown'; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

            </div>
        </div>
    </div>

    <div class="footer-text">
        <p>&copy; 2025 Web Vulnerability Scanner. All rights reserved.</p>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 