<?php
// Security protection - prevent direct access
if (!defined('SECURE_ACCESS') && basename($_SERVER['PHP_SELF']) == 'vulnerabilities.php') {
    header('HTTP/1.1 403 Forbidden');
    exit('Direct access to this file is forbidden.');
}

// Define SECURE_ACCESS to use this file in other scripts
if (!defined('SECURE_ACCESS')) {
    define('SECURE_ACCESS', true);
}

/**
 * Log detected vulnerabilities to database or file
 * 
 * @param string $url The scanned URL
 * @param array $scan_results The scan results containing vulnerability information
 * @return bool Whether logging was successful
 */
function log_vulnerability($url, $scan_results) {
    // Ensure we have valid scan results
    if (empty($scan_results) || !isset($scan_results['vulnerabilities']) || !isset($scan_results['details'])) {
        return false;
    }
    
    $vulnerabilities = $scan_results['vulnerabilities'];
    $details = $scan_results['details'];
    
    // Skip logging if no vulnerabilities found
    if (empty($vulnerabilities)) {
        return true;
    }
    
    // Prepare data for logging
    $timestamp = date('Y-m-d H:i:s');
    $client_ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown';
    
    // Create log entry
    $log_entry = [
        'timestamp' => $timestamp,
        'url' => $url,
        'client_ip' => $client_ip,
        'user_agent' => $user_agent,
        'security_rating' => $scan_results['security_rating'],
        'vulnerabilities' => $vulnerabilities,
        'details' => $details
    ];
    
    // Convert to JSON for storage
    $log_json = json_encode($log_entry, JSON_PRETTY_PRINT);
    
    // Create logs directory if it doesn't exist
    $logs_dir = 'logs';
    if (!is_dir($logs_dir)) {
        mkdir($logs_dir, 0755, true);
    }
    
    // Generate log filename (using date and URL hash)
    $url_hash = md5($url);
    $log_filename = $logs_dir . '/vuln_' . date('Ymd_His') . '_' . substr($url_hash, 0, 8) . '.json';
    
    // Write log to file
    $result = file_put_contents($log_filename, $log_json);
    
    // Also save to summary CSV for easier analysis
    log_to_summary_csv($log_entry);
    
    return ($result !== false);
}

/**
 * Log vulnerability data to a summary CSV file for easier analysis
 * 
 * @param array $log_entry The vulnerability log entry
 */
function log_to_summary_csv($log_entry) {
    $csv_file = 'logs/vulnerability_summary.csv';
    $file_exists = file_exists($csv_file);
    
    // Open CSV file for appending
    $fp = fopen($csv_file, 'a');
    if (!$fp) {
        return false;
    }
    
    // Write header if file is new
    if (!$file_exists) {
        $header = [
            'Timestamp', 
            'URL', 
            'Security Score', 
            'Security Level', 
            'Vulnerability Count', 
            'Vulnerability Types'
        ];
        fputcsv($fp, $header);
    }
    
    // Prepare and write data row
    $vuln_types = implode(', ', $log_entry['vulnerabilities']);
    $data = [
        $log_entry['timestamp'],
        $log_entry['url'],
        $log_entry['security_rating']['score'],
        $log_entry['security_rating']['level'],
        count($log_entry['vulnerabilities']),
        $vuln_types
    ];
    
    fputcsv($fp, $data);
    fclose($fp);
    
    return true;
}

/**
 * Get recent vulnerability statistics for dashboard
 * 
 * @param int $limit Maximum number of entries to retrieve
 * @return array Statistics about recent vulnerability scans
 */
function get_vulnerability_statistics($limit = 10) {
    $logs_dir = 'logs';
    $csv_file = $logs_dir . '/vulnerability_summary.csv';

    $recent_scans = [];
    $vulnerability_counts = [];
    $vulnerable_sites = 0;

    // Read CSV File
    if (file_exists($csv_file)) {
        $handle = fopen($csv_file, "r");
        if ($handle) {
            fgetcsv($handle); // Skip header row
            while ($row = fgetcsv($handle)) {
                if (count($row) < 6) continue;

                $timestamp = $row[0];
                $url = $row[1];
                $security_level = $row[3];
                $vuln_count = (int)$row[4];
                $vuln_types = explode(", ", $row[5]);

                $recent_scans[] = [
                    'timestamp' => $timestamp,
                    'url' => $url,
                    'security_rating' => $security_level,
                    'vulnerability_count' => $vuln_count
                ];

                if ($vuln_count > 0) {
                    $vulnerable_sites++;
                    foreach ($vuln_types as $vuln) {
                        $vulnerability_counts[$vuln] = ($vulnerability_counts[$vuln] ?? 0) + 1;
                    }
                }
            }
            fclose($handle);
        }
    }

    // Read JSON Logs
    $files = glob($logs_dir . '/vuln_*.json');
    usort($files, function($a, $b) {
        return filemtime($b) - filemtime($a);
    });

    foreach ($files as $file) {
        $content = file_get_contents($file);
        $log = json_decode($content, true);
        
        if ($log) {
            $recent_scans[] = [
                'timestamp' => $log['timestamp'],
                'url' => $log['url'],
                'security_rating' => $log['security_rating'],
                'vulnerability_count' => count($log['vulnerabilities'])
            ];

            if (!empty($log['vulnerabilities'])) {
                $vulnerable_sites++;

                foreach ($log['vulnerabilities'] as $vuln) {
                    $vulnerability_counts[$vuln] = ($vulnerability_counts[$vuln] ?? 0) + 1;
                }
            }
        }
    }

    // Sort vulnerabilities by frequency
    arsort($vulnerability_counts);

    return [
        'recent_scans' => array_slice($recent_scans, 0, $limit),
        'total_scans' => count($recent_scans),
        'vulnerable_sites' => $vulnerable_sites,
        'most_common_vulnerabilities' => $vulnerability_counts
    ];
}


/**
 * Clear all vulnerability logs (admin function)
 * 
 * @param string $admin_password Admin password to confirm deletion
 * @return bool Whether logs were successfully cleared
 */
function clear_vulnerability_logs($admin_password) {
    // Simple protection - in a real app, you'd use proper authentication
    $admin_hash = '5f4dcc3b5aa765d61d8327deb882cf99'; // md5 of 'password'
    
    if (md5($admin_password) !== $admin_hash) {
        return false;
    }
    
    $logs_dir = 'logs';
    if (!is_dir($logs_dir)) {
        return true; // No logs to clear
    }
    
    // Delete all JSON log files
    $json_files = glob($logs_dir . '/vuln_*.json');
    foreach ($json_files as $file) {
        unlink($file);
    }
    
    // Delete the summary CSV file
    if (file_exists($logs_dir . '/vulnerability_summary.csv')) {
        unlink($logs_dir . '/vulnerability_summary.csv');
    }
    
    return true;
}
?>