<?php
// Function to get the response of a URL with better error handling and timeout settings
function get_url_response($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        return ['error' => $error, 'code' => $http_code, 'body' => ''];
    }
    
    return ['error' => null, 'code' => $http_code, 'body' => $response];
}

// SQL Injection Detection - Improved to check for error patterns
function check_sql_injection($url) {
    $payloads = [
        "' OR '1'='1",
        "1 UNION SELECT 1,2,3--",
        "1' AND 1=1 --",
        "1'; DROP TABLE users--",
        "1' OR '1'='1' #",
        "admin' --"
    ];
    
    $sql_error_patterns = [
        "sql syntax",
        "mysql error",
        "syntax error",
        "microsoft sql server",
        "unclosed quotation mark",
        "oracle database error",
        "postgresql query failed",
        "sqlite3"
    ];
    
    $test_endpoints = ["", "/login", "/search", "/user", "/product", "/id"];
    
    foreach ($test_endpoints as $endpoint) {
        $base_test_url = rtrim($url, '/') . $endpoint;
        
        // Test GET parameters
        foreach ($payloads as $payload) {
            $test_url = $base_test_url . "?id=" . urlencode($payload);
            $response = get_url_response($test_url);
            
            if (!$response['error']) {
                // Check for SQL error patterns in the response
                foreach ($sql_error_patterns as $pattern) {
                    if (stripos($response['body'], $pattern) !== false) {
                        return [
                            'vulnerable' => true,
                            'type' => 'SQL Injection',
                            'url' => $test_url,
                            'description' => 'SQL injection vulnerability detected. The application may be exposing database error messages.'
                        ];
                    }
                }
                
                // Check if there's a difference in response code or size compared to normal request
                $normal_response = get_url_response($base_test_url);
                if ($response['code'] != $normal_response['code'] || 
                    (abs(strlen($response['body']) - strlen($normal_response['body'])) > 500)) {
                    return [
                        'vulnerable' => true,
                        'type' => 'Potential SQL Injection',
                        'url' => $test_url,
                        'description' => 'Potential SQL injection point detected. Different response observed with SQL injection payload.'
                    ];
                }
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Cross-Site Scripting (XSS) Detection - Improved to check for reflected input
function check_xss($url) {
    $unique_marker = md5(uniqid());
    $payloads = [
        "<script>alert('" . $unique_marker . "')</script>",
        "<img src='x' onerror='alert(\"" . $unique_marker . "\")'>",
        "<svg/onload=alert('" . $unique_marker . "')>",
        "';alert(" . $unique_marker . ");//",
        "\"><script>alert('" . $unique_marker . "')</script>"
    ];
    
    $test_endpoints = ["", "/search", "/login", "/contact", "/feedback", "/comment"];
    
    foreach ($test_endpoints as $endpoint) {
        $base_test_url = rtrim($url, '/') . $endpoint;
        
        // Test GET parameters
        foreach ($payloads as $payload) {
            $test_url = $base_test_url . "?q=" . urlencode($payload);
            $response = get_url_response($test_url);
            
            if (!$response['error'] && stripos($response['body'], $payload) !== false) {
                return [
                    'vulnerable' => true,
                    'type' => 'Cross-Site Scripting (XSS)',
                    'url' => $test_url,
                    'description' => 'XSS vulnerability detected. The application reflects user input without proper sanitization.'
                ];
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Open Redirect Detection - Improved with multiple payloads and verification
function check_open_redirect($url) {
    $redirect_domains = [
        "https://evil-site.com",
        "https://attacker.net",
        "//evil.org",
        "data:text/html,<script>alert(document.domain)</script>"
    ];
    
    $test_endpoints = ["", "/redirect", "/login", "/logout", "/goto", "/link"];
    
    foreach ($test_endpoints as $endpoint) {
        $base_test_url = rtrim($url, '/') . $endpoint;
        
        foreach ($redirect_domains as $redirect) {
            $param_names = ["redirect", "url", "next", "target", "redir", "destination", "return", "returnUrl"];
            
            foreach ($param_names as $param) {
                $test_url = $base_test_url . "?" . $param . "=" . urlencode($redirect);
                $response = get_url_response($test_url);
                
                // Check if there's a redirect to our malicious domain
                if (!$response['error'] && 
                    ($response['code'] >= 300 && $response['code'] < 400) && 
                    (stripos($response['body'], "Location: " . $redirect) !== false || 
                     stripos($response['body'], "Refresh: 0; url=" . $redirect) !== false)) {
                    return [
                        'vulnerable' => true,
                        'type' => 'Open Redirect',
                        'url' => $test_url,
                        'description' => 'Open redirect vulnerability detected. The application allows redirecting to arbitrary external domains.'
                    ];
                }
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Server Information Disclosure - Identifies server information in headers
function check_server_disclosure($url) {
    $response = get_url_response($url);
    
    if (!$response['error']) {
        $headers = substr($response['body'], 0, strpos($response['body'], "\r\n\r\n"));
        
        // Check for version information in headers
        $sensitive_headers = [
            "Server: " => "Server version",
            "X-Powered-By: " => "Technology information",
            "X-AspNet-Version: " => ".NET version",
            "X-Runtime: " => "Ruby version",
            "X-Version: " => "Application version"
        ];
        
        foreach ($sensitive_headers as $header => $info_type) {
            if (stripos($headers, $header) !== false) {
                // Extract the header value
                preg_match('/' . preg_quote($header, '/') . '([^\r\n]+)/i', $headers, $matches);
                $header_value = isset($matches[1]) ? trim($matches[1]) : "[value hidden]";
                
                return [
                    'vulnerable' => true,
                    'type' => 'Information Disclosure',
                    'url' => $url,
                    'description' => $info_type . ' disclosed in HTTP headers: ' . $header_value
                ];
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Insecure HTTP Methods Detection
function check_http_methods($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "OPTIONS");
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    
    if ($response && stripos($response, "Allow:") !== false) {
        // Extract the allowed methods
        preg_match('/Allow: ([^\r\n]+)/i', $response, $matches);
        $allowed_methods = isset($matches[1]) ? trim($matches[1]) : "";
        
        // Check for dangerous methods
        $dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"];
        foreach ($dangerous_methods as $method) {
            if (stripos($allowed_methods, $method) !== false) {
                return [
                    'vulnerable' => true,
                    'type' => 'Insecure HTTP Methods',
                    'url' => $url,
                    'description' => 'Potentially dangerous HTTP methods are enabled: ' . $allowed_methods
                ];
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Missing Security Headers Detection
function check_security_headers($url) {
    $response = get_url_response($url);
    
    if (!$response['error']) {
        $headers = substr($response['body'], 0, strpos($response['body'], "\r\n\r\n"));
        
        $security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ];
        
        $missing_headers = [];
        
        foreach ($security_headers as $header) {
            if (stripos($headers, $header . ":") === false) {
                $missing_headers[] = $header;
            }
        }
        
        if (!empty($missing_headers)) {
            return [
                'vulnerable' => true,
                'type' => 'Missing Security Headers',
                'url' => $url,
                'description' => 'The following security headers are missing: ' . implode(', ', $missing_headers)
            ];
        }
    }
    
    return ['vulnerable' => false];
}

// Check for CSRF token in forms
function check_csrf_protection($url) {
    $response = get_url_response($url);
    
    if (!$response['error']) {
        // Extract forms from the response
        preg_match_all('/<form[^>]*>(.+?)<\/form>/is', $response['body'], $forms);
        
        if (!empty($forms[0])) {
            foreach ($forms[0] as $form) {
                // Check if the form has a CSRF token
                if (stripos($form, "csrf") === false && 
                    stripos($form, "token") === false && 
                    stripos($form, "_token") === false && 
                    stripos($form, "authenticity") === false) {
                    
                    // Extract action URL for reference
                    preg_match('/action=["\'](.*?)["\']/i', $form, $action);
                    $form_action = isset($action[1]) ? $action[1] : "unknown";
                    
                    return [
                        'vulnerable' => true,
                        'type' => 'CSRF Vulnerability',
                        'url' => $url,
                        'description' => 'Form found without CSRF protection (action: ' . $form_action . ')'
                    ];
                }
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Check for SSL/TLS vulnerabilities
function check_ssl_tls($url) {
    // Check if the site uses HTTPS
    if (strpos($url, "https://") !== 0) {
        return [
            'vulnerable' => true,
            'type' => 'Insecure Communication',
            'url' => $url,
            'description' => 'The website does not use HTTPS, which could lead to data interception.'
        ];
    }
    
    // This is a simplified check - in a real scanner, you'd check for outdated protocols
    // and cipher suites, which would require more advanced tools
    
    return ['vulnerable' => false];
}

// Directory Listing Detection
function check_directory_listing($url) {
    $test_directories = ["/images", "/css", "/js", "/uploads", "/inc", "/include", "/backup", "/admin", "/assets"];
    
    foreach ($test_directories as $dir) {
        $test_url = rtrim($url, '/') . $dir;
        $response = get_url_response($test_url);
        
        if (!$response['error'] && $response['code'] == 200) {
            // Check for common directory listing indicators
            $indicators = [
                "Index of /",
                "Directory Listing For",
                "<title>Index of",
                "Parent Directory</a>",
                "[To Parent Directory]"
            ];
            
            foreach ($indicators as $indicator) {
                if (stripos($response['body'], $indicator) !== false) {
                    return [
                        'vulnerable' => true,
                        'type' => 'Directory Listing Enabled',
                        'url' => $test_url,
                        'description' => 'Directory listing is enabled, which may expose sensitive files and information.'
                    ];
                }
            }
        }
    }
    
    return ['vulnerable' => false];
}

// Main scanning function
function scan_website($url) {
    // Validate URL format
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return ["Error: Invalid URL format. Please enter a valid URL including http:// or https://"];
    }
    
    // Store detailed vulnerability information
    $vulnerabilities = [];
    $vulnerability_details = [];
    
    // Run all checks and collect detailed results
    $checks = [
        'sql_injection' => check_sql_injection($url),
        'xss' => check_xss($url),
        'open_redirect' => check_open_redirect($url),
        'server_disclosure' => check_server_disclosure($url),
        'http_methods' => check_http_methods($url),
        'security_headers' => check_security_headers($url),
        'csrf' => check_csrf_protection($url),
        'ssl_tls' => check_ssl_tls($url),
        'directory_listing' => check_directory_listing($url)
    ];
    
    // Process results
    foreach ($checks as $check_name => $result) {
        if (isset($result['vulnerable']) && $result['vulnerable']) {
            $vulnerabilities[] = $result['type'];
            $vulnerability_details[] = [
                'type' => $result['type'],
                'url' => $result['url'],
                'description' => $result['description']
            ];
        }
    }
    
    // Calculate security rating based on number and types of vulnerabilities
    $security_rating = calculate_security_rating($vulnerability_details);
    
    // Return both simple and detailed results
    return [
        'vulnerabilities' => $vulnerabilities,
        'details' => $vulnerability_details,
        'security_rating' => $security_rating,
        'scanned_url' => $url
    ];
}

// Calculate security rating based on vulnerabilities
function calculate_security_rating($vulnerability_details) {
    if (empty($vulnerability_details)) {
        return [
            'level' => 'Safe',
            'score' => 'A+',
            'color' => 'success'
        ];
    }
    
    // Count high, medium and low severity vulnerabilities
    $high_severity = 0;
    $medium_severity = 0;
    $low_severity = 0;
    
    $high_severity_types = ['SQL Injection', 'CSRF Vulnerability', 'Insecure Communication'];
    $medium_severity_types = ['Cross-Site Scripting (XSS)', 'Open Redirect', 'Directory Listing Enabled'];
    
    foreach ($vulnerability_details as $vuln) {
        if (in_array($vuln['type'], $high_severity_types)) {
            $high_severity++;
        } elseif (in_array($vuln['type'], $medium_severity_types)) {
            $medium_severity++;
        } else {
            $low_severity++;
        }
    }
    
    // Calculate score
    if ($high_severity > 0) {
        return [
            'level' => 'Critical',
            'score' => 'F',
            'color' => 'danger'
        ];
    } elseif ($medium_severity > 1) {
        return [
            'level' => 'High Risk',
            'score' => 'D',
            'color' => 'danger'
        ];
    } elseif ($medium_severity == 1) {
        return [
            'level' => 'Medium Risk',
            'score' => 'C',
            'color' => 'warning'
        ];
    } elseif ($low_severity > 2) {
        return [
            'level' => 'Low Risk',
            'score' => 'B',
            'color' => 'warning'
        ];
    } else {
        return [
            'level' => 'Minor Issues',
            'score' => 'B+',
            'color' => 'success'
        ];
    }
}
?>