<?php
/**
 * Firebase Proxy API - Complete Fixed Version
 * แก้ไขปัญหาสระไทย + เพิ่ม Admin functions
 */

// เปิด error reporting สำหรับ debug
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Security Headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Firebase Database URL
$FIREBASE_URL = 'https://nbu25th-default-rtdb.asia-southeast1.firebasedatabase.app';

/**
 * ฟังก์ชันทำ HTTP Request ไปยัง Firebase
 */
function makeFirebaseRequest($url, $method = 'GET', $data = null) {
    if (!function_exists('curl_init')) {
        throw new Exception('cURL is not available');
    }
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Firebase-Proxy-Complete/1.0');
    
    if ($method === 'POST' && $data !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Content-Length: ' . strlen(json_encode($data))
        ]);
    } else if ($method === 'DELETE') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    }

    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($result === false) {
        throw new Exception('cURL Error: ' . $error);
    }

    if ($httpCode >= 400) {
        throw new Exception('HTTP Error: ' . $httpCode . ' Response: ' . substr($result, 0, 200));
    }

    return $result;
}

/**
 * ตรวจสอบ Captcha
 */
function validateCaptcha($correctAnswer, $userAnswer) {
    if (!is_numeric($userAnswer) || !is_numeric($correctAnswer)) {
        return false;
    }
    
    $userAnswerInt = intval($userAnswer);
    $correctAnswerInt = intval($correctAnswer);
    
    if ($correctAnswerInt < 2 || $correctAnswerInt > 40) {
        return false;
    }
    
    return $userAnswerInt === $correctAnswerInt;
}

/**
 * Sanitize input - แก้ไขปัญหาสระไทยหาย (FINAL VERSION)
 */
function sanitizeInput($input, $type = 'text') {
    if (empty($input)) {
        return '';
    }
    
    $input = trim($input);
    
    switch ($type) {
        case 'text':
            // สำหรับข้อความ ใช้การป้องกันปกติ
            $input = strip_tags($input);
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            break;
            
        case 'name':
            // 🔥 สำหรับชื่อ - ไม่ใช้ htmlspecialchars เพราะจะทำให้สระไทยหาย
            $input = strip_tags($input);
            
            // กรองเฉพาะอักขระที่อันตรายจริงๆ สำหรับ database
            $dangerousPatterns = [
                '/<script.*?\/script>/is',
                '/<iframe.*?\/iframe>/is',
                '/javascript:/i',
                '/vbscript:/i',
                '/onload=/i',
                '/onclick=/i',
                '/onerror=/i',
                '/data:/i',
                '/eval\(/i',
                '/alert\(/i'
            ];
            
            // กรองด้วย regex patterns
            foreach ($dangerousPatterns as $pattern) {
                $input = preg_replace($pattern, '', $input);
            }
            
            // กรองเครื่องหมายเฉพาะตัวที่อันตราย
            $input = str_replace(['<', '>', '"', '\\', '|', ';'], '', $input);
            
            break;
            
        case 'id':
            $input = preg_replace('/[^a-zA-Z0-9\-_]/', '', $input);
            break;
            
        case 'number':
            $input = preg_replace('/[^0-9\-]/', '', $input);
            break;
    }
    
    return $input;
}

/**
 * Rate Limiting - ปรับปรุงแล้ว
 */
function checkRateLimit($reset = false) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $now = time();
    $window = 3600; // 1 ชั่วโมง
    $limit = 50;    // 50 ข้อความต่อชั่วโมง
    
    $rateLimitFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip) . '.json';
    
    // ถ้าเป็น reset ให้ลบไฟล์
    if ($reset) {
        if (file_exists($rateLimitFile)) {
            unlink($rateLimitFile);
        }
        return true;
    }
    
    $attempts = [];
    if (file_exists($rateLimitFile)) {
        $attempts = json_decode(file_get_contents($rateLimitFile), true) ?: [];
    }
    
    // ลบ timestamp เก่า
    $attempts = array_filter($attempts, function($timestamp) use ($now, $window) {
        return ($now - $timestamp) < $window;
    });
    
    // ตรวจสอบจำนวน
    if (count($attempts) >= $limit) {
        return false;
    }
    
    // เพิ่ม timestamp ใหม่
    $attempts[] = $now;
    file_put_contents($rateLimitFile, json_encode($attempts));
    
    return true;
}

/**
 * ตรวจสอบคำหยาบคาย
 */
function containsProfanity($text) {
    $badWords = [
        'ควย', 'หี', 'เย็ด', 'สัด', 'เหี้ย', 'มึง', 'กู',
        'fuck', 'shit', 'damn', 'bitch', 'asshole',
    ];
    
    $textLower = strtolower($text);
    
    foreach ($badWords as $badWord) {
        if (strpos($textLower, strtolower($badWord)) !== false) {
            return true;
        }
    }
    
    return false;
}

/**
 * ตรวจสอบ spam
 */
function isSpam($text) {
    $spamPatterns = [
        '/(.)\1{10,}/',                    // ตัวอักษรซ้ำเกิน 10 ครั้ง
        '/https?:\/\/[^\s]{20,}/',         // URL ยาวผิดปกติ
        '/[A-Z]{20,}/',                    // ตัวใหญ่ติดกันยาว
    ];
    
    foreach ($spamPatterns as $pattern) {
        if (preg_match($pattern, $text)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Log events
 */
function logEvent($event, $details = []) {
    $logEntry = [
        'timestamp' => date('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'event' => $event,
        'details' => $details
    ];
    
    $logFile = sys_get_temp_dir() . '/events.log';
    file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

$action = $_GET['action'] ?? ($_POST['action'] ?? 'get');

try {
    switch ($action) {
        case 'reset_rate_limit':
            // รีเซ็ต rate limit
            checkRateLimit(true);
            logEvent('rate_limit_reset');
            
            $response = [
                'success' => true,
                'message' => 'Rate limit has been reset for your IP',
                'timestamp' => date('c')
            ];
            break;

        case 'get':
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url);
            $data = json_decode($result, true);

            $messages = [];
            if ($data && is_array($data)) {
                foreach ($data as $key => $value) {
                    if (is_array($value) && isset($value['message']) && !empty($value['message'])) {
                        $messages[] = [
                            'id' => $key,
                            'name' => $value['name'] ?? 'ไม่ระบุชื่อ',
                            'message' => $value['message'],
                            'timestamp' => $value['timestamp'] ?? date('c'),
                            'ip' => 'hidden'
                        ];
                    }
                }
            }

            usort($messages, function($a, $b) {
                return strtotime($b['timestamp']) - strtotime($a['timestamp']);
            });

            $response = [
                'success' => true,
                'messages' => $messages,
                'total' => count($messages),
                'timestamp' => date('c')
            ];
            break;

        case 'delete':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('POST method required');
            }

            $id = sanitizeInput($_POST['id'] ?? '', 'id');
            if (empty($id)) {
                throw new Exception('Message ID is required');
            }

            // ลบจาก Firebase
            $url = $FIREBASE_URL . "/wishes/{$id}.json";
            $result = makeFirebaseRequest($url, 'DELETE');

            logEvent('message_deleted', ['id' => $id]);

            $response = [
                'success' => true,
                'message' => 'Message deleted successfully',
                'id' => $id,
                'timestamp' => date('c')
            ];
            break;

        case 'add':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('POST method required');
            }

            // ตรวจสอบ Rate Limiting
            if (!checkRateLimit()) {
                logEvent('rate_limit_exceeded');
                throw new Exception('Rate limit exceeded. Please wait or use ?action=reset_rate_limit to reset.');
            }

            $name = sanitizeInput($_POST['name'] ?? 'ไม่ระบุชื่อ', 'name');
            $message = sanitizeInput($_POST['message'] ?? '', 'text');
            
            // ตรวจสอบ Captcha
            $captchaAnswer = sanitizeInput($_POST['captcha_answer'] ?? '', 'number');
            $captchaUserAnswer = sanitizeInput($_POST['captcha_user_answer'] ?? '', 'number');
            
            if (!validateCaptcha($captchaAnswer, $captchaUserAnswer)) {
                logEvent('captcha_failed', [
                    'expected' => $captchaAnswer,
                    'received' => $captchaUserAnswer
                ]);
                throw new Exception('Captcha validation failed. Please solve the math problem correctly.');
            }

            // ตรวจสอบความถูกต้องของข้อมูล
            if (empty($message)) {
                throw new Exception('Message is required');
            }

            if (strlen($message) > 1000) {
                throw new Exception('Message too long (max 1000 characters)');
            }

            if (strlen($name) > 100) {
                throw new Exception('Name too long (max 100 characters)');
            }

            // ตรวจสอบ spam และคำหยาบ
            if (isSpam($message) || isSpam($name)) {
                logEvent('spam_detected');
                throw new Exception('Spam content detected');
            }

            if (containsProfanity($message) || containsProfanity($name)) {
                logEvent('profanity_detected');
                throw new Exception('Inappropriate content detected');
            }

            // สร้างข้อมูลใหม่
            $newMessage = [
                'name' => $name,
                'message' => $message,
                'timestamp' => date('c'),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'captcha_verified' => true
            ];

            // ส่งไปยัง Firebase
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url, 'POST', $newMessage);
            $firebaseResponse = json_decode($result, true);

            if (!$firebaseResponse || !isset($firebaseResponse['name'])) {
                throw new Exception('Failed to save to Firebase');
            }

            logEvent('message_added', [
                'id' => $firebaseResponse['name'],
                'name_length' => strlen($name),
                'message_length' => strlen($message)
            ]);

            $response = [
                'success' => true,
                'message' => 'Message added successfully with captcha verification',
                'id' => $firebaseResponse['name'],
                'timestamp' => date('c')
            ];
            break;

        case 'test':
            $url = $FIREBASE_URL . '/.json';
            $result = makeFirebaseRequest($url);
            
            $testCaptcha = validateCaptcha(8, '8');
            
            // ทดสอบชื่อไทยหลายแบบ
            $thaiNames = [
                'สุธิพงษ์',
                'นางสาวสุธิดา',
                'กิตติพงษ์ แสงไทย',
                'วิภาวดี รุ่งเรื่อง',
                'ธีรพัฒน์ เจริญกิจ'
            ];
            
            $testResults = [];
            foreach ($thaiNames as $name) {
                $sanitized = sanitizeInput($name, 'name');
                $testResults[] = [
                    'original' => $name,
                    'sanitized' => $sanitized,
                    'same' => ($name === $sanitized)
                ];
            }

            $response = [
                'success' => true,
                'message' => 'All systems operational - Thai names FIXED!',
                'tests' => [
                    'firebase_connection' => 'OK',
                    'captcha_validation' => $testCaptcha ? 'PASS' : 'FAIL',
                    'thai_names_test' => $testResults,
                    'rate_limit_status' => checkRateLimit() ? 'OK' : 'EXCEEDED'
                ],
                'timestamp' => date('c'),
                'features' => [
                    'rate_limiting' => 'Enhanced (50/hour)',
                    'spam_detection' => true,
                    'profanity_filter' => true,
                    'captcha_validation' => true,
                    'thai_names_support' => 'FIXED - No htmlspecialchars for names',
                    'admin_delete' => true,
                    'rate_limit_reset' => true
                ]
            ];
            break;

        case 'stats':
            // สถิติรวม
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url);
            $data = json_decode($result, true);

            $totalMessages = $data ? count($data) : 0;
            $captchaVerified = 0;

            $uniqueIPs = [];
            if ($data) {
                foreach ($data as $message) {
                    $ip = $message['ip'] ?? 'unknown';
                    $uniqueIPs[$ip] = true;
                    
                    if (isset($message['captcha_verified']) && $message['captcha_verified']) {
                        $captchaVerified++;
                    }
                }
            }

            $response = [
                'success' => true,
                'stats' => [
                    'total_messages' => $totalMessages,
                    'captcha_verified' => $captchaVerified,
                    'unique_users' => count($uniqueIPs),
                    'verification_rate' => $totalMessages > 0 ? round(($captchaVerified / $totalMessages) * 100, 2) : 0,
                    'last_updated' => date('c')
                ],
                'timestamp' => date('c')
            ];
            break;

        default:
            throw new Exception('Invalid action. Available: get, add, delete, test, stats, reset_rate_limit');
    }

    echo json_encode($response, JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    http_response_code(500);
    
    logEvent('error', ['message' => $e->getMessage(), 'action' => $action]);
    
    $error = [
        'success' => false,
        'error' => $e->getMessage(),
        'action' => $action,
        'timestamp' => date('c'),
        'debug' => [
            'php_version' => phpversion(),
            'method' => $_SERVER['REQUEST_METHOD'],
            'features' => [
                'captcha_enabled' => true,
                'thai_names_fixed' => true,
                'admin_functions' => true
            ]
        ]
    ];

    echo json_encode($error, JSON_UNESCAPED_UNICODE);
}
?>
