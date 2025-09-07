<?php
/**
 * Firebase Proxy API - Enhanced Security Version with Captcha (Fixed Thai vowels)
 * ไฟล์: firebase_proxy.php
 *
 * แก้ไขปัญหาสระไทยถูกตัดออก
 */

// Security Headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

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
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Firebase-Proxy/2.1-Captcha-Thai-Fixed');

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
            throw new Exception('HTTP Error: ' . $httpCode);
        }

        return $result;
    }

    throw new Exception('cURL not available');
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
 * ปรับปรุงการ sanitize input - แก้ไขปัญหาสระไทย
 */
function sanitizeInput($input, $type = 'text') {
    if (empty($input)) {
        return '';
    }
    
    // ทำความสะอาดพื้นฐาน
    $input = trim($input);
    
    switch ($type) {
        case 'text':
            // กรอง HTML tags และ JavaScript
            $input = strip_tags($input);
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            // กรอง JavaScript keywords
            $jsPatterns = [
                '/javascript:/i',
                '/vbscript:/i',
                '/onload=/i',
                '/onclick=/i',
                '/onerror=/i',
                '/alert\(/i',
                '/document\./i',
                '/window\./i',
                '/<script/i',
                '/<\/script>/i'
            ];
            foreach ($jsPatterns as $pattern) {
                $input = preg_replace($pattern, '', $input);
            }
            break;
            
        case 'name':
            // กรองชื่อ - แก้ไขให้รองรับภาษาไทยครบถ้วน
            $input = strip_tags($input);
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            
            // อนุญาตเฉพาะ:
            // - ตัวอักษรไทย (\u0E00-\u0E7F) รวมสระ วรรณยุกต์
            // - ตัวอักษรละติน (a-zA-Z)
            // - ตัวเลข (0-9)
            // - ช่องว่าง เครื่องหมาย - _ .
            $input = preg_replace('/[^\u0E00-\u0E7Fa-zA-Z0-9\s\-_\.]/u', '', $input);
            break;
            
        case 'id':
            // กรอง ID
            $input = preg_replace('/[^a-zA-Z0-9\-_]/', '', $input);
            break;
            
        case 'number':
            // กรองตัวเลข
            $input = preg_replace('/[^0-9\-]/', '', $input);
            break;
    }
    
    return $input;
}

/**
 * ตรวจสอบ spam patterns
 */
function isSpam($text) {
    $spamPatterns = [
        '/(.)\1{10,}/',                    // ตัวอักษรซ้ำเกิน 10 ครั้ง
        '/https?:\/\/[^\s]{20,}/',         // URL ยาวผิดปกติ
        '/[A-Z]{20,}/',                    // ตัวใหญ่ติดกันยาว
        '/\b(buy|sale|discount|free|win|prize|money|cash|bitcoin|crypto)\b/i',
        '/[^\w\s\u0E00-\u0E7F]{10,}/u',   // เครื่องหมายพิเศษมากเกินไป
    ];
    
    foreach ($spamPatterns as $pattern) {
        if (preg_match($pattern, $text)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Rate Limiting
 */
function checkRateLimit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $now = time();
    $window = 3600; // 1 ชั่วโมง
    $limit = 10;    // 10 ข้อความต่อชั่วโมง ต่อ IP
    
    $rateLimitFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip) . '.json';
    
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
        // คำหยาบภาษาไทย
        'ควย', 'หี', 'เย็ด', 'สัด', 'เหี้ย', 'มึง', 'กู',
        // คำหยาบภาษาอังกฤษ
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
 * Log security events
 */
function logSecurityEvent($event, $details = []) {
    $logEntry = [
        'timestamp' => date('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'event' => $event,
        'details' => $details
    ];
    
    $logFile = sys_get_temp_dir() . '/security.log';
    file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

$action = $_GET['action'] ?? ($_POST['action'] ?? 'get');

try {
    switch ($action) {
        case 'get':
            // อ่านข้อความทั้งหมด
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url);
            $data = json_decode($result, true);

            // แปลง Firebase object เป็น array
            $messages = [];
            if ($data && is_array($data)) {
                foreach ($data as $key => $value) {
                    if (is_array($value) &&
                        isset($value['message']) &&
                        !empty($value['message']) &&
                        is_string($value['message'])) {

                        $messages[] = [
                            'id' => $key,
                            'name' => isset($value['name']) && is_string($value['name']) ? $value['name'] : 'ไม่ระบุชื่อ',
                            'message' => $value['message'],
                            'timestamp' => isset($value['timestamp']) ? $value['timestamp'] : date('c'),
                            'ip' => 'hidden'
                        ];
                    }
                }
            }

            // เรียงลำดับตามเวลา
            usort($messages, function($a, $b) {
                return strtotime($b['timestamp']) - strtotime($a['timestamp']);
            });

            $response = [
                'success' => true,
                'messages' => $messages,
                'total' => count($messages),
                'timestamp' => date('c'),
                'storage' => 'firebase-proxy-secure-captcha-thai-fixed'
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

            $url = $FIREBASE_URL . "/wishes/{$id}.json";
            $result = makeFirebaseRequest($url, 'DELETE');

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
                logSecurityEvent('rate_limit_exceeded');
                throw new Exception('Rate limit exceeded. Please try again later.');
            }

            $name = sanitizeInput($_POST['name'] ?? 'ไม่ระบุชื่อ', 'name');
            $message = sanitizeInput($_POST['message'] ?? '', 'text');
            
            // ตรวจสอบ Captcha
            $captchaAnswer = sanitizeInput($_POST['captcha_answer'] ?? '', 'number');
            $captchaUserAnswer = sanitizeInput($_POST['captcha_user_answer'] ?? '', 'number');
            
            if (!validateCaptcha($captchaAnswer, $captchaUserAnswer)) {
                logSecurityEvent('captcha_failed', [
                    'expected' => $captchaAnswer,
                    'received' => $captchaUserAnswer,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                throw new Exception('Captcha validation failed. Please solve the math problem correctly.');
            }

            // ตรวจสอบความถูกต้องของข้อมูล
            if (empty($message)) {
                throw new Exception('Message is required');
            }

            if (strlen($message) > 1000) {
                logSecurityEvent('message_too_long', ['length' => strlen($message)]);
                throw new Exception('Message too long (max 1000 characters)');
            }

            if (strlen($name) > 100) {
                logSecurityEvent('name_too_long', ['length' => strlen($name)]);
                throw new Exception('Name too long (max 100 characters)');
            }

            // ตรวจสอบ spam
            if (isSpam($message) || isSpam($name)) {
                logSecurityEvent('spam_detected', ['name' => $name, 'message' => substr($message, 0, 100)]);
                throw new Exception('Spam content detected');
            }

            // ตรวจสอบคำหยาบคาย
            if (containsProfanity($message) || containsProfanity($name)) {
                logSecurityEvent('profanity_detected', ['name' => $name, 'message' => substr($message, 0, 100)]);
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

            // Log successful submission
            logSecurityEvent('message_added', [
                'id' => $firebaseResponse['name'],
                'name_length' => strlen($name),
                'message_length' => strlen($message),
                'name_sample' => mb_substr($name, 0, 3) . '***' // เก็บตัวอย่างชื่อแรก 3 ตัว
            ]);

            $response = [
                'success' => true,
                'message' => 'Message added successfully with captcha verification (Thai names supported)',
                'id' => $firebaseResponse['name'],
                'timestamp' => date('c')
            ];

            break;

        case 'stats':
            // อ่านสถิติ
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url);
            $data = json_decode($result, true);

            $totalMessages = $data ? count($data) : 0;
            $captchaVerified = 0;

            // นับจำนวน IP ที่ไม่ซ้ำ และข้อความที่ผ่าน captcha
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

        case 'test':
            // ทดสอบการเชื่อมต่อ Firebase และ Captcha
            $url = $FIREBASE_URL . '/.json';
            $result = makeFirebaseRequest($url);

            // ทดสอบ captcha function
            $testCaptcha = validateCaptcha(8, '8');
            
            // ทดสอบการ sanitize ชื่อไทย
            $testThaiName = sanitizeInput('สุธิพงษ์ ทดสอบ', 'name');

            $response = [
                'success' => true,
                'message' => 'Firebase connection successful (Thai names fixed)',
                'firebase_url' => $FIREBASE_URL,
                'response_length' => strlen($result),
                'captcha_test' => $testCaptcha ? 'PASS' : 'FAIL',
                'thai_name_test' => $testThaiName, // ควรแสดง "สุธิพงษ์ ทดสอบ" ครบถ้วน
                'timestamp' => date('c'),
                'features' => [
                    'rate_limiting' => true,
                    'spam_detection' => true,
                    'profanity_filter' => true,
                    'captcha_validation' => true,
                    'security_logging' => true,
                    'thai_names_support' => true
                ]
            ];

            break;

        case 'captcha_test':
            // ทดสอบ captcha validation
            $correctAnswer = sanitizeInput($_POST['correct_answer'] ?? '', 'number');
            $userAnswer = sanitizeInput($_POST['user_answer'] ?? '', 'number');
            
            $isValid = validateCaptcha($correctAnswer, $userAnswer);
            
            $response = [
                'success' => true,
                'captcha_valid' => $isValid,
                'correct_answer' => $correctAnswer,
                'user_answer' => $userAnswer,
                'timestamp' => date('c')
            ];
            
            if (!$isValid) {
                logSecurityEvent('captcha_test_failed', [
                    'expected' => $correctAnswer,
                    'received' => $userAnswer
                ]);
            }
            
            break;

        default:
            logSecurityEvent('invalid_action', ['action' => $action]);
            throw new Exception('Invalid action. Available: get, add, stats, test, delete, captcha_test');
    }

    echo json_encode($response, JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    http_response_code(500);

    $error = [
        'success' => false,
        'error' => $e->getMessage(),
        'action' => $action,
        'timestamp' => date('c'),
        'debug' => [
            'firebase_url' => $FIREBASE_URL,
            'php_version' => phpversion(),
            'method' => $_SERVER['REQUEST_METHOD'],
            'captcha_enabled' => true,
            'thai_support' => true
        ]
    ];

    // Log error
    logSecurityEvent('error', ['message' => $e->getMessage(), 'action' => $action]);

    echo json_encode($error, JSON_UNESCAPED_UNICODE);
}
?>
