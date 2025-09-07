<?php
/**
 * Firebase Proxy API - Enhanced Security Version
 * ไฟล์: firebase_proxy.php
 *
 * ทำหน้าที่เป็นตัวกลางระหว่าง JavaScript กับ Firebase
 * เพื่อหลีกเลี่ยงปัญหา CSP (Content Security Policy)
 * + ปรับปรุงความปลอดภัย
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
        curl_setopt($ch, CURLOPT_USERAGENT, 'Firebase-Proxy/2.0');

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
 * ปรับปรุงการ sanitize input
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
            // กรองชื่อ
            $input = strip_tags($input);
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            // อนุญาตเฉพาะตัวอักษร ตัวเลข ช่องว่าง และเครื่องหมายพื้นฐาน
            $input = preg_replace('/[^\p{L}\p{N}\s\-_\.]/u', '', $input);
            break;
            
        case 'id':
            // กรอง ID
            $input = preg_replace('/[^a-zA-Z0-9\-_]/', '', $input);
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
        '/\b(buy|sale|discount|free|win|prize|money|cash|bitcoin|crypto)\b/i', // คำที่มักใช้ใน spam (ปรับตามความเหมาะสม)
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
 * ปรับปรุง Rate Limiting ใช้ IP-based
 */
function checkRateLimit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $now = time();
    $window = 3600; // 1 ชั่วโมง
    $limit = 15;    // 15 ข้อความต่อชั่วโมง ต่อ IP
    
    // ใช้ไฟล์เก็บข้อมูล rate limit (สำหรับ production ควรใช้ Redis หรือ Database)
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
 * ตรวจสอบคำหยาบคาย (ปรับปรุง)
 */
function containsProfanity($text) {
    $badWords = [
        // คำหยาบภาษาไทย
        'ควย', 'หี', 'เย็ด', 'สัด', 'เหี้ย', 'มึง', 'กู',
        // คำหยาบภาษาอังกฤษ
        'fuck', 'shit', 'damn', 'bitch', 'asshole',
        // เพิ่มคำที่ไม่เหมาะสมอื่นๆ ตามต้องการ
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
                'storage' => 'firebase-proxy-secure'
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
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ];

            // ส่งไปยัง Firebase
            $url = $FIREBASE_URL . '/wishes.json';
            $result = makeFirebaseRequest($url, 'POST', $newMessage);
            $firebaseResponse = json_decode($result, true);

            if (!$firebaseResponse || !isset($firebaseResponse['name'])) {
                throw new Exception('Failed to save to Firebase');
            }

            $response = [
                'success' => true,
                'message' => 'Message added successfully',
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

            // นับจำนวน IP ที่ไม่ซ้ำ
            $uniqueIPs = [];
            if ($data) {
                foreach ($data as $message) {
                    $ip = $message['ip'] ?? 'unknown';
                    $uniqueIPs[$ip] = true;
                }
            }

            $response = [
                'success' => true,
                'stats' => [
                    'total_messages' => $totalMessages,
                    'unique_users' => count($uniqueIPs),
                    'last_updated' => date('c')
                ],
                'timestamp' => date('c')
            ];

            break;

        case 'test':
            // ทดสอบการเชื่อมต่อ Firebase
            $url = $FIREBASE_URL . '/.json';
            $result = makeFirebaseRequest($url);

            $response = [
                'success' => true,
                'message' => 'Firebase connection successful (secure version)',
                'firebase_url' => $FIREBASE_URL,
                'response_length' => strlen($result),
                'timestamp' => date('c')
            ];

            break;

        default:
            logSecurityEvent('invalid_action', ['action' => $action]);
            throw new Exception('Invalid action. Available: get, add, stats, test, delete');
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
            'method' => $_SERVER['REQUEST_METHOD']
        ]
    ];

    // Log error
    logSecurityEvent('error', ['message' => $e->getMessage(), 'action' => $action]);

    echo json_encode($error, JSON_UNESCAPED_UNICODE);
}
?>
