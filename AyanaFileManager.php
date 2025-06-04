<?php
session_start();
error_reporting(0); 

// --- PENGATURAN KRUSIAL UNTUK ENKRIPSI ---
// !! GANTI PASSPHRASE INI DENGAN SESUATU YANG KUAT, UNIK, DAN RAHASIA !!
// !! JANGAN SAMPAI HILANG, KARENA DATA KONFIGURASI TIDAK AKAN BISA DIBACA !!
define('LOG_CONFIG_ENCRYPTION_PASSPHRASE', 'GantiDenganPassphraseSuperRahasiaAndaYangPanjangDanKuat!');
define('ENCRYPTION_CIPHER', 'AES-256-CBC'); // Metode enkripsi

define('CONFIG_LOG_FILE_PATH', __DIR__ . '/config_log.json');

// --- FUNGSI ENKRIPSI & DEKRIPSI ---
function get_encryption_key() {
    // Menggunakan SHA256 untuk menghasilkan kunci 32-byte dari passphrase
    return hash('sha256', LOG_CONFIG_ENCRYPTION_PASSPHRASE, true);
}

function encrypt_data($data, $key) {
    if (!function_exists('openssl_encrypt')) return false;
    $iv_length = openssl_cipher_iv_length(ENCRYPTION_CIPHER);
    if ($iv_length === false) return false;
    $iv = openssl_random_pseudo_bytes($iv_length);
    $cipher_text = openssl_encrypt(json_encode($data), ENCRYPTION_CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    if ($cipher_text === false) return false;
    return ['iv' => base64_encode($iv), 'cipher_text' => base64_encode($cipher_text)];
}

function decrypt_data($cipher_text_base64, $iv_base64, $key) {
    if (!function_exists('openssl_decrypt')) return false;
    $iv = base64_decode($iv_base64);
    $cipher_text = base64_decode($cipher_text_base64);
    $decrypted_json = openssl_decrypt($cipher_text, ENCRYPTION_CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted_json === false) return false;
    return json_decode($decrypted_json, true);
}


// --- FUNGSI UNTUK MEMUAT DAN MENYIMPAN KONFIGURASI LOGGING DARI/KE FILE JSON ---
function load_logging_config_from_file(&$main_config_array) {
    global $config_log_file_writable_warning, $openssl_unavailable_warning;
    
    $default_log_credentials = [
        'discord_webhook_url' => '', 'discord_username' => 'FileManager Bot',
        'telegram_bot_token' => '', 'telegram_chat_id' => '',
        'email_to_address' => '', 'email_from_address' => 'noreply@yourdomain.com',
        'email_subject_prefix' => '[FileMan Log]'
    ];

    $loaded_credentials = $default_log_credentials; // Mulai dengan default

    if (!function_exists('openssl_encrypt')) {
        $openssl_unavailable_warning = "Peringatan: Ekstensi OpenSSL PHP tidak tersedia. Konfigurasi logging akan disimpan/dibaca sebagai plain text (tidak aman). Sangat disarankan untuk mengaktifkan OpenSSL.";
    }

    if (file_exists(CONFIG_LOG_FILE_PATH) && is_readable(CONFIG_LOG_FILE_PATH)) {
        $json_content = file_get_contents(CONFIG_LOG_FILE_PATH);
        $data_from_file = json_decode($json_content, true);

        if (is_array($data_from_file)) {
            if (isset($data_from_file['iv']) && isset($data_from_file['cipher_text']) && function_exists('openssl_decrypt')) {
                // Format terenkripsi baru
                $key = get_encryption_key();
                $decrypted = decrypt_data($data_from_file['cipher_text'], $data_from_file['iv'], $key);
                if ($decrypted !== false && is_array($decrypted)) {
                    $loaded_credentials = array_merge($default_log_credentials, $decrypted);
                } else {
                    $config_log_file_writable_warning .= " Error: Gagal mendekripsi " . basename(CONFIG_LOG_FILE_PATH) . ". File mungkin rusak atau passphrase salah. Menggunakan default. ";
                }
            } elseif (!isset($data_from_file['iv']) && !isset($data_from_file['cipher_text'])) {
                // Format plain-text lama, coba upgrade
                $loaded_credentials = array_merge($default_log_credentials, $data_from_file);
                if (function_exists('openssl_encrypt')) {
                    $save_attempt = save_logging_config_to_file($loaded_credentials, false); // false untuk tidak redirect
                    if ($save_attempt !== true) {
                         $config_log_file_writable_warning .= " Info: Mencoba mengenkripsi file konfigurasi log lama, tetapi gagal: " . (is_string($save_attempt) ? $save_attempt : "Unknown error") . ". ";
                    } else {
                         $config_log_file_writable_warning .= " Info: File konfigurasi log lama berhasil dienkripsi. ";
                    }
                } else {
                    // OpenSSL not available, keep using plain text
                }
            } else {
                 $config_log_file_writable_warning .= " Error: Format " . basename(CONFIG_LOG_FILE_PATH) . " tidak dikenali. Menggunakan default. ";
            }
        }
    } elseif (is_writable(__DIR__) && function_exists('openssl_encrypt')) {
        // File tidak ada, coba buat dengan default terenkripsi
        $save_attempt = save_logging_config_to_file($default_log_credentials, false);
        if ($save_attempt !== true) {
            // Gagal membuat file, akan ada warning dari save_logging_config_to_file
        }
    }
    
    // Merge loaded/default credentials into the main config
    if (isset($main_config_array['logging']['discord'])) {
         $main_config_array['logging']['discord']['webhook_url'] = $loaded_credentials['discord_webhook_url'];
         $main_config_array['logging']['discord']['username'] = $loaded_credentials['discord_username'];
    }
    if (isset($main_config_array['logging']['telegram'])) {
        $main_config_array['logging']['telegram']['bot_token'] = $loaded_credentials['telegram_bot_token'];
        $main_config_array['logging']['telegram']['chat_id'] = $loaded_credentials['telegram_chat_id'];
    }
    if (isset($main_config_array['logging']['email'])) {
        $main_config_array['logging']['email']['to_address'] = $loaded_credentials['email_to_address'];
        $main_config_array['logging']['email']['from_address'] = $loaded_credentials['email_from_address'];
        $main_config_array['logging']['email']['subject_prefix'] = $loaded_credentials['email_subject_prefix'];
    }
    return true;
}

function save_logging_config_to_file($data_to_save, $do_redirect_and_log = true) {
    global $openssl_unavailable_warning;

    $credentials_to_save = [
        'discord_webhook_url' => filter_var($data_to_save['discord_webhook_url'] ?? '', FILTER_SANITIZE_URL),
        'discord_username' => htmlspecialchars($data_to_save['discord_username'] ?? 'FileManager Bot', ENT_QUOTES, 'UTF-8'),
        'telegram_bot_token' => htmlspecialchars($data_to_save['telegram_bot_token'] ?? '', ENT_QUOTES, 'UTF-8'),
        'telegram_chat_id' => htmlspecialchars($data_to_save['telegram_chat_id'] ?? '', ENT_QUOTES, 'UTF-8'),
        'email_to_address' => filter_var($data_to_save['email_to_address'] ?? '', FILTER_SANITIZE_EMAIL),
        'email_from_address' => filter_var($data_to_save['email_from_address'] ?? 'noreply@yourdomain.com', FILTER_SANITIZE_EMAIL),
        'email_subject_prefix' => htmlspecialchars($data_to_save['email_subject_prefix'] ?? '[FileMan Log]', ENT_QUOTES, 'UTF-8'),
    ];

    $file_content_to_write = '';
    if (function_exists('openssl_encrypt')) {
        $key = get_encryption_key();
        $encrypted_payload = encrypt_data($credentials_to_save, $key);
        if ($encrypted_payload === false) {
            return "Error: Gagal mengenkripsi data konfigurasi.";
        }
        $file_content_to_write = json_encode($encrypted_payload, JSON_PRETTY_PRINT);
    } else {
        // OpenSSL not available, save as plain text (warning already set)
        $file_content_to_write = json_encode($credentials_to_save, JSON_PRETTY_PRINT);
    }
    
    if (!is_writable(CONFIG_LOG_FILE_PATH)) {
        if (!file_exists(CONFIG_LOG_FILE_PATH) && !is_writable(__DIR__)) {
            return "Error: Direktori tidak dapat ditulis, file konfigurasi log (" . basename(CONFIG_LOG_FILE_PATH) . ") tidak dapat dibuat.";
        } elseif (file_exists(CONFIG_LOG_FILE_PATH) && !is_writable(CONFIG_LOG_FILE_PATH)) {
            return "Error: File konfigurasi log (" . basename(CONFIG_LOG_FILE_PATH) . ") tidak dapat ditulis. Periksa izin file.";
        }
    }

    if (@file_put_contents(CONFIG_LOG_FILE_PATH, $file_content_to_write) !== false) {
        if ($do_redirect_and_log) { // Hanya log dan redirect jika ini adalah aksi pengguna langsung
            log_action("Logging Configuration Updated", "User updated external logging service credentials via UI.", "CONFIG_CHANGE");
        }
        return true;
    }
    return "Error: Gagal menyimpan konfigurasi log ke file (" . basename(CONFIG_LOG_FILE_PATH) . ").";
}


// --- KONFIGURASI UTAMA (Default) ---
$config = [
    'judul_filemanager' => 'Ayana File Manager',
    'deskripsi_filemanager' => 'Kelola file dengan konfigurasi logging terenkripsi via UI.',
    'direktori_dasar' => __DIR__, 
    'aktifkan_login' => false,
    'pengguna' => [
        'admin' => '$2y$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' // GANTI HASH INI!
    ],
    'fitur_berbahaya' => [
        'terminal' => true, 
        'edit_chmod_luas' => true, 
        'tampilkan_error_php' => false, 
        'akses_pengaturan_log' => true, 
    ],
    'sembunyikan_item' => ['.', '..', '.htaccess', '.htpasswd', basename(__FILE__), basename(CONFIG_LOG_FILE_PATH)], 
    'zona_waktu' => 'Asia/Jakarta',
    'max_upload_size_mb' => 100, 
    'default_chmod_folder' => 0755,
    'default_chmod_file' => 0644,
    'editable_extensions' => [
        'txt', 'md', 'log', 'json', 'xml', 'js', 'css', 'html', 'php', 
        'py', 'sh', 'ini', 'cfg', 'conf', 'env', 'sql', 'csv', 'bat', 'yaml', 'yml'
    ],
    'malicious_patterns' => [ 
        'eval\(base64_decode\(', 'eval\(gzinflate\(base64_decode\(', 'passthru\(', 'shell_exec\(', 'system\(',
        'php_uname\(', 'fsockopen\(', 'pfsockopen\(', 'assert\(', 'str_rot13\(', 'gzuncompress\(',
        'create_function\s*\(', 
        '\$_REQUEST\s*\[\s*[\'"][a-zA-Z0-9_]+[\'"]\s*\]\s*$$\s*\$_REQUEST\s*\[\s*[\'"][a-zA-Z0-9_]+[\'"]\s*\]\s*$$', 
        'move_uploaded_file\s*$$\s*\$_FILES\s*\[.+?\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*\$_FILES\s*\[.+?\]\s*\[\s*[\'"]name[\'"]\s*\]\s*$$',
        'webshell', 'c99', 'r57', 'phpspy', 'shell_ দেখুনঃ', 'document\.write\(unescape\(', 'fromCharCode\('
    ],
    'scan_file_max_size_kb' => 512, 
    'enable_malware_scan_on_list' => true,
    'logging' => [ 
        'enabled' => true, 
        'log_ip_address' => true, 
        'discord' => [ 'enabled' => false, 'webhook_url' => '', 'username' => 'FileManager Bot' ],
        'telegram' => [ 'enabled' => false, 'bot_token' => '', 'chat_id' => '' ],
        'email' => [ 'enabled' => false, 'to_address' => '', 'from_address' => 'noreply@yourdomain.com', 'subject_prefix' => '[FileMan Log]' ],
    ],
];

$config_log_file_writable_warning = ''; // Akan diisi oleh load_logging_config_from_file jika ada masalah
$openssl_unavailable_warning = ''; // Akan diisi jika openssl tidak ada
load_logging_config_from_file($config);


if ($config['fitur_berbahaya']['tampilkan_error_php']) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}
date_default_timezone_set($config['zona_waktu']);

// --- FUNGSI LOGGING ---
function send_to_discord($message, $webhook_url, $bot_username) {
    if (!function_exists('curl_init') || empty($webhook_url)) return false;
    $data = json_encode(['content' => $message, 'username' => $bot_username]);
    $ch = curl_init($webhook_url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); 
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    $result = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($http_code >= 200 && $http_code < 300);
}

function send_to_telegram($message, $bot_token, $chat_id) {
    if (!function_exists('curl_init') || empty($bot_token) || empty($chat_id)) return false;
    $url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
    $tg_message = str_replace(
        ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'],
        ['\_', '\*', '\[', '\]', '$$', '$$', '\~', '\`', '\>', '\#', '\+', '\-', '\=', '\|', '\{', '\}', '\.', '\!'],
        $message
    );
    $data = ['chat_id' => $chat_id, 'text' => $tg_message, 'parse_mode' => 'MarkdownV2'];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    $result = curl_exec($ch);
    curl_close($ch);
    return (bool)$result; 
}

function send_to_email($message, $to_address, $from_address, $subject_prefix, $status) {
    if (empty($to_address) || empty($from_address)) return false;
    $subject = "{$subject_prefix} [$status] Notifikasi Aksi";
    $headers = "From: {$from_address}\r\n";
    $headers .= "Reply-To: {$from_address}\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    return mail($to_address, $subject, $message, $headers);
}

function is_service_logging_active($service_name) {
    global $config;
    if (!$config['logging']['enabled']) return false; 

    $service_config_key_exists = isset($config['logging'][$service_name]['enabled']);
    $service_config_enabled = $service_config_key_exists ? $config['logging'][$service_name]['enabled'] : false;

    $session_key = 'logging_override_' . $service_name . '_enabled';
    if (isset($_SESSION[$session_key])) {
        return $_SESSION[$session_key]; 
    }
    return $service_config_enabled; 
}

function log_action($action_name, $details = "", $status = "INFO") {
    global $config;
    if (!$config['logging']['enabled']) { 
        return;
    }

    $timestamp = date("Y-m-d H:i:s T");
    $log_message = "[$timestamp] [$status] $action_name";

    if ($config['logging']['log_ip_address'] && isset($_SERVER['REMOTE_ADDR'])) {
        $log_message .= " | IP: " . $_SERVER['REMOTE_ADDR'];
    }
    if (isset($_SESSION['pengguna_login'])) {
        $log_message .= " | User: " . $_SESSION['pengguna_login'];
    }
    if (!empty($details)) {
        $log_message .= " | Details: " . (is_array($details) ? json_encode($details) : $details);
    }

    if (is_service_logging_active('discord') && !empty($config['logging']['discord']['webhook_url'])) {
        send_to_discord($log_message, $config['logging']['discord']['webhook_url'], $config['logging']['discord']['username']);
    }
    if (is_service_logging_active('telegram') && !empty($config['logging']['telegram']['bot_token']) && !empty($config['logging']['telegram']['chat_id'])) {
        send_to_telegram($log_message, $config['logging']['telegram']['bot_token'], $config['logging']['telegram']['chat_id']);
    }
    if (is_service_logging_active('email') && !empty($config['logging']['email']['to_address'])) {
        send_to_email($log_message, $config['logging']['email']['to_address'], $config['logging']['email']['from_address'], $config['logging']['email']['subject_prefix'], $status);
    }
}

// --- FUNGSI HELPER ---
function sanitize_path($path) { return str_replace(['..', "\0"], '', $path); }
function get_current_path() { global $config; $path = $_GET['path'] ?? ''; $path = sanitize_path($path); $full_path = realpath($config['direktori_dasar'] . DIRECTORY_SEPARATOR . $path); if (!$full_path || strpos($full_path, realpath($config['direktori_dasar'])) !== 0) { return realpath($config['direktori_dasar']); } return $full_path; }
function get_relative_path($full_path) { global $config; return ltrim(str_replace(realpath($config['direktori_dasar']), '', $full_path), DIRECTORY_SEPARATOR); }
function format_size($bytes) { if ($bytes >= 1073741824) { $bytes = number_format($bytes / 1073741824, 2) . ' GB'; } elseif ($bytes >= 1048576) { $bytes = number_format($bytes / 1048576, 2) . ' MB'; } elseif ($bytes >= 1024) { $bytes = number_format($bytes / 1024, 2) . ' KB'; } elseif ($bytes > 1) { $bytes = $bytes . ' bytes'; } elseif ($bytes == 1) { $bytes = $bytes . ' byte'; } else { $bytes = '0 bytes'; } return $bytes; }
function get_file_icon($item_path) { if (is_dir($item_path)) return '📁'; $ext = strtolower(pathinfo($item_path, PATHINFO_EXTENSION)); switch ($ext) { case 'txt': case 'md': case 'log': return '📄'; case 'jpg': case 'jpeg': case 'png': case 'gif': case 'bmp': case 'svg': case 'webp': return '🖼️'; case 'pdf': return '📚'; case 'zip': case 'rar': case 'tar': case 'gz': return '📦'; case 'mp3': case 'wav': case 'ogg': case 'flac': return '🎵'; case 'mp4': case 'avi': case 'mov': case 'mkv': case 'webm': return '🎞️'; case 'doc': case 'docx': return '📝'; case 'xls': case 'xlsx': case 'csv': return '📊'; case 'ppt': case 'pptx': return '🖥️'; case 'js': case 'json': case 'html': case 'css': case 'php': case 'py': case 'sh': case 'sql': case 'yaml': case 'yml': return '⚙️'; default: return '📎'; } }
function check_login() { global $config; if (!$config['aktifkan_login']) return true; return isset($_SESSION['pengguna_login']); }
function handle_login() { 
    global $config; 
    if (isset($_POST['username']) && isset($_POST['password'])) { 
        $username = $_POST['username']; $password = $_POST['password']; 
        if (isset($config['pengguna'][$username]) && password_verify($password, $config['pengguna'][$username])) { 
            $_SESSION['pengguna_login'] = $username; 
            log_action("Login Success", "Username: " . htmlspecialchars($username), "SUCCESS");
            header("Location: " . basename(__FILE__)); exit; 
        } else { 
            log_action("Login Failed", "Username: " . htmlspecialchars($username), "WARNING");
            return "Username atau password salah."; 
        } 
    } return null; 
}
function handle_logout() { 
    log_action("Logout", "User: " . ($_SESSION['pengguna_login'] ?? 'N/A'), "INFO");
    session_destroy(); header("Location: " . basename(__FILE__)); exit; 
}
function delete_recursive($dir) { if (!file_exists($dir)) return true; if (!is_dir($dir)) return unlink($dir); foreach (scandir($dir) as $item) { if ($item == '.' || $item == '..') continue; if (!delete_recursive($dir . DIRECTORY_SEPARATOR . $item)) return false; } return rmdir($dir); }
function get_owner_name($path) { if (function_exists('posix_getpwuid')) { $owner_info = posix_getpwuid(fileowner($path)); return $owner_info['name'] ?? fileowner($path); } return fileowner($path); }
function is_file_editable($file_path) { global $config; if (!is_file($file_path) || !is_readable($file_path)) return false; $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION)); return in_array($ext, $config['editable_extensions']); }
function scan_for_malicious_patterns($file_path) { global $config; if (!is_file($file_path) || !is_readable($file_path) || filesize($file_path) == 0 || filesize($file_path) > ($config['scan_file_max_size_kb'] * 1024)) { return false; } $content = @file_get_contents($file_path, false, null, 0, ($config['scan_file_max_size_kb'] * 1024)); if ($content === false) return false; foreach ($config['malicious_patterns'] as $pattern) { if (preg_match('/' . $pattern . '/i', $content)) { return true; } } return false; }

// --- LOGIKA AKSI ---
$current_path = get_current_path();
$relative_current_path = get_relative_path($current_path);
$login_error = null;
$action_message = null; 

if ($config['aktifkan_login'] && !check_login()) {
    $login_error = handle_login();
    if (check_login()) { header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path)); exit; }
}
$aksi = $_GET['aksi'] ?? '';
if (isset($_GET['status_msg'])) { $action_message = ['type' => ($_GET['status_type'] ?? 'success'), 'text' => urldecode($_GET['status_msg'])]; }

if ($config['aktifkan_login'] && !check_login() && $aksi !== 'login_page') { /* Tampilkan login */ } 
elseif ($aksi === 'logout') { handle_logout(); } 
elseif ($aksi === 'toggle_logging_service' && isset($_GET['service'])) {
    $service = $_GET['service'];
    $valid_services = ['discord', 'telegram', 'email'];
    if (in_array($service, $valid_services)) {
        $session_key = 'logging_override_' . $service . '_enabled';
        $current_effective_status = $config['logging'][$service]['enabled'] ?? false;
        if (isset($_SESSION[$session_key])) {
            $current_effective_status = $_SESSION[$session_key];
        }
        $_SESSION[$session_key] = !$current_effective_status;
        $new_status_text = ($_SESSION[$session_key] ? "diaktifkan" : "dinonaktifkan");
        $msg = "Logging untuk " . ucfirst($service) . " berhasil " . $new_status_text . " untuk sesi ini.";
        $type = "success";
        log_action("Logging Setting Changed by User (Toggle)", "Service: ".ucfirst($service).", New Session Status: ".($_SESSION[$session_key] ? "Enabled" : "Disabled"), "INFO");
    } else {
        $msg = "Layanan logging tidak valid.";
        $type = "danger";
    }
    header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type . "&show_logging_settings=true");
    exit;
}
elseif ($aksi === 'save_logging_config' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (check_login() || !$config['aktifkan_login']) {
        $save_result = save_logging_config_to_file($_POST); // true on success, error string on failure
        if ($save_result === true) {
            $msg = "Konfigurasi logging eksternal berhasil disimpan.";
            $type = "success";
            // Reload config into current $config array for immediate effect if needed
            load_logging_config_from_file($config); 
        } else {
            $msg = $save_result; // Contains error message from save function
            $type = "danger";
        }
    } else {
        $msg = "Anda harus login untuk menyimpan konfigurasi.";
        $type = "danger";
    }
    header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type . "&show_logging_settings=true");
    exit;
}
elseif (check_login() || !$config['aktifkan_login']) {
    $msg = ""; $type = "info"; 
    // ... (Aksi upload, create_folder, create_file, dst.) ...
    if ($aksi === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_FILES['files'])) {
            $files = $_FILES['files']; $upload_count = 0; $errors = []; $malware_detected_files = [];
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] === UPLOAD_ERR_OK) {
                    $tmp_name = $files['tmp_name'][$i]; $name = sanitize_path(basename($files['name'][$i]));
                    $destination = $current_path . DIRECTORY_SEPARATOR . $name;
                    if (move_uploaded_file($tmp_name, $destination)) { 
                        $upload_count++;
                        log_action("File Uploaded", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
                        if (scan_for_malicious_patterns($destination)) {
                            $malware_detected_files[] = htmlspecialchars($name);
                            log_action("Malware Detected on Upload", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "CRITICAL");
                        }
                    } else { 
                        $errors[] = "Gagal mengunggah " . htmlspecialchars($name); 
                        log_action("File Upload Failed", "File: " . htmlspecialchars($name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
                    }
                } elseif ($files['error'][$i] !== UPLOAD_ERR_NO_FILE) { 
                    $errors[] = "Error pada file " . htmlspecialchars($files['name'][$i]) . ": " . $files['error'][$i];
                    log_action("File Upload Error", "File: " . htmlspecialchars($files['name'][$i]) . ", Error Code: " . $files['error'][$i], "ERROR");
                }
            }
            $msg = $upload_count . " file berhasil diunggah.";
            if (!empty($malware_detected_files)) $msg .= " Peringatan: Potensi kode berbahaya terdeteksi di file: " . implode(', ', $malware_detected_files) . ".";
            if (!empty($errors)) $msg .= " Kesalahan: " . implode(", ", $errors);
            $type = (empty($errors) && empty($malware_detected_files) ? "success" : (empty($errors) ? "warning" : "danger"));
        } else { $msg = "Tidak ada file yang dipilih untuk diunggah."; $type = "warning"; log_action("Upload Attempt Failed", "No files selected", "WARNING");}
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'create_folder' && isset($_POST['folder_name'])) {
        $folder_name = sanitize_path(basename($_POST['folder_name']));
        if (!empty($folder_name) && !file_exists($current_path . DIRECTORY_SEPARATOR . $folder_name)) {
            if(mkdir($current_path . DIRECTORY_SEPARATOR . $folder_name, $config['default_chmod_folder'])) {
                $msg = "Folder '" . htmlspecialchars($folder_name) . "' berhasil dibuat."; $type = "success";
                log_action("Folder Created", "Name: " . htmlspecialchars($folder_name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal membuat folder '" . htmlspecialchars($folder_name) . "'. Periksa izin."; $type = "danger"; 
                log_action("Folder Creation Failed", "Name: " . htmlspecialchars($folder_name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Nama folder tidak valid, kosong, atau sudah ada."; $type = "danger"; 
            log_action("Folder Creation Attempt Failed", "Invalid/Existing Name: " . htmlspecialchars($folder_name), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'create_file' && isset($_POST['file_name'])) {
        $file_name = sanitize_path(basename($_POST['file_name']));
        if (!empty($file_name) && !file_exists($current_path . DIRECTORY_SEPARATOR . $file_name)) {
            if (file_put_contents($current_path . DIRECTORY_SEPARATOR . $file_name, '') !== false && chmod($current_path . DIRECTORY_SEPARATOR . $file_name, $config['default_chmod_file'])) {
                $msg = "File '" . htmlspecialchars($file_name) . "' berhasil dibuat."; $type = "success";
                log_action("File Created", "Name: " . htmlspecialchars($file_name) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal membuat file '" . htmlspecialchars($file_name) . "'. Periksa izin."; $type = "danger"; 
                log_action("File Creation Failed", "Name: " . htmlspecialchars($file_name) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Nama file tidak valid, kosong, atau sudah ada."; $type = "danger"; 
            log_action("File Creation Attempt Failed", "Invalid/Existing Name: " . htmlspecialchars($file_name), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'delete' && isset($_GET['item'])) {
        $item_to_delete = sanitize_path(basename($_GET['item']));
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_delete;
        if (file_exists($item_full_path) && !in_array($item_to_delete, $config['sembunyikan_item'])) {
            if (delete_recursive($item_full_path)) {
                $msg = "Item '" . htmlspecialchars($item_to_delete) . "' berhasil dihapus."; $type = "success";
                log_action("Item Deleted", "Item: " . htmlspecialchars($item_to_delete) . ", Path: " . htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal menghapus item '" . htmlspecialchars($item_to_delete) . "'."; $type = "danger"; 
                log_action("Item Deletion Failed", "Item: " . htmlspecialchars($item_to_delete) . ", Path: " . htmlspecialchars($relative_current_path), "ERROR");
            }
        } else { 
            $msg = "Item tidak ditemukan atau tidak diizinkan untuk dihapus."; $type = "danger"; 
            log_action("Item Deletion Attempt Failed", "Not Found/Forbidden: " . htmlspecialchars($item_to_delete), "WARNING");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'multi_delete' && isset($_POST['items_to_zip']) && is_array($_POST['items_to_zip'])) {
        $items_to_delete_arr = $_POST['items_to_zip']; 
        $deleted_count = 0; $error_count = 0; $error_details = []; $deleted_items_log = [];
        foreach ($items_to_delete_arr as $item_name) {
            $item_name_sanitized = sanitize_path(basename($item_name));
            $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_name_sanitized;
            if (file_exists($item_full_path) && !in_array($item_name_sanitized, $config['sembunyikan_item'])) {
                if (delete_recursive($item_full_path)) { $deleted_count++; $deleted_items_log[] = $item_name_sanitized; } 
                else { $error_count++; $error_details[] = htmlspecialchars($item_name_sanitized); }
            } else { $error_count++; $error_details[] = htmlspecialchars($item_name_sanitized) . " (tidak ada/dilarang)"; }
        }
        $msg = $deleted_count . " item berhasil dihapus.";
        if ($error_count > 0) { $msg .= " " . $error_count . " item gagal dihapus: " . implode(', ', $error_details) . "."; }
        $type = ($error_count == 0) ? "success" : ($deleted_count > 0 ? "warning" : "danger");
        log_action("Multi-Item Delete", "Deleted: " . implode(', ', $deleted_items_log) . ($error_count > 0 ? ", Failed: " . implode(', ', $error_details) : "") . ", Path: " . htmlspecialchars($relative_current_path), $type == "success" ? "SUCCESS" : ($type == "warning" ? "WARNING" : "ERROR"));
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'rename' && isset($_POST['old_name']) && isset($_POST['new_name'])) {
        $old_name = sanitize_path(basename($_POST['old_name'])); $new_name = sanitize_path(basename($_POST['new_name']));
        $old_full_path = $current_path . DIRECTORY_SEPARATOR . $old_name; $new_full_path = $current_path . DIRECTORY_SEPARATOR . $new_name;
        if (empty($new_name)) { $msg = "Nama baru tidak boleh kosong."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New name empty", "WARNING");}
        elseif (file_exists($new_full_path)) { $msg = "Nama baru '" . htmlspecialchars($new_name) . "' sudah ada."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name)." (already exists)", "WARNING");}
        elseif (!file_exists($old_full_path)) { $msg = "Item lama '" . htmlspecialchars($old_name) . "' tidak ditemukan."; $type = "danger"; log_action("Rename Failed", "Old: ".htmlspecialchars($old_name)." (not found)", "WARNING");}
        elseif (rename($old_full_path, $new_full_path)) { 
            $msg = "Item '" . htmlspecialchars($old_name) . "' berhasil di-rename menjadi '" . htmlspecialchars($new_name) . "'."; $type = "success"; 
            log_action("Item Renamed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
        } else { 
            $msg = "Gagal me-rename item '" . htmlspecialchars($old_name) . "'. Periksa izin."; $type = "danger"; 
            log_action("Rename Failed", "Old: ".htmlspecialchars($old_name).", New: ".htmlspecialchars($new_name).", Path: ".htmlspecialchars($relative_current_path), "ERROR");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'chmod' && isset($_POST['item']) && isset($_POST['permissions'])) {
        if (!$config['fitur_berbahaya']['edit_chmod_luas']) {
            $msg = "Fitur ubah izin (chmod) dinonaktifkan oleh administrator."; $type = "warning";
            log_action("Chmod Attempt Denied", "Feature disabled by admin", "WARNING");
        } else {
            $item_to_chmod = sanitize_path(basename($_POST['item'])); $permissions = $_POST['permissions']; 
            $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_chmod;
            if (!file_exists($item_full_path)) { $msg = "Item '" . htmlspecialchars($item_to_chmod) . "' tidak ditemukan."; $type = "danger"; log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod)." (not found)", "WARNING");}
            elseif (!preg_match('/^0[0-7]{3}$/', $permissions)) { $msg = "Format izin tidak valid. Gunakan format octal 4 digit (mis: 0755)."; $type = "danger"; log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod).", Invalid perms: ".$permissions, "WARNING");}
            elseif (chmod($item_full_path, octdec($permissions))) { 
                $msg = "Izin untuk '" . htmlspecialchars($item_to_chmod) . "' berhasil diubah menjadi " . htmlspecialchars($permissions) . "."; $type = "success"; 
                log_action("Permissions Changed", "Item: ".htmlspecialchars($item_to_chmod).", Perms: ".$permissions.", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
            } else { 
                $msg = "Gagal mengubah izin untuk '" . htmlspecialchars($item_to_chmod) . "'."; $type = "danger"; 
                log_action("Chmod Failed", "Item: ".htmlspecialchars($item_to_chmod).", Perms: ".$permissions.", Path: ".htmlspecialchars($relative_current_path), "ERROR");
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'edit_time' && isset($_POST['item']) && isset($_POST['datetime'])) {
        $item_to_touch = sanitize_path(basename($_POST['item'])); $datetime_str = $_POST['datetime'];
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_touch; $timestamp = strtotime($datetime_str);
        if (!file_exists($item_full_path)) { $msg = "Item '" . htmlspecialchars($item_to_touch) . "' tidak ditemukan."; $type = "danger"; log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch)." (not found)", "WARNING");}
        elseif ($timestamp === false) { $msg = "Format tanggal/waktu tidak valid: " . htmlspecialchars($datetime_str); $type = "danger"; log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch).", Invalid datetime: ".$datetime_str, "WARNING");}
        elseif (touch($item_full_path, $timestamp)) { 
            $msg = "Waktu modifikasi untuk '" . htmlspecialchars($item_to_touch) . "' berhasil diubah."; $type = "success"; 
            log_action("Timestamp Changed", "Item: ".htmlspecialchars($item_to_touch).", Time: ".$datetime_str.", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
        } else { 
            $msg = "Gagal mengubah waktu modifikasi untuk '" . htmlspecialchars($item_to_touch) . "'."; $type = "danger"; 
            log_action("Edit Time Failed", "Item: ".htmlspecialchars($item_to_touch).", Time: ".$datetime_str.", Path: ".htmlspecialchars($relative_current_path), "ERROR");
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'zip' && isset($_POST['items_to_zip']) && is_array($_POST['items_to_zip'])) {
        if (!class_exists('ZipArchive')) { $msg = "Kelas ZipArchive tidak ditemukan. Fitur Zip tidak tersedia."; $type = "danger"; log_action("Zip Failed", "ZipArchive class not found", "ERROR");}
        else {
            $items_to_zip_arr = $_POST['items_to_zip']; $zip_name = 'arsip_' . date('YmdHis') . '.zip';
            $zip_path = $current_path . DIRECTORY_SEPARATOR . $zip_name; $zip = new ZipArchive();
            if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
                $zipped_count = 0; $zipped_items_log = [];
                foreach ($items_to_zip_arr as $item_name) {
                    $item_name_sanitized = sanitize_path(basename($item_name));
                    $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_name_sanitized;
                    if (file_exists($item_full_path)) {
                        if (is_dir($item_full_path)) {
                            $files_in_dir = new RecursiveIteratorIterator( new RecursiveDirectoryIterator($item_full_path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
                            foreach ($files_in_dir as $name_in_dir => $file_in_dir) {
                                if (!$file_in_dir->isDir()) {
                                    $filePath = $file_in_dir->getRealPath();
                                    $relativePath = $item_name_sanitized . DIRECTORY_SEPARATOR . substr($filePath, strlen($item_full_path) + 1);
                                    $zip->addFile($filePath, $relativePath);
                                }
                            } $zip->addEmptyDir($item_name_sanitized); 
                        } else { $zip->addFile($item_full_path, $item_name_sanitized); }
                        $zipped_count++; $zipped_items_log[] = $item_name_sanitized;
                    }
                } $zip->close();
                if ($zipped_count > 0) { 
                    $msg = $zipped_count . " item berhasil di-zip ke '" . htmlspecialchars($zip_name) . "'."; $type = "success"; 
                    log_action("Files Zipped", "Archive: ".htmlspecialchars($zip_name).", Items: ".implode(', ',$zipped_items_log).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
                } else { 
                    $msg = "Tidak ada item valid yang dipilih untuk di-zip."; $type = "warning"; unlink($zip_path); 
                    log_action("Zip Attempt Failed", "No valid items selected", "WARNING");
                }
            } else { $msg = "Gagal membuat file zip."; $type = "danger"; log_action("Zip Failed", "Could not create zip archive", "ERROR");}
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'unzip' && isset($_GET['item'])) {
        if (!class_exists('ZipArchive')) { $msg = "Kelas ZipArchive tidak ditemukan. Fitur Unzip tidak tersedia."; $type = "danger"; log_action("Unzip Failed", "ZipArchive class not found", "ERROR");}
        else {
            $zip_file_name = sanitize_path(basename($_GET['item']));
            $zip_file_path = $current_path . DIRECTORY_SEPARATOR . $zip_file_name;
            if (!file_exists($zip_file_path) || strtolower(pathinfo($zip_file_name, PATHINFO_EXTENSION)) !== 'zip') { 
                $msg = "File zip '" . htmlspecialchars($zip_file_name) . "' tidak ditemukan atau bukan file zip."; $type = "danger"; 
                log_action("Unzip Failed", "File not found or not a zip: ".htmlspecialchars($zip_file_name), "WARNING");
            } else {
                $zip = new ZipArchive();
                if ($zip->open($zip_file_path) === TRUE) {
                    if ($zip->extractTo($current_path)) { 
                        $msg = "File '" . htmlspecialchars($zip_file_name) . "' berhasil di-unzip."; $type = "success"; 
                        log_action("File Unzipped", "Archive: ".htmlspecialchars($zip_file_name).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
                    } else { 
                        $msg = "Gagal mengekstrak file '" . htmlspecialchars($zip_file_name) . "'. Periksa izin tulis."; $type = "danger"; 
                        log_action("Unzip Failed", "Could not extract: ".htmlspecialchars($zip_file_name), "ERROR");
                    }
                    $zip->close();
                } else { 
                    $msg = "Gagal membuka file zip '" . htmlspecialchars($zip_file_name) . "'."; $type = "danger"; 
                    log_action("Unzip Failed", "Could not open zip: ".htmlspecialchars($zip_file_name), "ERROR");
                }
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'preview' && isset($_GET['item'])) {
        $item_to_preview = sanitize_path(basename($_GET['item']));
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_preview;
        if (file_exists($item_full_path) && is_readable($item_full_path) && !is_dir($item_full_path)) {
            log_action("File Preview/Download", "Item: ".htmlspecialchars($item_to_preview).", Path: ".htmlspecialchars($relative_current_path), "INFO");
            $mime_type = mime_content_type($item_full_path);
            if (strpos($mime_type, 'text/') === 0 || in_array($mime_type, ['application/json', 'application/xml', 'application/javascript', 'application/css'])) {
                header('Content-Type: ' . $mime_type . '; charset=utf-8'); readfile($item_full_path); exit;
            } elseif (strpos($mime_type, 'image/') === 0 || $mime_type === 'application/pdf') { 
                header('Content-Type: ' . $mime_type); header('Content-Length: ' . filesize($item_full_path)); readfile($item_full_path); exit;
            } else { 
                header('Content-Description: File Transfer'); header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($item_full_path) . '"');
                header('Expires: 0'); header('Cache-Control: must-revalidate'); header('Pragma: public');
                header('Content-Length: ' . filesize($item_full_path)); readfile($item_full_path); exit;
            }
        }
        $msg = "Gagal mempreview file '" . htmlspecialchars($item_to_preview) . "'. File tidak ada atau tidak bisa dibaca."; $type = "danger";
        log_action("Preview Failed", "Item: ".htmlspecialchars($item_to_preview)." (not found/unreadable)", "WARNING");
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'edit' && isset($_GET['item'])) { 
        log_action("File Edit Page Accessed", "Item: ".htmlspecialchars(basename($_GET['item'])).", Path: ".htmlspecialchars($relative_current_path), "INFO");
        /* Halaman edit ditangani di HTML */ 
    } elseif ($aksi === 'save_edit' && isset($_POST['item']) && isset($_POST['content'])) {
        $item_to_save = sanitize_path(basename($_POST['item'])); $content_to_save = $_POST['content']; 
        $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item_to_save;
        $malware_detected_msg = "";
        if (!is_file_editable($item_full_path)) { $msg = "Tipe file '" . htmlspecialchars($item_to_save) . "' tidak diizinkan untuk diedit."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (not editable type)", "WARNING");}
        elseif (!is_writable($item_full_path)) { $msg = "File '" . htmlspecialchars($item_to_save) . "' tidak dapat ditulis. Periksa izin."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (not writable)", "ERROR");}
        elseif (file_put_contents($item_full_path, $content_to_save) !== false) {
            $msg = "File '" . htmlspecialchars($item_to_save) . "' berhasil disimpan."; $type = "success";
            log_action("File Edited & Saved", "Item: ".htmlspecialchars($item_to_save).", Path: ".htmlspecialchars($relative_current_path), "SUCCESS");
            if (scan_for_malicious_patterns($item_full_path)) {
                $malware_detected_msg = " PERINGATAN: Potensi kode berbahaya terdeteksi setelah menyimpan file ini!";
                $type = "warning"; 
                log_action("Malware Detected After Edit", "Item: ".htmlspecialchars($item_to_save).", Path: ".htmlspecialchars($relative_current_path), "CRITICAL");
            } $msg .= $malware_detected_msg;
        } else { $msg = "Gagal menyimpan file '" . htmlspecialchars($item_to_save) . "'."; $type = "danger"; log_action("Save Edit Failed", "Item: ".htmlspecialchars($item_to_save)." (file_put_contents failed)", "ERROR");}
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&item=" . urlencode($item_to_save) . "&aksi=edit&status_msg=" . urlencode($msg) . "&status_type=" . $type); exit;
    } elseif ($aksi === 'terminal_exec' && $config['fitur_berbahaya']['terminal'] && isset($_POST['command'])) {
        $command = $_POST['command']; $output = '';
        log_action("Terminal Command Executed", "Command: ".$command.", Path: ".htmlspecialchars($relative_current_path), "WARNING");
        if (function_exists('shell_exec')) { $output = shell_exec($command . ' 2>&1'); } 
        else { $output = "Fungsi shell_exec tidak tersedia."; }
        $_SESSION['terminal_output'] = $output; $_SESSION['last_command'] = $command;
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&show_terminal=true"); exit;
    } elseif ($aksi === 'scan_directory') {
        $scanned_files_count = 0; $threats_found_count = 0; $threat_details = [];
        $dir_items = scandir($current_path);
        if ($dir_items === false) {
            $msg = "Gagal membaca isi direktori."; $type = "danger";
            log_action("Directory Scan Failed", "Could not read directory: ".htmlspecialchars($relative_current_path), "ERROR");
        } else {
            foreach ($dir_items as $item) {
                if (in_array($item, $config['sembunyikan_item'])) continue;
                $item_full_path = $current_path . DIRECTORY_SEPARATOR . $item;
                if (is_file($item_full_path)) {
                    $scanned_files_count++;
                    if (scan_for_malicious_patterns($item_full_path)) {
                        $threats_found_count++;
                        $threat_details[] = htmlspecialchars($item);
                    }
                }
            }
            if ($threats_found_count > 0) {
                $msg = "Pemindaian direktori selesai. " . $threats_found_count . " potensi ancaman ditemukan di " . $scanned_files_count . " file yang dipindai: " . implode(', ', $threat_details) . ". Harap periksa secara manual!";
                $type = "warning";
                log_action("Directory Scan Result", "Path: ".htmlspecialchars($relative_current_path).", Threats: ".$threats_found_count."/".$scanned_files_count.", Files: ".implode(', ',$threat_details), "WARNING");
            } else {
                $msg = "Pemindaian direktori selesai. Tidak ada potensi ancaman terdeteksi di " . $scanned_files_count . " file yang dipindai.";
                $type = "success";
                log_action("Directory Scan Result", "Path: ".htmlspecialchars($relative_current_path).", Threats: 0/".$scanned_files_count, "INFO");
            }
        }
        header("Location: " . basename(__FILE__) . "?path=" . urlencode($relative_current_path) . "&status_msg=" . urlencode($msg) . "&status_type=" . $type);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php if ($aksi === 'edit' && isset($_GET['item'])) { echo "Edit: " . htmlspecialchars(basename($_GET['item'])) . " - " . htmlspecialchars($config['judul_filemanager']); } else { echo htmlspecialchars($config['judul_filemanager']) . " - " . htmlspecialchars(basename($current_path)); } ?></title>
    <style>
        /* CSS (AYANA FILE MANAGER <3) */
        :root { 
            --font-family-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-family-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            --color-bg-light: #f9fafb; --color-text-light: #1f2937; --color-primary-light: #3b82f6;
            --color-primary-hover-light: #2563eb; --color-secondary-light: #6b7280; --color-border-light: #e5e7eb;
            --color-card-bg-light: #ffffff; --color-table-header-bg-light: #f3f4f6; --color-table-row-hover-bg-light: #f0f2f5;
            --color-success-light: #10b981; --color-danger-light: #ef4444; --color-warning-light: #f59e0b; --color-info-light: #3b82f6;
            --color-link-light: var(--color-primary-light);
            --color-danger-light-rgb: 239, 68, 68; 

            --color-bg-dark: #111827; --color-text-dark: #d1d5db; --color-primary-dark: #60a5fa;
            --color-primary-hover-dark: #3b82f6; --color-secondary-dark: #9ca3af; --color-border-dark: #374151;
            --color-card-bg-dark: #1f2937; --color-table-header-bg-dark: #374151; --color-table-row-hover-bg-dark: #2c3542;
            --color-success-dark: #34d399; --color-danger-dark: #f87171; --color-warning-dark: #fbbf24; --color-info-dark: var(--color-primary-dark);
            --color-link-dark: var(--color-primary-dark);
            --color-danger-dark-rgb: 248, 113, 113; 

            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05); --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --border-radius: 0.5rem; --border-radius-sm: 0.25rem;
        }
        body { font-family: var(--font-family-sans); margin: 0; background-color: var(--color-bg-light); color: var(--color-text-light); font-size: 14px; line-height: 1.6; display: flex; flex-direction: column; min-height: 100vh; transition: background-color 0.3s ease, color 0.3s ease; }
        body.dark-mode { background-color: var(--color-bg-dark); color: var(--color-text-dark); }
        .main-wrapper { display: flex; flex-direction: column; flex-grow: 1; }
        .container { width: 95%; max-width: 1400px; margin: 20px auto; padding: 20px; background-color: var(--color-card-bg-light); border-radius: var(--border-radius); box-shadow: var(--shadow-md); flex-grow: 1; }
        body.dark-mode .container { background-color: var(--color-card-bg-dark); }
        .navbar { background-color: var(--color-card-bg-light); color: var(--color-text-light); padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--color-border-light); box-shadow: var(--shadow-sm); position: sticky; top: 0; z-index: 1000; }
        body.dark-mode .navbar { background-color: var(--color-card-bg-dark); color: var(--color-text-dark); border-bottom-color: var(--color-border-dark); }
        .navbar .title { font-size: 1.5em; font-weight: 600; }
        .navbar .nav-buttons .btn { margin-left: 0.75rem; }
        .breadcrumb { padding: 0.75rem 0; margin-bottom: 1.25rem; list-style: none; background-color: transparent; font-size: 0.9em; display: flex; flex-wrap: wrap; align-items: center; }
        .breadcrumb-item { display: flex; align-items: center; }
        .breadcrumb-item+.breadcrumb-item::before { content: "›"; margin: 0 0.5rem; color: var(--color-secondary-light); }
        body.dark-mode .breadcrumb-item+.breadcrumb-item::before { color: var(--color-secondary-dark); }
        .breadcrumb-item a { color: var(--color-link-light); text-decoration: none; font-weight: 500; }
        body.dark-mode .breadcrumb-item a { color: var(--color-link-dark); }
        .breadcrumb-item a:hover { text-decoration: underline; }
        .breadcrumb-item.active { color: var(--color-secondary-light); font-weight: 500; }
        body.dark-mode .breadcrumb-item.active { color: var(--color-secondary-dark); }
        .current-path-info { font-size: 0.85em; color: var(--color-secondary-light); margin-bottom: 1.25rem; word-break: break-all; }
        body.dark-mode .current-path-info { color: var(--color-secondary-dark); }
        .toolbar { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.25rem; align-items: center; }
        .search-bar { display: flex; flex-grow: 1; min-width: 250px; }
        .search-bar input[type="text"] { flex-grow: 1; padding: 0.6rem 0.8rem; border: 1px solid var(--color-border-light); border-radius: var(--border-radius-sm) 0 0 var(--border-radius-sm); font-size: 0.9em; background-color: var(--color-card-bg-light); color: var(--color-text-light); }
        body.dark-mode .search-bar input[type="text"] { background-color: var(--color-card-bg-dark); border-color: var(--color-border-dark); color: var(--color-text-dark); }
        .search-bar input[type="text"]:focus { outline: none; border-color: var(--color-primary-light); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3); }
        body.dark-mode .search-bar input[type="text"]:focus { border-color: var(--color-primary-dark); box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.3); }
        .search-bar .btn { border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0; }
        .actions-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
        .file-table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 1.25rem; font-size: 0.9em; }
        .file-table th, .file-table td { padding: 0.75rem 1rem; text-align: left; vertical-align: middle; border-bottom: 1px solid var(--color-border-light); }
        body.dark-mode .file-table th, body.dark-mode .file-table td { border-bottom-color: var(--color-border-dark); }
        .file-table th { background-color: var(--color-table-header-bg-light); font-weight: 600; color: var(--color-text-light); }
        body.dark-mode .file-table th { background-color: var(--color-table-header-bg-dark); color: var(--color-text-dark); }
        .file-table tr:hover td { background-color: var(--color-table-row-hover-bg-light); }
        body.dark-mode .file-table tr:hover td { background-color: var(--color-table-row-hover-bg-dark); }
        .file-table tr.table-danger-row td { background-color: rgba(var(--color-danger-light-rgb), 0.15) !important; }
        body.dark-mode .file-table tr.table-danger-row td { background-color: rgba(var(--color-danger-dark-rgb), 0.2) !important; }
        .file-table tr.table-danger-row:hover td { background-color: rgba(var(--color-danger-light-rgb), 0.25) !important; }
        body.dark-mode .file-table tr.table-danger-row:hover td { background-color: rgba(var(--color-danger-dark-rgb), 0.3) !important; }
        .file-table td a { color: var(--color-link-light); text-decoration: none; font-weight: 500; }
        body.dark-mode .file-table td a { color: var(--color-link-dark); }
        .file-table td a:hover { text-decoration: underline; }
        .file-table .actions .btn { margin-right: 0.3rem; margin-bottom: 0.3rem; padding: 0.3rem 0.6rem; font-size: 0.85em; }
        .file-table .icon { font-size: 1.2em; margin-right: 0.5rem; vertical-align: middle; }
        .file-table input[type="checkbox"] { width: 1rem; height: 1rem; vertical-align: middle; }
        .malware-warning-icon { color: var(--color-danger-light); font-weight: bold; margin-left: 0.3rem; cursor: help; }
        body.dark-mode .malware-warning-icon { color: var(--color-danger-dark); }
        #drop-area { border: 2px dashed var(--color-border-light); border-radius: var(--border-radius); padding: 2rem; text-align: center; margin-bottom: 1.25rem; background-color: var(--color-bg-light); cursor: pointer; transition: border-color 0.2s ease, background-color 0.2s ease; }
        body.dark-mode #drop-area { border-color: var(--color-border-dark); background-color: var(--color-card-bg-dark); }
        #drop-area.highlight { border-color: var(--color-primary-light); background-color: rgba(59, 130, 246, 0.05); }
        body.dark-mode #drop-area.highlight { border-color: var(--color-primary-dark); background-color: rgba(96, 165, 250, 0.1); }
        #drop-area p { margin: 0; font-size: 1em; color: var(--color-secondary-light); }
        body.dark-mode #drop-area p { color: var(--color-secondary-dark); }
        #upload-progress { width:100%; margin-top: 0.5rem; height: 0.5rem; border-radius: var(--border-radius-sm); }
        #upload-progress::-webkit-progress-bar { background-color: var(--color-border-light); border-radius: var(--border-radius-sm); }
        #upload-progress::-webkit-progress-value { background-color: var(--color-primary-light); border-radius: var(--border-radius-sm); transition: width 0.1s ease; }
        body.dark-mode #upload-progress::-webkit-progress-bar { background-color: var(--color-border-dark); }
        body.dark-mode #upload-progress::-webkit-progress-value { background-color: var(--color-primary-dark); }
        .footer { text-align: center; padding: 1.5rem; margin-top: auto; background-color: var(--color-card-bg-light); color: var(--color-secondary-light); font-size: 0.9em; border-top: 1px solid var(--color-border-light); }
        body.dark-mode .footer { background-color: var(--color-card-bg-dark); color: var(--color-secondary-dark); border-top-color: var(--color-border-dark); }
        .modal { display: none; position: fixed; z-index: 1050; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); backdrop-filter: blur(5px); align-items: center; justify-content: center; }
        .modal-content { background-color: var(--color-card-bg-light); margin: auto; padding: 1.5rem; border: 1px solid var(--color-border-light); width: 90%; max-width: 600px; border-radius: var(--border-radius); box-shadow: var(--shadow-lg); position: relative; animation: modal-fade-in 0.3s ease-out; }
        body.dark-mode .modal-content { background-color: var(--color-card-bg-dark); border-color: var(--color-border-dark); }
        @keyframes modal-fade-in { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        .modal-header { padding-bottom: 0.75rem; border-bottom: 1px solid var(--color-border-light); margin-bottom: 1rem; }
        body.dark-mode .modal-header { border-bottom-color: var(--color-border-dark); }
        .modal-header h4 { margin: 0; font-size: 1.25em; font-weight: 600; }
        .modal-body { padding-top: 0.5rem; padding-bottom: 1rem; max-height: 70vh; overflow-y: auto;}
        .modal-body .logging-toggle-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--color-border-light); }
        body.dark-mode .modal-body .logging-toggle-item { border-bottom-color: var(--color-border-dark); }
        .modal-body .logging-toggle-item:last-child { border-bottom: none; }
        .modal-body hr { border: 0; border-top: 1px solid var(--color-border-light); margin: 1.5rem 0; }
        body.dark-mode .modal-body hr { border-top-color: var(--color-border-dark); }
        .modal-footer { padding-top: 1rem; border-top: 1px solid var(--color-border-light); text-align: right; display: flex; gap: 0.5rem; justify-content: flex-end; }
        body.dark-mode .modal-footer { border-top-color: var(--color-border-dark); }
        .close-btn { color: var(--color-secondary-light); font-size: 1.75rem; font-weight: bold; cursor: pointer; position: absolute; top: 0.75rem; right: 1rem; line-height: 1; }
        body.dark-mode .close-btn { color: var(--color-secondary-dark); }
        .close-btn:hover, .close-btn:focus { color: var(--color-text-light); text-decoration: none; }
        body.dark-mode .close-btn:hover, body.dark-mode .close-btn:focus { color: var(--color-text-dark); }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: .5rem; font-weight: 500; font-size: 0.9em; }
        .form-group input[type="text"], .form-group input[type="password"], .form-group input[type="datetime-local"], .form-group input[type="url"], .form-group input[type="email"], .form-group textarea { width: 100%; box-sizing: border-box; padding: 0.6rem 0.8rem; font-size: 0.9em; color: var(--color-text-light); background-color: var(--color-card-bg-light); border: 1px solid var(--color-border-light); border-radius: var(--border-radius-sm); transition: border-color .15s ease-in-out, box-shadow .15s ease-in-out; }
        body.dark-mode .form-group input[type="text"], body.dark-mode .form-group input[type="password"], body.dark-mode .form-group input[type="datetime-local"], body.dark-mode .form-group input[type="url"], body.dark-mode .form-group input[type="email"], body.dark-mode .form-group textarea { color: var(--color-text-dark); background-color: var(--color-bg-dark); border-color: var(--color-border-dark); }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: var(--color-primary-light); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
        body.dark-mode .form-group input:focus, body.dark-mode .form-group textarea:focus { border-color: var(--color-primary-dark); box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.2); }
        .form-group textarea { min-height: 150px; font-family: var(--font-family-mono); }
        .btn { display: inline-flex; align-items: center; justify-content: center; font-weight: 500; text-align: center; vertical-align: middle; cursor: pointer; user-select: none; background-color: transparent; border: 1px solid transparent; padding: 0.6rem 1rem; font-size: 0.9em; line-height: 1.5; border-radius: var(--border-radius-sm); transition: color .15s ease-in-out, background-color .15s ease-in-out, border-color .15s ease-in-out, box-shadow .15s ease-in-out, transform .1s ease-out; }
        .btn:disabled { opacity: 0.65; cursor: not-allowed; box-shadow: none; transform: none; }
        .btn .icon { margin-right: 0.4em; font-size: 1.1em; }
        .btn-primary { color: #fff; background-color: var(--color-primary-light); border-color: var(--color-primary-light); box-shadow: var(--shadow-sm); }
        .btn-primary:hover:not(:disabled) { background-color: var(--color-primary-hover-light); border-color: var(--color-primary-hover-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-primary { background-color: var(--color-primary-dark); border-color: var(--color-primary-dark); }
        body.dark-mode .btn-primary:hover:not(:disabled) { background-color: var(--color-primary-hover-dark); border-color: var(--color-primary-hover-dark); }
        .btn-secondary { color: var(--color-text-light); background-color: var(--color-table-header-bg-light); border-color: var(--color-border-light); box-shadow: var(--shadow-sm); }
        .btn-secondary:hover:not(:disabled) { background-color: var(--color-border-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-secondary { color: var(--color-text-dark); background-color: var(--color-border-dark); border-color: var(--color-border-dark); }
        body.dark-mode .btn-secondary:hover:not(:disabled) { background-color: var(--color-table-header-bg-dark); }
        .btn-danger { color: #fff; background-color: var(--color-danger-light); border-color: var(--color-danger-light); box-shadow: var(--shadow-sm); }
        .btn-danger:hover:not(:disabled) { background-color: #d93333; border-color: #d93333; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-danger { background-color: var(--color-danger-dark); border-color: var(--color-danger-dark); }
        body.dark-mode .btn-danger:hover:not(:disabled) { background-color: #f05050; border-color: #f05050; }
        .btn-warning { color: #fff; background-color: var(--color-warning-light); border-color: var(--color-warning-light); box-shadow: var(--shadow-sm); }
        .btn-warning:hover:not(:disabled) { background-color: #e08e0b; border-color: #e08e0b; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-warning { color: var(--color-bg-dark); background-color: var(--color-warning-dark); border-color: var(--color-warning-dark); }
        body.dark-mode .btn-warning:hover:not(:disabled) { background-color: #f0b01f; border-color: #f0b01f; }
        .btn-info { color: #fff; background-color: var(--color-info-light); border-color: var(--color-info-light); box-shadow: var(--shadow-sm); }
        .btn-info:hover:not(:disabled) { background-color: var(--color-primary-hover-light); border-color: var(--color-primary-hover-light); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-info { background-color: var(--color-info-dark); border-color: var(--color-info-dark); }
        body.dark-mode .btn-info:hover:not(:disabled) { background-color: var(--color-primary-hover-dark); border-color: var(--color-primary-hover-dark); }
        .btn-success { color: #fff; background-color: var(--color-success-light); border-color: var(--color-success-light); box-shadow: var(--shadow-sm); }
        .btn-success:hover:not(:disabled) { background-color: #0c9b6a; border-color: #0c9b6a; box-shadow: var(--shadow-md); transform: translateY(-1px); }
        body.dark-mode .btn-success { background-color: var(--color-success-dark); border-color: var(--color-success-dark); }
        body.dark-mode .btn-success:hover:not(:disabled) { background-color: #2cc289; border-color: #2cc289; }
        .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8em; }
        .alert { position: relative; padding: 0.8rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: var(--border-radius-sm); font-size: 0.9em; }
        .alert-success { color: var(--color-success-light); background-color: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.2); }
        body.dark-mode .alert-success { color: var(--color-success-dark); background-color: rgba(52, 211, 153, 0.15); border-color: rgba(52, 211, 153, 0.3); }
        .alert-danger { color: var(--color-danger-light); background-color: rgba(var(--color-danger-light-rgb), 0.1); border-color: rgba(var(--color-danger-light-rgb), 0.2); }
        body.dark-mode .alert-danger { color: var(--color-danger-dark); background-color: rgba(var(--color-danger-dark-rgb), 0.15); border-color: rgba(var(--color-danger-dark-rgb), 0.3); }
        .alert-warning { color: #856404; background-color: #fff3cd; border-color: #ffeeba; }
        body.dark-mode .alert-warning { color: var(--color-warning-dark); background-color: rgba(251, 191, 36, 0.15); border-color: rgba(251, 191, 36, 0.3); }
        .alert-info { color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; }
        body.dark-mode .alert-info { color: var(--color-info-dark); background-color: rgba(96, 165, 250, 0.15); border-color: rgba(96, 165, 250, 0.3); }
        .glitch-hover:hover { animation: glitch-subtle 0.2s infinite alternate; }
        @keyframes glitch-subtle { 0% { transform: translate(0, 0) skew(0); } 50% { transform: translate(0.5px, -0.5px) skew(0.2deg); } 100% { transform: translate(-0.5px, 0.5px) skew(-0.2deg); } }
        .login-page-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; background-color: var(--color-bg-light); }
        body.dark-mode .login-page-wrapper { background-color: var(--color-bg-dark); }
        .login-box { width: 100%; max-width: 400px; padding: 2rem; background: var(--color-card-bg-light); border-radius: var(--border-radius); box-shadow: var(--shadow-lg); }
        body.dark-mode .login-box { background: var(--color-card-bg-dark); }
        .login-box h2 { text-align: center; margin-bottom: 1.5rem; font-size: 1.5em; font-weight: 600; color: var(--color-text-light); }
        body.dark-mode .login-box h2 { color: var(--color-text-dark); }
        .login-box .btn { width: 100%; padding: 0.75rem; font-size: 1em; }
        .edit-page-container { padding: 1rem 0; }
        .edit-page-container h3 { font-size: 1.5em; margin-bottom: 1rem; font-weight: 600; }
        .edit-page-container .form-group textarea { min-height: calc(100vh - 320px); max-height: 70vh; font-size: 0.9em; line-height: 1.6; }
        .edit-page-container .edit-actions-bar { margin-top: 1rem; display: flex; gap: 0.75rem; justify-content: flex-start; }
        #terminal-output { background: var(--color-bg-dark); color: #00ff00; padding: 0.75rem; height: 350px; overflow-y: scroll; font-family: var(--font-family-mono); white-space: pre-wrap; margin-bottom: 0.75rem; border-radius: var(--border-radius-sm); border: 1px solid var(--color-border-dark); font-size: 0.85em; }
        body.dark-mode #terminal-output { background: #0a0f14; border-color: #2a3038; }
        #terminal-form .input-group { display: flex; }
        #terminal-form .input-group-prepend { padding: 0.6rem 0.8rem; background: var(--color-secondary-dark); color: var(--color-text-dark); border-radius: var(--border-radius-sm) 0 0 var(--border-radius-sm); font-family: var(--font-family-mono); font-size: 0.9em; }
        body.dark-mode #terminal-form .input-group-prepend { background: #4b5563; }
        #terminal_command { border-radius: 0 !important; flex-grow: 1; }
        #terminal-form .btn { border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0; }
        #scrollTopBtn { display: none; position: fixed; bottom: 20px; right: 20px; z-index: 1010; border: none; outline: none; background-color: var(--color-primary-light); color: white; cursor: pointer; padding: 10px 12px; border-radius: var(--border-radius-sm); font-size: 1.2em; box-shadow: var(--shadow-md); transition: opacity 0.3s, visibility 0.3s; opacity: 0; visibility: hidden; }
        body.dark-mode #scrollTopBtn { background-color: var(--color-primary-dark); }
        #scrollTopBtn.show { opacity: 1; visibility: visible; }
        #scrollTopBtn:hover { background-color: var(--color-primary-hover-light); }
        body.dark-mode #scrollTopBtn:hover { background-color: var(--color-primary-hover-dark); }
        .security-note { font-size: 0.8em; color: var(--color-secondary-light); margin-top: 1rem; padding: 0.5rem; background-color: rgba(245,158,11, 0.1); border: 1px solid rgba(245,158,11, 0.2); border-radius: var(--border-radius-sm); }
        body.dark-mode .security-note { color: var(--color-secondary-dark); background-color: rgba(251,191,36, 0.1); border-color: rgba(251,191,36, 0.2); }
        .encryption-warning { font-size: 0.85em; padding: 0.75rem; margin-bottom:1rem; border: 1px solid var(--color-warning-light); background-color: rgba(245,158,11,0.05); color: var(--color-warning-light); border-radius: var(--border-radius-sm); }
        body.dark-mode .encryption-warning { border-color: var(--color-warning-dark); background-color: rgba(251,191,36,0.1); color: var(--color-warning-dark); }
        @media (max-width: 768px) { .navbar { flex-direction: column; align-items: flex-start; gap: 0.5rem; } .navbar .nav-buttons { margin-top: 0.5rem; margin-left: 0; width: 100%; display: flex; flex-direction: column; gap: 0.5rem; } .navbar .nav-buttons .btn { width: 100%; } .toolbar { flex-direction: column; gap: 1rem; } .search-bar { width: 100%; } .file-table { font-size: 0.85em; } .file-table th, .file-table td { padding: 0.5rem; } .file-table .actions .btn { display: block; width: calc(100% - 0.6rem); margin-bottom: 0.5rem; text-align: center; } .modal-content { width: 95%; margin: 5% auto; padding: 1rem; } .breadcrumb { font-size: 0.8em; } .edit-page-container .form-group textarea { min-height: calc(100vh - 250px); } }
        @media (max-width: 480px) { .container { padding: 15px; } .navbar .title { font-size: 1.2em; } .file-table th:nth-child(4), .file-table td:nth-child(4), .file-table th:nth-child(6), .file-table td:nth-child(6), .file-table th:nth-child(8), .file-table td:nth-child(8) { display: none; } .file-table .icon { margin-right: 0.3rem; } }
    </style>
</head>
<body class="<?php echo isset($_COOKIE['dark_mode']) && $_COOKIE['dark_mode'] === 'enabled' ? 'dark-mode' : ''; ?>">

<div class="main-wrapper">
<?php if ($config['aktifkan_login'] && !check_login()): ?>
    <div class="login-page-wrapper">
        <div class="login-box">
            <h2><?php echo htmlspecialchars($config['judul_filemanager']); ?></h2>
            <?php if ($login_error): ?> <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div> <?php endif; ?>
            <form method="POST" action="<?php echo basename(__FILE__); ?>?aksi=login_page">
                <div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" required></div>
                <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
                <button type="submit" class="btn btn-primary glitch-hover"><span class="icon">🔑</span> Login</button>
            </form>
        </div>
    </div>
<?php elseif ($aksi === 'edit' && isset($_GET['item'])):
    $item_to_edit_name = sanitize_path(basename($_GET['item']));
    $item_full_path_edit = $current_path . DIRECTORY_SEPARATOR . $item_to_edit_name;
    $content_edit = ''; $can_really_edit = false;
    if (is_file_editable($item_full_path_edit)) {
        if (is_writable($item_full_path_edit)) { $content_edit = htmlspecialchars(file_get_contents($item_full_path_edit)); $can_really_edit = true; } 
        else { if (!$action_message) $action_message = ['type' => 'danger', 'text' => "File '" . htmlspecialchars($item_to_edit_name) . "' tidak dapat ditulis. Periksa izin."]; }
    } else { if (!$action_message) $action_message = ['type' => 'danger', 'text' => "Tipe file '" . htmlspecialchars($item_to_edit_name) . "' tidak dapat diedit atau file tidak ditemukan."]; }
?>
    <div class="navbar">
        <span class="title"><span class="icon">✏️</span> Edit File: <?php echo htmlspecialchars($item_to_edit_name); ?></span>
        <div class="nav-buttons"> <a href="<?php echo basename(__FILE__); ?>?path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-secondary glitch-hover"><span class="icon">↩️</span> Kembali</a> </div>
    </div>
    <div class="container edit-page-container">
        <?php if ($action_message): ?> <div class="alert alert-<?php echo htmlspecialchars($action_message['type']); ?>"><?php echo htmlspecialchars($action_message['text']); ?></div> <?php endif; ?>
        <?php if ($can_really_edit): ?>
            <form method="POST" action="<?php echo basename(__FILE__); ?>?aksi=save_edit&path=<?php echo urlencode($relative_current_path); ?>">
                <input type="hidden" name="item" value="<?php echo htmlspecialchars($item_to_edit_name); ?>">
                <div class="form-group"> <textarea name="content" rows="25" <?php if (!is_writable($item_full_path_edit)) echo 'readonly'; ?>><?php echo $content_edit; ?></textarea> </div>
                <div class="edit-actions-bar"> <button type="submit" class="btn btn-primary glitch-hover" <?php if (!is_writable($item_full_path_edit)) echo 'disabled'; ?>><span class="icon">💾</span> Simpan Perubahan</button> </div>
            </form>
        <?php else: ?> <p>Tidak dapat memuat editor untuk file ini.</p> <?php endif; ?>
    </div>
<?php else: // Tampilan utama file manager ?>
    <div class="navbar">
        <span class="title"><?php echo htmlspecialchars($config['judul_filemanager']); ?></span>
        <div class="nav-buttons">
            <button id="toggle-dark-mode" class="btn btn-secondary glitch-hover"><span class="icon">🌓</span> Mode</button>
            <?php if ($config['aktifkan_login']): ?> <a href="?aksi=logout" class="btn btn-secondary glitch-hover"><span class="icon">🚪</span> Logout (<?php echo htmlspecialchars($_SESSION['pengguna_login']); ?>)</a> <?php endif; ?>
        </div>
    </div>
    <div class="container">
        <?php if ($action_message): ?> <div class="alert alert-<?php echo htmlspecialchars($action_message['type']); ?>"><?php echo htmlspecialchars($action_message['text']); ?></div> <?php endif; ?>
        <?php if (!empty($config_log_file_writable_warning)): ?> <div class="alert alert-warning"><?php echo $config_log_file_writable_warning; /* Already HTML, no need to escape */ ?></div> <?php endif; ?>
        <?php if (!empty($openssl_unavailable_warning)): ?> <div class="alert alert-danger"><?php echo htmlspecialchars($openssl_unavailable_warning); ?></div> <?php endif; ?>


        <nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="?path=" class="glitch-hover">🏠 Root</a></li><?php $path_parts = explode(DIRECTORY_SEPARATOR, $relative_current_path); $current_breadcrumb_path = ''; foreach ($path_parts as $part) { if (empty($part)) continue; $current_breadcrumb_path_part_only = $current_breadcrumb_path . $part; $current_breadcrumb_path .= $part . DIRECTORY_SEPARATOR; if ($current_breadcrumb_path_part_only == rtrim($relative_current_path, DIRECTORY_SEPARATOR) || $current_breadcrumb_path_part_only == $relative_current_path) { echo '<li class="breadcrumb-item active" aria-current="page">' . htmlspecialchars($part) . '</li>'; } else { echo '<li class="breadcrumb-item"><a href="?path=' . urlencode($current_breadcrumb_path_part_only) . '" class="glitch-hover">' . htmlspecialchars($part) . '</a></li>'; } } ?></ol></nav>
        <div class="current-path-info">Lokasi: <?php echo htmlspecialchars($current_path); ?></div>
        <div class="toolbar">
            <form method="GET" action="<?php echo basename(__FILE__); ?>" class="search-bar">
                <input type="hidden" name="path" value="<?php echo htmlspecialchars($relative_current_path); ?>">
                <input type="text" name="search" placeholder="Cari file atau folder..." value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                <button type="submit" class="btn btn-primary glitch-hover"><span class="icon">🔍</span> Cari</button>
                <?php if(isset($_GET['search'])): ?><a href="?path=<?php echo htmlspecialchars($relative_current_path); ?>" style="margin-left:0.5rem;" class="btn btn-secondary glitch-hover">Reset</a><?php endif; ?>
            </form>
            <div class="main-actions" style="display:flex; gap: 0.5rem; flex-wrap:wrap;">
                <button onclick="showModal('createFolderModal')" class="btn btn-success glitch-hover"><span class="icon">➕</span> Folder</button>
                <button onclick="showModal('createFileModal')" class="btn btn-success glitch-hover"><span class="icon">📄</span> File</button>
                <a href="?aksi=scan_directory&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-warning glitch-hover" onclick="return confirmAction('Pindai direktori ini untuk potensi ancaman? Ini mungkin memakan waktu.')"><span class="icon">🛡️</span> Pindai Direktori</a>
                <button onclick="showModal('systemInfoModal')" class="btn btn-info glitch-hover"><span class="icon">ℹ️</span> Info</button>
                <?php if ($config['fitur_berbahaya']['akses_pengaturan_log']): ?>
                <button onclick="showModal('loggingSettingsModal')" class="btn btn-secondary glitch-hover"><span class="icon">⚙️</span> Settings</button>
                <?php endif; ?>
                <?php if ($config['fitur_berbahaya']['terminal']): ?><button onclick="showModal('terminalModal')" class="btn btn-danger glitch-hover"><span class="icon">💀</span> Terminal</button><?php endif; ?>
            </div>
        </div>
        <div id="drop-area"><p>Seret & lepas file di sini, atau <label for="fileElem" class="btn btn-secondary btn-sm glitch-hover" style="cursor:pointer; display:inline-block; padding: 0.4rem 0.8rem;">Pilih File</label></p><input type="file" id="fileElem" multiple style="display:none;"><progress id="upload-progress" value="0" max="100" style="width:100%; display:none; margin-top:0.5rem;"></progress></div>
        <form id="upload-form" action="?aksi=upload&path=<?php echo urlencode($relative_current_path); ?>" method="post" enctype="multipart/form-data" style="display:none;"><input type="file" name="files[]" id="actual-upload-input" multiple></form>
        <form id="file-action-form" method="POST" action="?path=<?php echo urlencode($relative_current_path); ?>"><div class="actions-bar"><button type="button" onclick="selectAllFiles(true)" class="btn btn-sm btn-secondary glitch-hover">Pilih Semua</button><button type="button" onclick="selectAllFiles(false)" class="btn btn-sm btn-secondary glitch-hover">Batal Pilih</button><button type="submit" name="multi_delete_btn" value="delete_selected" formaction="?aksi=multi_delete&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-sm btn-danger glitch-hover" onclick="return confirmAction('Anda yakin ingin menghapus item terpilih?')"><span class="icon">🗑️</span> Hapus</button><button type="submit" name="items_to_zip_btn" value="zip_selected" formaction="?aksi=zip&path=<?php echo urlencode($relative_current_path); ?>" class="btn btn-sm btn-primary glitch-hover"><span class="icon">📦</span> Zip</button></div>
            <div style="overflow-x: auto;"><table class="file-table"><thead><tr><th><input type="checkbox" id="select-all-checkbox" onchange="selectAllFiles(this.checked)"></th><th class="icon-col">Ikon</th><th>Nama</th><th>Ukuran</th><th>Jenis</th><th>Modifikasi</th><th>Izin</th><th>Pemilik</th><th style="min-width: 300px;">Aksi</th></tr></thead><tbody>
                    <?php
                    $items = scandir($current_path); $search_query = isset($_GET['search']) ? strtolower($_GET['search']) : null;
                    $folders = []; $files_list = [];
                    foreach ($items as $item) {
                        if (in_array($item, $config['sembunyikan_item'])) continue;
                        if ($search_query && stripos(strtolower($item), $search_query) === false) continue;
                        $item_path = $current_path . DIRECTORY_SEPARATOR . $item; $is_dir = is_dir($item_path);
                        $is_malicious = false;
                        if (!$is_dir && $config['enable_malware_scan_on_list']) { $is_malicious = scan_for_malicious_patterns($item_path); }
                        $item_data = [ 'name' => $item, 'path' => $item_path, 'is_dir' => $is_dir, 'icon' => get_file_icon($item_path), 'size' => $is_dir ? '-' : format_size(filesize($item_path)), 'type' => $is_dir ? 'Folder' : (mime_content_type($item_path) ?: 'File'), 'modified' => date("d M Y, H:i", filemtime($item_path)), 'perms' => substr(sprintf('%o', fileperms($item_path)), -4), 'owner' => get_owner_name($item_path), 'is_writable' => is_writable($item_path), 'is_malicious' => $is_malicious ];
                        if ($is_dir) $folders[] = $item_data; else $files_list[] = $item_data;
                    }
                    usort($folders, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
                    usort($files_list, function($a, $b) { return strcasecmp($a['name'], $b['name']); });
                    $sorted_items = array_merge($folders, $files_list);
                    if (empty($sorted_items) && $search_query) { echo '<tr><td colspan="9" style="text-align:center; padding: 1rem;">Tidak ada file atau folder yang cocok.</td></tr>'; } 
                    elseif (empty($sorted_items)) { echo '<tr><td colspan="9" style="text-align:center; padding: 1rem;">Folder ini kosong.</td></tr>'; }
                    foreach ($sorted_items as $data) {
                        echo "<tr class='file-item" . ($data['is_malicious'] ? " table-danger-row" : "") . "'>";
                        echo "<td><input type='checkbox' name='items_to_zip[]' value='" . htmlspecialchars($data['name']) . "' class='file-checkbox'></td>";
                        echo "<td><span class='icon'>" . $data['icon'] . "</span></td>";
                        echo "<td style='word-break:break-all;'>";
                        if ($data['is_dir']) { echo "<a href='?path=" . urlencode($relative_current_path . DIRECTORY_SEPARATOR . $data['name']) . "' class='glitch-hover'>" . htmlspecialchars($data['name']) . "</a>"; } 
                        else { echo htmlspecialchars($data['name']); }
                        if ($data['is_malicious']) { echo " <span class='malware-warning-icon' title='Peringatan: Potensi kode berbahaya terdeteksi di file ini! Periksa secara manual.'>⚠️</span>"; }
                        echo "</td>";
                        echo "<td>" . $data['size'] . "</td><td>" . htmlspecialchars($data['type']) . "</td><td>" . $data['modified'] . "</td><td>" . $data['perms'] . "</td><td>" . htmlspecialchars($data['owner']) . "</td>";
                        echo "<td class='actions'>";
                        echo "<button type='button' onclick=\"showRenameModal('" . htmlspecialchars($data['name']) . "')\" class='btn btn-sm btn-warning glitch-hover' title='Rename'><span class='icon'>🏷️</span></button>";
                        echo "<a href='?aksi=delete&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-danger glitch-hover' onclick=\"return confirmAction('Hapus " . htmlspecialchars($data['name']) . "?')\" title='Hapus'><span class='icon'>🗑️</span></a>";
                        if (!$data['is_dir']) {
                            echo "<a href='?aksi=preview&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' target='_blank' class='btn btn-sm btn-info glitch-hover' title='Preview/Unduh'><span class='icon'>👁️</span></a>";
                            if (is_file_editable($data['path']) && $data['is_writable']) { echo "<a href='?aksi=edit&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-success glitch-hover' title='Edit'><span class='icon'>✏️</span></a>"; }
                        }
                        if (strtolower(pathinfo($data['name'], PATHINFO_EXTENSION)) === 'zip' && !$data['is_dir']) { echo "<a href='?aksi=unzip&path=" . urlencode($relative_current_path) . "&item=" . urlencode($data['name']) . "' class='btn btn-sm btn-primary glitch-hover' onclick=\"return confirmAction('Unzip " . htmlspecialchars($data['name']) . "?')\" title='Unzip'><span class='icon'>📦</span></a>"; }
                        echo "<button type='button' onclick=\"showChmodModal('" . htmlspecialchars($data['name']) . "', '" . $data['perms'] . "')\" class='btn btn-sm btn-secondary glitch-hover' title='Chmod'><span class='icon'>🔑</span></button>";
                        echo "<button type='button' onclick=\"showEditTimeModal('" . htmlspecialchars($data['name']) . "', '" . date("Y-m-d\TH:i:s", filemtime($data['path'])) . "')\" class='btn btn-sm btn-secondary glitch-hover' title='Edit Waktu'><span class='icon'>⏱️</span></button>";
                        echo "</td></tr>";
                    }
                    ?>
            </tbody></table></div>
            <div class="security-note"> <strong>Catatan Keamanan:</strong> Fitur deteksi potensi kode berbahaya (shell/backdoor) bersifat dasar dan hanya berdasarkan pencocokan pola string sederhana. Ini BUKAN solusi keamanan yang komprehensif dan mungkin tidak mendeteksi semua ancaman atau dapat salah mendeteksi file yang aman. Selalu lakukan pemeriksaan manual dan gunakan alat keamanan server yang lebih canggih. </div>
            </form>
    </div> <!-- End container -->
    
    <!-- Modals -->
    <div id="createFolderModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('createFolderModal')">&times;</span><div class="modal-header"><h4><span class="icon">➕</span> Folder Baru</h4></div><form method="POST" action="?aksi=create_folder&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><div class="form-group"><label for="folder_name_modal">Nama Folder:</label><input type="text" id="folder_name_modal" name="folder_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('createFolderModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Buat</button></div></form></div></div>
    <div id="createFileModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('createFileModal')">&times;</span><div class="modal-header"><h4><span class="icon">📄</span> File Baru</h4></div><form method="POST" action="?aksi=create_file&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><div class="form-group"><label for="file_name_modal">Nama File (mis: data.txt):</label><input type="text" id="file_name_modal" name="file_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('createFileModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Buat</button></div></form></div></div>
    <div id="renameModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('renameModal')">&times;</span><div class="modal-header"><h4><span class="icon">🏷️</span> Rename Item</h4></div><form method="POST" action="?aksi=rename&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="old_name_rename" name="old_name"><div class="form-group"><label for="new_name_rename">Nama Baru:</label><input type="text" id="new_name_rename" name="new_name" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('renameModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Rename</button></div></form></div></div>
    <div id="chmodModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('chmodModal')">&times;</span><div class="modal-header"><h4><span class="icon">🔑</span> Ubah Izin (Chmod)</h4></div><form method="POST" action="?aksi=chmod&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="item_chmod" name="item"><p>Item: <strong id="chmod_item_name_display"></strong></p><div class="form-group"><label for="permissions_chmod">Izin Baru (mis: 0755):</label><input type="text" id="permissions_chmod" name="permissions" pattern="0[0-7]{3}" title="Format octal 4 digit, mis: 0755" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('chmodModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover" <?php if(!$config['fitur_berbahaya']['edit_chmod_luas']) echo 'disabled title="Fitur dinonaktifkan"'; ?>><span class="icon">✔️</span> Ubah</button></div></form></div></div>
    <div id="editTimeModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('editTimeModal')">&times;</span><div class="modal-header"><h4><span class="icon">⏱️</span> Ubah Waktu Modifikasi</h4></div><form method="POST" action="?aksi=edit_time&path=<?php echo urlencode($relative_current_path); ?>"><div class="modal-body"><input type="hidden" id="item_edit_time" name="item"><p>Item: <strong id="edit_time_item_name_display"></strong></p><div class="form-group"><label for="datetime_edit_time">Waktu Baru:</label><input type="datetime-local" id="datetime_edit_time" name="datetime" required></div></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('editTimeModal')">Batal</button><button type="submit" class="btn btn-primary glitch-hover"><span class="icon">✔️</span> Ubah</button></div></form></div></div>
    <div id="systemInfoModal" class="modal"><div class="modal-content"><span class="close-btn" onclick="closeModal('systemInfoModal')">&times;</span><div class="modal-header"><h4><span class="icon">ℹ️</span> Informasi Sistem</h4></div><div class="modal-body" style="font-size:0.9em; line-height:1.8;"><p><strong>OS:</strong> <?php echo php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'); ?></p><p><strong>PHP:</strong> <?php echo phpversion(); ?></p><p><strong>Server:</strong> <?php echo $_SERVER['SERVER_SOFTWARE']; ?></p><p><strong>Disk Total:</strong> <?php echo format_size(disk_total_space($config['direktori_dasar'])); ?></p><p><strong>Disk Tersedia:</strong> <?php echo format_size(disk_free_space($config['direktori_dasar'])); ?></p><p><strong>Zona Waktu:</strong> <?php echo date_default_timezone_get(); ?></p><p><strong>Max Upload:</strong> <?php echo ini_get('upload_max_filesize'); ?></p><p><strong>Max Post:</strong> <?php echo ini_get('post_max_size'); ?></p></div><div class="modal-footer"><button type="button" class="btn btn-primary" onclick="closeModal('systemInfoModal')">Tutup</button></div></div></div>
    
    <div id="loggingSettingsModal" class="modal" <?php if(isset($_GET['show_logging_settings'])) echo 'style="display:flex;"'; ?>>
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('loggingSettingsModal')">&times;</span>
            <div class="modal-header"><h4><span class="icon">⚙️</span> Settings</h4></div>
            <div class="modal-body">
                <div class="encryption-warning">
                    <strong>PENTING:</strong> Passphrase enkripsi saat ini adalah: "<code><?php echo htmlspecialchars(LOG_CONFIG_ENCRYPTION_PASSPHRASE); ?></code>".
                    <br><strong>Segera ganti passphrase ini</strong> di dalam kode PHP (konstanta <code>LOG_CONFIG_ENCRYPTION_PASSPHRASE</code>) dengan passphrase yang kuat dan unik.
                    <br>Jika passphrase diubah, file <code>config_log.json</code> yang ada mungkin perlu dihapus agar dapat dibuat ulang dengan enkripsi baru.
                    <?php if (!empty($openssl_unavailable_warning)): ?> <br><strong style="color:var(--color-danger-light);"><?php echo htmlspecialchars($openssl_unavailable_warning); ?></strong> <?php endif; ?>
                </div>

                <h5>Status Logging Sesi Ini:</h5>
                <p style="font-size: 0.85em; margin-bottom: 1rem;">Pengaturan ini hanya berlaku untuk sesi Anda saat ini dan akan kembali ke default jika Anda logout atau menutup browser.</p>
                <?php
                $services_to_toggle = ['discord', 'telegram', 'email'];
                foreach ($services_to_toggle as $service_name) {
                    $is_active = is_service_logging_active($service_name);
                    $button_text = $is_active ? "Nonaktifkan" : "Aktifkan";
                    $button_class = $is_active ? "btn-danger" : "btn-success";
                    $service_label = ucfirst($service_name);
                    $config_default_status_text = ($config['logging'][$service_name]['enabled'] ?? false) ? "Aktif" : "Nonaktif";
                    $status_display = "Default: {$config_default_status_text}";
                    if (isset($_SESSION['logging_override_' . $service_name . '_enabled'])) {
                         $status_display .= " (Sesi: " . ($is_active ? "Aktif" : "Nonaktif") . ")";
                    }

                    echo "<div class='logging-toggle-item'>";
                    echo "<span>Log ke {$service_label} <small style='color:var(--color-secondary-light);'>{$status_display}</small></span>";
                    echo "<a href='?aksi=toggle_logging_service&service={$service_name}&path=" . urlencode($relative_current_path) . "' class='btn btn-sm {$button_class} glitch-hover'>{$button_text}</a>";
                    echo "</div>";
                }
                ?>
                <hr>
                <h5>Konfigurasi Kredensial Logging (Disimpan Terenkripsi ke File):</h5>
                <p style="font-size: 0.85em; margin-bottom: 1rem;">Perubahan di sini akan disimpan secara permanen (terenkripsi) ke file <code>config_log.json</code> dan berlaku untuk semua sesi.</p>
                <?php if (!empty($config_log_file_writable_warning) && strpos($config_log_file_writable_warning, "Info:") !== 0): /* Jangan tampilkan info sebagai error */ ?> <div class="alert alert-warning" style="font-size:0.85em;"><?php echo htmlspecialchars($config_log_file_writable_warning); ?></div> <?php endif; ?>
                <form method="POST" action="?aksi=save_logging_config&path=<?php echo urlencode($relative_current_path); ?>">
                    <div class="form-group">
                        <label for="log_discord_webhook_url">Discord Webhook URL:</label>
                        <input type="url" class="form-control" id="log_discord_webhook_url" name="discord_webhook_url" value="<?php echo htmlspecialchars($config['logging']['discord']['webhook_url'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_discord_username">Discord Username Bot:</label>
                        <input type="text" class="form-control" id="log_discord_username" name="discord_username" value="<?php echo htmlspecialchars($config['logging']['discord']['username'] ?? 'FileManager Bot'); ?>">
                    </div>
                    <hr style="margin: 1rem 0;">
                    <div class="form-group">
                        <label for="log_telegram_bot_token">Telegram Bot Token:</label>
                        <input type="text" class="form-control" id="log_telegram_bot_token" name="telegram_bot_token" value="<?php echo htmlspecialchars($config['logging']['telegram']['bot_token'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_telegram_chat_id">Telegram Chat ID:</label>
                        <input type="text" class="form-control" id="log_telegram_chat_id" name="telegram_chat_id" value="<?php echo htmlspecialchars($config['logging']['telegram']['chat_id'] ?? ''); ?>">
                    </div>
                     <hr style="margin: 1rem 0;">
                    <div class="form-group">
                        <label for="log_email_to_address">Email Penerima Log:</label>
                        <input type="email" class="form-control" id="log_email_to_address" name="email_to_address" value="<?php echo htmlspecialchars($config['logging']['email']['to_address'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="log_email_from_address">Email Pengirim Log:</label>
                        <input type="email" class="form-control" id="log_email_from_address" name="email_from_address" value="<?php echo htmlspecialchars($config['logging']['email']['from_address'] ?? 'noreply@yourdomain.com'); ?>">
                    </div>
                     <div class="form-group">
                        <label for="log_email_subject_prefix">Prefix Subjek Email Log:</label>
                        <input type="text" class="form-control" id="log_email_subject_prefix" name="email_subject_prefix" value="<?php echo htmlspecialchars($config['logging']['email']['subject_prefix'] ?? '[FileMan Log]'); ?>">
                    </div>
                    <button type="submit" class="btn btn-primary glitch-hover" <?php if(!empty($config_log_file_writable_warning) && strpos($config_log_file_writable_warning, "Error:") === 0) echo 'disabled title="File konfigurasi tidak dapat ditulis"'; ?>><span class="icon">💾</span> Simpan Konfigurasi Logging</button>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeModal('loggingSettingsModal')">Tutup</button>
            </div>
        </div>
    </div>

    <?php if ($config['fitur_berbahaya']['terminal']): ?>
    <div id="terminalModal" class="modal" <?php if(isset($_GET['show_terminal'])) echo 'style="display:flex;"'; ?>><div class="modal-content" style="width: 90%; max-width: 800px;"><span class="close-btn" onclick="closeModal('terminalModal')">&times;</span><div class="modal-header"><h4><span class="icon">💀</span> Terminal (RISIKO TINGGI!)</h4></div><div class="modal-body"><p style="color:var(--color-danger-light); font-weight:bold;">PERINGATAN: Penggunaan terminal web sangat berbahaya. Hanya jalankan perintah yang Anda pahami sepenuhnya.</p><body:dark-mode><p style="color:var(--color-danger-dark); font-weight:bold;">PERINGATAN: Penggunaan terminal web sangat berbahaya. Hanya jalankan perintah yang Anda pahami sepenuhnya.</p></body:dark-mode><div id="terminal-output"><?php if (isset($_SESSION['terminal_output'])) { echo htmlspecialchars($_SESSION['terminal_output']); unset($_SESSION['terminal_output']); } else { echo "Selamat datang di terminal.\n"; }?></div><form method="POST" action="?aksi=terminal_exec&path=<?php echo urlencode($relative_current_path); ?>" id="terminal-form"><div class="input-group"><span class="input-group-prepend"><?php echo htmlspecialchars(basename($current_path)); ?> $</span><input type="text" id="terminal_command" name="command" autofocus value="<?php echo isset($_SESSION['last_command']) ? htmlspecialchars($_SESSION['last_command']) : ''; unset($_SESSION['last_command']); ?>"><button type="submit" class="btn btn-primary glitch-hover">Jalankan</button></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" onclick="closeModal('terminalModal')">Tutup</button></div></div></div>
    <?php endif; ?>
    <div class="footer"><p>&copy; <?php echo date("Y"); ?> <?php echo htmlspecialchars($config['judul_filemanager']); ?>. Dibuat dengan ❤️.</p></div>
<?php endif; ?>
</div>
<button id="scrollTopBtn" title="Kembali ke atas">⬆️</button>
<script>
    const toggleDarkModeButton = document.getElementById('toggle-dark-mode');
    const body = document.body;
    if (toggleDarkModeButton) { toggleDarkModeButton.addEventListener('click', () => { body.classList.toggle('dark-mode'); const isDarkMode = body.classList.contains('dark-mode'); document.cookie = "dark_mode=" + (isDarkMode ? "enabled" : "disabled") + ";path=/;max-age=" + (60*60*24*365) + ";samesite=lax"; }); }
    function showModal(modalId) { const modal = document.getElementById(modalId); if(modal) modal.style.display = "flex"; if(modalId === 'terminalModal') { const cmdInput = document.getElementById('terminal_command'); if(cmdInput) { cmdInput.focus(); cmdInput.selectionStart = cmdInput.selectionEnd = cmdInput.value.length; } } else if (modalId === 'createFolderModal') { const folderNameInput = document.getElementById('folder_name_modal'); if(folderNameInput) folderNameInput.focus(); } else if (modalId === 'createFileModal') { const fileNameInput = document.getElementById('file_name_modal'); if(fileNameInput) fileNameInput.focus(); } else if (modalId === 'renameModal') { const newNameInput = document.getElementById('new_name_rename'); if(newNameInput) { newNameInput.focus(); newNameInput.select(); }} else if (modalId === 'chmodModal') { const permsInput = document.getElementById('permissions_chmod'); if(permsInput) permsInput.focus(); } else if (modalId === 'editTimeModal') { const dtInput = document.getElementById('datetime_edit_time'); if(dtInput) dtInput.focus(); }}
    function closeModal(modalId) { const modal = document.getElementById(modalId); if(modal) modal.style.display = "none"; }
    document.querySelectorAll('.modal').forEach(modal => { modal.addEventListener('click', function(event) { if (event.target === this) { closeModal(this.id); } }); });
    document.addEventListener('keydown', function(event) { if (event.key === "Escape") { document.querySelectorAll('.modal').forEach(modal => closeModal(modal.id)); } });
    function showRenameModal(oldName) { document.getElementById('old_name_rename').value = oldName; document.getElementById('new_name_rename').value = oldName; showModal('renameModal'); }
    function showChmodModal(itemName, currentPerms) { document.getElementById('item_chmod').value = itemName; document.getElementById('chmod_item_name_display').textContent = itemName; document.getElementById('permissions_chmod').value = currentPerms; showModal('chmodModal'); }
    function showEditTimeModal(itemName, currentDatetime) { document.getElementById('item_edit_time').value = itemName; document.getElementById('edit_time_item_name_display').textContent = itemName; document.getElementById('datetime_edit_time').value = currentDatetime; showModal('editTimeModal'); }
    function confirmAction(message) { return confirm(message); }
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    function selectAllFiles(checked) { fileCheckboxes.forEach(checkbox => checkbox.checked = checked); if(selectAllCheckbox) selectAllCheckbox.checked = checked; }
    if(selectAllCheckbox){ selectAllCheckbox.addEventListener('change', (event) => selectAllFiles(event.target.checked)); }
    fileCheckboxes.forEach(checkbox => { checkbox.addEventListener('change', () => { if(selectAllCheckbox){ let allChecked = true; fileCheckboxes.forEach(cb => { if(!cb.checked) allChecked = false; }); selectAllCheckbox.checked = allChecked; } }); });
    let dropArea = document.getElementById('drop-area'); let fileInputForDrop = document.getElementById('fileElem'); let actualUploadInput = document.getElementById('actual-upload-input'); let uploadForm = document.getElementById('upload-form'); let progressBar = document.getElementById('upload-progress');
    if (dropArea && fileInputForDrop && actualUploadInput && uploadForm) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => { dropArea.addEventListener(eventName, preventDefaults, false); document.body.addEventListener(eventName, preventDefaults, false); });
        function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
        ['dragenter', 'dragover'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false));
        ['dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false));
        dropArea.addEventListener('drop', function(e) { handleFiles(e.dataTransfer.files); }, false); 
        fileInputForDrop.addEventListener('click', (e) => { e.preventDefault(); actualUploadInput.click(); });
        actualUploadInput.addEventListener('change', function() { handleFiles(this.files); });
        function handleFiles(files) { if (files.length === 0) return; let formData = new FormData(); for (let i = 0; i < files.length; i++) { formData.append('files[]', files[i]); } let xhr = new XMLHttpRequest(); xhr.open('POST', uploadForm.action, true); if(progressBar) { progressBar.style.display = 'block'; progressBar.value = 0; } xhr.upload.onprogress = function(event) { if (event.lengthComputable && progressBar) { let percentComplete = (event.loaded / event.total) * 100; progressBar.value = percentComplete; } }; xhr.onload = function() { if(progressBar) progressBar.style.display = 'none'; if (xhr.status >= 200 && xhr.status < 400) { window.location.href = xhr.responseURL; } else { alert('Upload gagal. Status: ' + xhr.status + "\n" + xhr.responseText); } }; xhr.onerror = function() { if(progressBar) progressBar.style.display = 'none'; alert('Terjadi kesalahan saat mengunggah file.'); }; xhr.send(formData); }
    }
    const terminalOutputDiv = document.getElementById('terminal-output'); const terminalCommandInput = document.getElementById('terminal_command'); if (terminalOutputDiv) { terminalOutputDiv.scrollTop = terminalOutputDiv.scrollHeight; }
    const terminalForm = document.getElementById('terminal-form'); if(terminalForm && terminalCommandInput){ terminalCommandInput.addEventListener('keypress', function(e){ if(e.key === 'Enter'){ e.preventDefault(); terminalForm.submit(); } }); }
    let scrollTopBtn = document.getElementById("scrollTopBtn"); window.onscroll = function() {scrollFunction()}; function scrollFunction() { if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) { scrollTopBtn.classList.add("show"); } else { scrollTopBtn.classList.remove("show"); } } scrollTopBtn.addEventListener("click", function() { document.body.scrollTop = 0; document.documentElement.scrollTop = 0; });
    document.querySelectorAll('.modal').forEach(modalEl => {
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.attributeName === 'style' && modalEl.style.display === 'flex') {
                    const firstFocusable = modalEl.querySelector('input[type="text"], input[type="password"], input[type="datetime-local"], input[type="url"], input[type="email"], textarea, button:not([disabled])');
                    if (firstFocusable && (modalEl.id === 'createFolderModal' || modalEl.id === 'createFileModal' || modalEl.id === 'renameModal' || modalEl.id === 'chmodModal' || modalEl.id === 'editTimeModal' || modalEl.id === 'terminalModal' )) { // Removed loggingSettingsModal from auto-focusing form fields
                        if (modalEl.id === 'renameModal') document.getElementById('new_name_rename')?.select();
                        else firstFocusable.focus();
                    }
                }
            });
        });
        observer.observe(modalEl, { attributes: true });
    });
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('show_logging_settings')) {
        showModal('loggingSettingsModal');
    }
</script>
</body>
</html>