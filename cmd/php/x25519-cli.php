<?php
// x25519_cli.php - X25519 CLI Tool (edgetk-style parsing)
// Usage: php x25519_cli.php [command] [options]

require_once('x25519.php');

// ====================================================================
// CLI HELPER FUNCTIONS (EDGETK STYLE)
// ====================================================================

function show_help() {
    echo "X25519 CLI TOOL - ELLIPTIC CURVE DIFFIE-HELLMAN (CURVE25519)\n";
    echo "============================================================\n\n";
    echo "Usage: php x25519-cli.php [command] [options]\n\n";
    echo "COMMANDS:\n";
    echo "  help                - Show this help\n";
    echo "  version             - Show version\n";
    echo "\n  generate            - Generate new key pair\n";
    echo "    --out=DIR         - Output directory (default: ./)\n";
    echo "    --name=NAME       - Base name for key files\n";
    echo "    --password        - Encrypt private key with password (optional)\n";
    echo "\n  publickey           - Derive public key from private key\n";
    echo "    --priv=FILE       - Private key file (required)\n";
    echo "    --password        - Password for encrypted private key (if needed)\n";
    echo "\n  sharedsecret        - Calculate shared secret\n";
    echo "    --priv=FILE       - Your private key file\n";
    echo "    --peer=FILE       - Peer public key file\n";
    echo "    --password        - Password for encrypted private key (if needed)\n";
    echo "    --out=FILE        - Output shared secret file\n";
    echo "\n  parse               - Parse and display key information (edgetk style)\n";
    echo "    --key=FILE        - Key file to parse\n";
    echo "    --password        - Password for encrypted private key (if needed)\n";
    echo "\nEXAMPLES:\n";
    echo "  php x25519_cli.php generate --name=alice --password\n";
    echo "  php x25519_cli.php publickey --priv=alice_private.pem\n";
    echo "  php x25519_cli.php sharedsecret --priv=alice_private.pem --peer=bob_public.pem\n";
    echo "  php x25519_cli.php parse --key=alice_public.pem\n";
}

function show_version() {
    echo "X25519 CLI Tool v2.0\n";
    echo "X25519 (Curve25519) Diffie-Hellman Key Exchange\n";
    echo "RFC 7748 - Elliptic Curves for Security\n";
    echo "Algorithm by Daniel J. Bernstein\n";
    echo "With Curupira-192-CBC encryption support\n";
}

// ====================================================================
// DER ENCODING FUNCTIONS
// ====================================================================

function der_encode_length($length) {
    if ($length < 128) {
        return chr($length);
    } else {
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}

function der_encode_integer($int) {
    $hex = gmp_strval(gmp_init($int, 10), 16);
    if (strlen($hex) % 2 == 1) {
        $hex = '0' . $hex;
    }
    $bytes = hex2bin($hex);
    
    // Ensure positive integer
    if (ord($bytes[0]) & 0x80) {
        $bytes = "\x00" . $bytes;
    }
    
    return "\x02" . der_encode_length(strlen($bytes)) . $bytes;
}

function der_encode_octet_string($data) {
    return "\x04" . der_encode_length(strlen($data)) . $data;
}

function der_encode_sequence($data) {
    return "\x30" . der_encode_length(strlen($data)) . $data;
}

function der_encode_oid($oid) {
    // OID 1.3.101.110
    $parts = explode('.', $oid);
    $first = $parts[0] * 40 + $parts[1];
    $encoded = chr($first);
    
    for ($i = 2; $i < count($parts); $i++) {
        $value = intval($parts[$i]);
        if ($value < 128) {
            $encoded .= chr($value);
        } else {
            $bytes = '';
            while ($value > 0) {
                $bytes = chr(($value & 0x7F) | 0x80) . $bytes;
                $value >>= 7;
            }
            $bytes[strlen($bytes)-1] = chr(ord($bytes[strlen($bytes)-1]) & 0x7F);
            $encoded .= $bytes;
        }
    }
    
    return "\x06" . der_encode_length(strlen($encoded)) . $encoded;
}

function der_encode_bit_string($data, $unused_bits = 0) {
    return "\x03" . der_encode_length(strlen($data) + 1) . chr($unused_bits) . $data;
}

// ====================================================================
// PASSWORD HANDLING FUNCTIONS
// ====================================================================

/**
 * Get password from user input
 */
function get_password($prompt = "Enter password: ", $confirm = false) {
    if (defined('STDIN')) {
        echo $prompt;
        system('stty -echo');
        $password = trim(fgets(STDIN));
        system('stty echo');
        echo "\n";
        
        if ($confirm) {
            echo "Confirm password: ";
            system('stty -echo');
            $confirm_password = trim(fgets(STDIN));
            system('stty echo');
            echo "\n";
            
            if ($password !== $confirm_password) {
                throw new Exception("Passwords do not match");
            }
        }
        
        return $password;
    } else {
        // Fallback para ambiente não-CLI
        return readline($prompt);
    }
}

/**
 * Parse password from arguments or prompt (MODIFIED: --password is now boolean)
 */
function parse_password_arg($args, $key_file = null) {
    $password = null;
    $has_password_arg = false;
    
    // Verificar se o argumento --password está presente (now boolean)
    foreach ($args as $arg) {
        if ($arg === '--password') {
            $has_password_arg = true;
            break;
        }
    }
    
    // Se a chave está criptografada e não tem senha, perguntar
    if ($key_file && !$has_password_arg && file_exists($key_file)) {
        $pem_data = file_get_contents($key_file);
        if (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false) {
            $password = get_password("Enter password to decrypt private key: ");
        }
    }
    
    return $password;
}

// ====================================================================
// PKCS#8 FUNCTIONS FOR X25519
// ====================================================================

function x25519_private_to_pkcs8($private_key_hex, $password = null) {
    $private_key_bin = hex2bin($private_key_hex);
    
    // RFC 8410 Section 7: Private keys for X25519 are simply 32-byte octet strings
    // The private key is encoded as an OCTET STRING containing another OCTET STRING
    
    // Inner OCTET STRING with the 32-byte private key
    $inner_octet_string = der_encode_octet_string($private_key_bin);
    
    // AlgorithmIdentifier for X25519 (1.3.101.110)
    // Note: RFC 8410 says parameters should be ABSENT, not NULL
    $algorithm_identifier = der_encode_sequence(
        der_encode_oid("1.3.101.110")
    );
    
    // PrivateKey is the inner OCTET STRING
    $private_key = der_encode_octet_string($inner_octet_string);
    
    // Version INTEGER 0
    $version = der_encode_integer("0");
    
    // PrivateKeyInfo SEQUENCE
    $private_key_info = $version . $algorithm_identifier . $private_key;
    $der = der_encode_sequence($private_key_info);
    
    if ($password) {
        // Encrypt using RFC 1423 with Curupira-192-CBC
        $encrypted_pem = X25519_PEM::private_to_pem_pkcs8($private_key_hex, $password);
        return $encrypted_pem;
    } else {
        return "-----BEGIN PRIVATE KEY-----\n" . 
               chunk_split(base64_encode($der), 64) . 
               "-----END PRIVATE KEY-----\n";
    }
}

function x25519_public_to_pkcs8($public_key_hex) {
    $public_key_bin = hex2bin($public_key_hex);
    
    // AlgorithmIdentifier for X25519 (1.3.101.110) - parameters ABSENT
    $algorithm_identifier = der_encode_sequence(
        der_encode_oid("1.3.101.110")
    );
    
    // SubjectPublicKey as BIT STRING
    $subject_public_key = der_encode_bit_string($public_key_bin);
    
    // SubjectPublicKeyInfo SEQUENCE
    $subject_public_key_info = $algorithm_identifier . $subject_public_key;
    
    $der = der_encode_sequence($subject_public_key_info);
    
    return "-----BEGIN PUBLIC KEY-----\n" . 
           chunk_split(base64_encode($der), 64) . 
           "-----END PUBLIC KEY-----\n";
}

function parse_x25519_pkcs8_private($pem_data, $password = null) {
    return X25519_PEM::parse_private_pem_pkcs8($pem_data, $password);
}

function parse_x25519_pkcs8_public($pem_data) {
    $lines = explode("\n", trim($pem_data));
    $b64 = '';
    
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line && !str_starts_with($line, '-----')) {
            $b64 .= $line;
        }
    }
    
    $der = base64_decode($b64);
    if ($der === false) {
        throw new Exception("Invalid base64 data");
    }
    
    // Parse DER
    $pos = 0;
    
    // SEQUENCE
    if (ord($der[$pos]) !== 0x30) {
        throw new Exception("Not a SEQUENCE");
    }
    $pos++;
    
    // Skip length
    $len = ord($der[$pos]);
    $pos++;
    if ($len & 0x80) {
        $len_bytes = $len & 0x7F;
        $len = 0;
        for ($i = 0; $i < $len_bytes; $i++) {
            $len = ($len << 8) | ord($der[$pos]);
            $pos++;
        }
    }
    
    // Skip AlgorithmIdentifier
    if (ord($der[$pos]) !== 0x30) {
        throw new Exception("Expected AlgorithmIdentifier SEQUENCE");
    }
    $pos++;
    $len = ord($der[$pos]);
    $pos++;
    if ($len & 0x80) {
        $len_bytes = $len & 0x7F;
        for ($i = 0; $i < $len_bytes; $i++) {
            $pos++;
        }
    }
    $pos += $len;
    
    // BIT STRING with public key
    if (ord($der[$pos]) !== 0x03) {
        throw new Exception("Expected BIT STRING");
    }
    $pos++;
    
    $len = ord($der[$pos]);
    $pos++;
    if ($len & 0x80) {
        $len_bytes = $len & 0x7F;
        $len = 0;
        for ($i = 0; $i < $len_bytes; $i++) {
            $len = ($len << 8) | ord($der[$pos]);
            $pos++;
        }
    }
    
    // Skip unused bits
    $pos++;
    
    $public_key_bin = substr($der, $pos, $len - 1);
    
    if (strlen($public_key_bin) !== 32) {
        throw new Exception("Invalid public key length: " . strlen($public_key_bin));
    }
    
    return bin2hex($public_key_bin);
}

// ====================================================================
// EDGETK-STYLE PARSING FUNCTIONS
// ====================================================================

function edgetk_style_parse_key($key_hex, $is_private = false) {
    try {
        if (strlen($key_hex) != 64 || !ctype_xdigit($key_hex)) {
            echo "ERROR: Invalid key hex (expected 64 hex characters)\n";
            return 1;
        }
        
        $bytes = hex2bin($key_hex);
        if ($bytes === false) {
            echo "ERROR: Invalid hex string\n";
            return 1;
        }
        
        // EDGETK-STYLE OUTPUT
        if ($is_private) {
            echo "X25519 Private-Key: (256 bit)\n";
            echo "priv:\n";
        } else {
            echo "X25519 Public-Key: (256 bit)\n";
            echo "pub:\n";
        }
        
        // Format like edgetk: 32 bytes = 64 hex chars, break every 30 hex chars (15 bytes)
        $hex_str = $key_hex;
        for ($i = 0; $i < strlen($hex_str); $i += 30) {
            $line_hex = substr($hex_str, $i, 30);
            // Format as colon-separated pairs
            $formatted = implode(':', str_split($line_hex, 2));
            echo "    " . $formatted . "\n";
        }
        
        if ($is_private) {
            // Check clamping for private keys
            $byte0 = ord($bytes[0]);
            $byte31 = ord($bytes[31]);
            $bits0_2_cleared = ($byte0 & 0x07) == 0;
            $bit254_set = ($byte31 & 0x40) != 0;
            $bit255_cleared = ($byte31 & 0x80) == 0;
            
            echo "Clamping check:\n";
            echo sprintf(
                "  Byte 0: 0x%02x (bits 0-2 cleared: %s)\n  Byte 31: 0x%02x (bit 254 set: %s, bit 255 cleared: %s)\n",
                $byte0, $bits0_2_cleared ? 'yes' : 'no',
                $byte31, $bit254_set ? 'yes' : 'no', $bit255_cleared ? 'yes' : 'no'
            );
            
            if ($bits0_2_cleared && $bit254_set && $bit255_cleared) {
                echo "  ✓ Key is properly clamped\n";
            } else {
                echo "  ⚠ Key is NOT properly clamped for X25519\n";
            }
        }
        
        echo "ASN1 OID: 1.3.101.110\n";
        echo "Curve: Curve25519 (X25519)\n";
        
        if ($is_private) {
            // Calculate and show public key
            echo "\nCalculating public key...\n";
            try {
                $public_key = X25519::x25519_get_public_key($key_hex);
                
                echo "Public-Key: (256 bit)\n";
                echo "pub:\n";
                
                $hex_str = $public_key;
                for ($i = 0; $i < strlen($hex_str); $i += 30) {
                    $line_hex = substr($hex_str, $i, 30);
                    $formatted = implode(':', str_split($line_hex, 2));
                    echo "    " . $formatted . "\n";
                }
                
                // Calculate fingerprint
                $fingerprint = hash('sha256', hex2bin($public_key));
                echo "\nFingerprint:\n";
                echo "  SHA256: " . $fingerprint . "\n";
                echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
                
            } catch (Exception $e) {
                echo "Note: Could not calculate public key: " . $e->getMessage() . "\n";
            }
        } else {
            // Calculate fingerprint for public key
            $fingerprint = hash('sha256', hex2bin($key_hex));
            echo "\nFingerprint:\n";
            echo "  SHA256: " . $fingerprint . "\n";
            echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
        }
        
        echo "\n✓ Key parsed successfully\n";
        
        return 0; // Success
        
    } catch (Exception $e) {
        echo "✖ Error: " . $e->getMessage() . "\n";
        return 1;
    }
}

function edgetk_style_parse_pem($key_file, $password = null) {
    try {
        $pem_data = file_get_contents($key_file);
        if ($pem_data === false) {
            echo "ERROR: Cannot read key file: $key_file\n";
            return 1;
        }
        
        // Check if encrypted
        $is_encrypted = false;
        $lines = explode("\n", $pem_data);
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        // Se estiver criptografada e não tem senha, pedir senha
        if ($is_encrypted && !$password) {
            $password = get_password("Enter password to decrypt private key: ");
        }
        
        // Show PEM header
        foreach ($lines as $line) {
            if (str_starts_with($line, '-----')) {
                echo $line . "\n";
                break;
            }
        }
        
        // Determine key type and parse
        $is_private = (strpos($pem_data, "PRIVATE KEY") !== false);
        $is_public = (strpos($pem_data, "PUBLIC KEY") !== false);
        
        if (!$is_private && !$is_public) {
            echo "ERROR: Unknown key format\n";
            return 1;
        }
        
        // Parse PKCS#8
        if ($is_private) {
            $key_hex = parse_x25519_pkcs8_private($pem_data, $password);
        } else {
            $key_hex = parse_x25519_pkcs8_public($pem_data);
        }
        
        // Show PEM body
        $in_body = false;
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if (strpos($trimmed, '-----BEGIN') === 0) {
                $in_body = true;
                continue;
            } elseif (strpos($trimmed, '-----END') === 0) {
                $in_body = false;
                continue;
            }
            
            if ($in_body && $trimmed !== '') {
                echo $line . "\n";
            }
        }
        
        // Show footer
        foreach ($lines as $line) {
            if (str_starts_with($line, '-----END')) {
                echo $line . "\n";
                break;
            }
        }
        
        // Show encryption info if applicable
        if ($is_encrypted) {
            echo "\nEncryption: CURUPIRA-192-CBC\n";
            if ($password) {
                echo "Status: ✓ Decrypted successfully\n";
            } else {
                echo "Status: ✗ Not decrypted (no password provided)\n";
            }
        }
        
        // Parse the key hex
        return edgetk_style_parse_key($key_hex, $is_private);
        
    } catch (Exception $e) {
        echo "✖ Error parsing PEM: " . $e->getMessage() . "\n";
        if (strpos($e->getMessage(), "Decryption failed") !== false) {
            echo "Hint: Wrong password or key is encrypted\n";
        }
        return 1;
    }
}

// ====================================================================
// MAIN COMMAND FUNCTIONS
// ====================================================================

function cmd_generate($args) {
    $output_dir = './';
    $name = 'x25519';
    $password = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--out=') === 0) {
            $output_dir = substr($arg, 6);
            if (!is_dir($output_dir)) {
                mkdir($output_dir, 0755, true);
            }
        } elseif (strpos($arg, '--name=') === 0) {
            $name = substr($arg, 7);
        } elseif ($arg === '--password') {
            // MODIFIED: --password is boolean, ask for password
            $password = get_password("Enter password for private key encryption: ", true);
        }
    }
    
    if ($password) {
        echo "Generating X25519 key pair with encrypted private key (CURUPIRA-192-CBC)...\n";
    } else {
        echo "Generating X25519 key pair (PKCS#8 RFC 8410 format)...\n";
    }
    
    // Generate keys
    $private_key = X25519::generate_private_key();
    $public_key = X25519::x25519_get_public_key($private_key);
    
    // Generate filenames
    $private_file = rtrim($output_dir, '/') . '/' . $name . '_private.pem';
    $public_file = rtrim($output_dir, '/') . '/' . $name . '_public.pem';
    
    // Save keys in PKCS#8 format (RFC 8410)
    $private_pem = x25519_private_to_pkcs8($private_key, $password);
    $public_pem = x25519_public_to_pkcs8($public_key);
    
    file_put_contents($private_file, $private_pem);
    file_put_contents($public_file, $public_pem);
    
    echo "✓ Key pair generated successfully:\n";
    echo "  Private: $private_file" . ($password ? " (ENCRYPTED)" : "") . "\n";
    echo "  Public:  $public_file\n";
    
    if ($password) {
        echo "  Cipher:  CURUPIRA-192-CBC\n";
    }
    
    // Show fingerprint like edgetk
    $fingerprint = hash('sha256', hex2bin($public_key));
    echo "\nFingerprint (SHA256):\n";
    echo "  " . $fingerprint . "\n";
    echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
    
    // Show warning if no password but generating keys
    if (!$password) {
        echo "\n⚠ Warning: Private key is NOT encrypted. Consider using --password option.\n";
    }
    
    return 0;
}

function cmd_publickey($args) {
    $priv_file = null;
    $password = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--priv=') === 0) {
            $priv_file = substr($arg, 7);
        } elseif ($arg === '--password') {
            // MODIFIED: --password is boolean, handled in parse_password_arg
        }
    }
    
    // Validate arguments
    if (!$priv_file) {
        echo "ERROR: Private key not specified\n";
        echo "       Use --priv=FILE\n";
        return 1;
    }
    
    // Load private key
    echo "Loading private key from: $priv_file\n";
    $pem_data = file_get_contents($priv_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $priv_file\n";
        return 1;
    }
    
    // Check if encrypted
    $is_encrypted = (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false);
    
    // Se estiver criptografada, pedir senha
    if ($is_encrypted) {
        $password = get_password("Enter password to decrypt private key: ");
    }
    
    try {
        $private_key = parse_x25519_pkcs8_private($pem_data, $password);
        echo "✓ Private key loaded" . ($is_encrypted ? " (decrypted)" : "") . "\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        if ($is_encrypted && strpos($e->getMessage(), "Decryption failed") !== false) {
            echo "Hint: Wrong password?\n";
        }
        return 1;
    }
    
    // Calculate public key
    echo "\nCalculating public key...\n";
    $public_key = X25519::x25519_get_public_key($private_key);
    
    echo "✓ Public key derived\n\n";
    
    // Show in edgetk style
    echo "Public-Key: (256 bit)\n";
    echo "pub:\n";
    
    $hex_str = $public_key;
    for ($i = 0; $i < strlen($hex_str); $i += 30) {
        $line_hex = substr($hex_str, $i, 30);
        $formatted = implode(':', str_split($line_hex, 2));
        echo "    " . $formatted . "\n";
    }
    
    echo "\nHexadecimal:\n";
    echo $public_key . "\n";
    
    echo "\nPKCS#8 format:\n";
    $pem = x25519_public_to_pkcs8($public_key);
    echo $pem;
    
    return 0;
}

function cmd_sharedsecret($args) {
    $priv_file = null;
    $peer_file = null;
    $password = null;
    $output_file = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--priv=') === 0) {
            $priv_file = substr($arg, 7);
        } elseif (strpos($arg, '--peer=') === 0) {
            $peer_file = substr($arg, 7);
        } elseif ($arg === '--password') {
            // MODIFIED: --password is boolean, handled below
        } elseif (strpos($arg, '--out=') === 0) {
            $output_file = substr($arg, 6);
        }
    }
    
    // Validate arguments
    if (!$priv_file || !$peer_file) {
        echo "ERROR: Both private and peer keys must be specified\n";
        echo "       Use --priv=FILE and --peer=FILE\n";
        return 1;
    }
    
    // Load private key
    echo "Loading private key from: $priv_file\n";
    $pem_data = file_get_contents($priv_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read private key file: $priv_file\n";
        return 1;
    }
    
    // Check if encrypted
    $is_encrypted = (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false);
    
    // Se estiver criptografada, pedir senha
    if ($is_encrypted) {
        $password = get_password("Enter password to decrypt private key: ");
    }
    
    try {
        $private_key = parse_x25519_pkcs8_private($pem_data, $password);
        echo "✓ Private key loaded" . ($is_encrypted ? " (decrypted)" : "") . "\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        if ($is_encrypted && strpos($e->getMessage(), "Decryption failed") !== false) {
            echo "Hint: Wrong password?\n";
        }
        return 1;
    }
    
    // Load peer public key
    echo "Loading peer public key from: $peer_file\n";
    $peer_pem = file_get_contents($peer_file);
    if (!$peer_pem) {
        echo "ERROR: Cannot read peer key file: $peer_file\n";
        return 1;
    }
    
    try {
        $peer_key = parse_x25519_pkcs8_public($peer_pem);
        echo "✓ Peer public key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load peer key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    // Calculate shared secret
    echo "\nCalculating shared secret...\n";
    $shared_secret = X25519::x25519_shared_secret($private_key, $peer_key);
    
    echo "✓ Shared secret calculated\n";
    echo $shared_secret . "\n";
 
    return 0;
}

function cmd_parse($args) {
    $key_file = null;
    $password = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif ($arg === '--password') {
            // MODIFIED: --password is boolean, handled in edgetk_style_parse_pem
        }
    }
    
    if ($key_file) {
        // Parse PEM file
        return edgetk_style_parse_pem($key_file, $password);
    } else {
        echo "ERROR: Key not specified (use --key=FILE)\n";
        return 1;
    }
}

// ====================================================================
// MAIN ENTRY POINT
// ====================================================================

function main() {
    global $argc, $argv;
    
    // Check if we have at least one argument
    if ($argc < 2) {
        show_help();
        return 1;
    }
    
    $command = $argv[1];
    $args = array_slice($argv, 2);
    
    // Execute command
    try {
        switch ($command) {
            case 'help':
                show_help();
                return 0;
                
            case 'version':
                show_version();
                return 0;
                
            case 'generate':
                return cmd_generate($args);
                
            case 'publickey':
                return cmd_publickey($args);
                
            case 'sharedsecret':
                return cmd_sharedsecret($args);
                
            case 'parse':
                return cmd_parse($args);
                
            default:
                echo "ERROR: Unknown command: $command\n";
                echo "       Use 'php x25519_cli.php help' for available commands.\n";
                return 1;
        }
    } catch (Exception $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        return 1;
    }
}

// Execute main function if run from command line
if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    exit(main());
}

// If included as a library, don't execute
return;
