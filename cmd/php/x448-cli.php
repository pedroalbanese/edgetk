<?php
// x448-cli.php - X448 CLI Tool (edgetk-style parsing)
// Usage: php x448-cli.php [command] [options]

require_once('x448.php');

// ====================================================================
// CLI HELPER FUNCTIONS (EDGETK STYLE)
// ====================================================================

function show_help() {
    echo "X448 CLI TOOL - ELLIPTIC CURVE DIFFIE-HELLMAN (CURVE448)\n";
    echo "============================================================\n\n";
    echo "Usage: php x448_cli.php [command] [options]\n\n";
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
    echo "  php x448_cli.php generate --name=alice --password\n";
    echo "  php x448_cli.php publickey --priv=alice_private.pem\n";
    echo "  php x448_cli.php sharedsecret --priv=alice_private.pem --peer=bob_public.pem\n";
    echo "  php x448_cli.php parse --key=alice_public.pem\n";
}

function show_version() {
    echo "X448 CLI Tool v1.0\n";
    echo "X448 (Curve448) Diffie-Hellman Key Exchange\n";
    echo "RFC 7748 - Elliptic Curves for Security\n";
    echo "Algorithm by Daniel J. Bernstein\n";
    echo "With Curupira-192-CBC encryption support\n";
}

// ====================================================================
// DER ENCODING FUNCTIONS FOR X448
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
    // OID 1.3.101.111 for X448
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
        return readline($prompt);
    }
}

function parse_password_arg($args, $key_file = null) {
    $password = null;
    $has_password_arg = false;
    
    foreach ($args as $arg) {
        if ($arg === '--password') {
            $has_password_arg = true;
            break;
        }
    }
    
    if ($key_file && !$has_password_arg && file_exists($key_file)) {
        $pem_data = file_get_contents($key_file);
        if (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false) {
            $password = get_password("Enter password to decrypt private key: ");
        }
    }
    
    return $password;
}

// ====================================================================
// PKCS#8 FUNCTIONS FOR X448
// ====================================================================

function x448_private_to_pkcs8($private_key_hex, $password = null) {
    $private_key_bin = hex2bin($private_key_hex);
    
    // Inner OCTET STRING with the 56-byte private key
    $inner_octet_string = der_encode_octet_string($private_key_bin);
    
    // AlgorithmIdentifier for X448 (1.3.101.111)
    $algorithm_identifier = der_encode_sequence(
        der_encode_oid("1.3.101.111")
    );
    
    // PrivateKey is the inner OCTET STRING
    $private_key = der_encode_octet_string($inner_octet_string);
    
    // Version INTEGER 0
    $version = der_encode_integer("0");
    
    // PrivateKeyInfo SEQUENCE
    $private_key_info = $version . $algorithm_identifier . $private_key;
    $der = der_encode_sequence($private_key_info);
    
    if ($password) {
        $encrypted_pem = X448_PEM::private_to_pem_pkcs8($private_key_hex, $password);
        return $encrypted_pem;
    } else {
        return "-----BEGIN X448 PRIVATE KEY-----\n" . 
               chunk_split(base64_encode($der), 64) . 
               "-----END X448 PRIVATE KEY-----\n";
    }
}

function x448_public_to_pkcs8($public_key_hex) {
    $public_key_bin = hex2bin($public_key_hex);
    
    $algorithm_identifier = der_encode_sequence(
        der_encode_oid("1.3.101.111")
    );
    
    $subject_public_key = der_encode_bit_string($public_key_bin);
    $subject_public_key_info = $algorithm_identifier . $subject_public_key;
    $der = der_encode_sequence($subject_public_key_info);
    
    return "-----BEGIN X448 PUBLIC KEY-----\n" . 
           chunk_split(base64_encode($der), 64) . 
           "-----END X448 PUBLIC KEY-----\n";
}

function parse_x448_pkcs8_private($pem_data, $password = null) {
    return X448_PEM::parse_private_pem_pkcs8($pem_data, $password);
}

function parse_x448_pkcs8_public($pem_data) {
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
    
    $pos = 0;
    
    if (ord($der[$pos]) !== 0x30) {
        throw new Exception("Not a SEQUENCE");
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
    
    $pos++;
    $public_key_bin = substr($der, $pos, $len - 1);
    
    if (strlen($public_key_bin) !== 56) {
        throw new Exception("Invalid public key length: " . strlen($public_key_bin));
    }
    
    return bin2hex($public_key_bin);
}

// ====================================================================
// EDGETK-STYLE PARSING FUNCTIONS FOR X448
// ====================================================================

function edgetk_style_parse_key($key_hex, $is_private = false) {
    try {
        if (strlen($key_hex) != 112 || !ctype_xdigit($key_hex)) {
            echo "ERROR: Invalid key hex (expected 112 hex characters for X448)\n";
            return 1;
        }
        
        $bytes = hex2bin($key_hex);
        if ($bytes === false) {
            echo "ERROR: Invalid hex string\n";
            return 1;
        }
        
        if ($is_private) {
            echo "X448 Private-Key: (448 bit)\n";
            echo "priv:\n";
        } else {
            echo "X448 Public-Key: (448 bit)\n";
            echo "pub:\n";
        }
        
        $hex_str = $key_hex;
        for ($i = 0; $i < strlen($hex_str); $i += 30) {
            $line_hex = substr($hex_str, $i, 30);
            $formatted = implode(':', str_split($line_hex, 2));
            echo "    " . $formatted . "\n";
        }
        
        if ($is_private) {
            $byte0 = ord($bytes[0]);
            $byte55 = ord($bytes[55]);
            $bits0_1_cleared = ($byte0 & 0x03) == 0;
            $bit447_set = ($byte55 & 0x80) != 0;
            
            echo "Clamping check:\n";
            echo sprintf(
                "  Byte 0: 0x%02x (bits 0-1 cleared: %s)\n  Byte 55: 0x%02x (bit 447 set: %s)\n",
                $byte0, $bits0_1_cleared ? 'yes' : 'no',
                $byte55, $bit447_set ? 'yes' : 'no'
            );
            
            if ($bits0_1_cleared && $bit447_set) {
                echo "  ✓ Key is properly clamped for X448\n";
            } else {
                echo "  ⚠ Key is NOT properly clamped for X448\n";
            }
        }
        
        echo "ASN1 OID: 1.3.101.111\n";
        echo "Curve: Curve448 (X448)\n";
        
        if ($is_private) {
            echo "\nCalculating public key...\n";
            try {
                $public_key = X448::x448_get_public_key($key_hex);
                
                echo "Public-Key: (448 bit)\n";
                echo "pub:\n";
                
                $hex_str = $public_key;
                for ($i = 0; $i < strlen($hex_str); $i += 30) {
                    $line_hex = substr($hex_str, $i, 30);
                    $formatted = implode(':', str_split($line_hex, 2));
                    echo "    " . $formatted . "\n";
                }
                
                $fingerprint = hash('sha256', hex2bin($public_key));
                echo "\nFingerprint:\n";
                echo "  SHA256: " . $fingerprint . "\n";
                echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
                
            } catch (Exception $e) {
                echo "Note: Could not calculate public key: " . $e->getMessage() . "\n";
            }
        } else {
            $fingerprint = hash('sha256', hex2bin($key_hex));
            echo "\nFingerprint:\n";
            echo "  SHA256: " . $fingerprint . "\n";
            echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
        }
        
        echo "\n✓ Key parsed successfully\n";
        return 0;
        
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
        
        $is_encrypted = false;
        $lines = explode("\n", $pem_data);
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        if ($is_encrypted && !$password) {
            $password = get_password("Enter password to decrypt private key: ");
        }
        
        foreach ($lines as $line) {
            if (str_starts_with($line, '-----')) {
                echo $line . "\n";
                break;
            }
        }
        
        $is_private = (strpos($pem_data, "X448 PRIVATE KEY") !== false);
        $is_public = (strpos($pem_data, "X448 PUBLIC KEY") !== false);
        
        if (!$is_private && !$is_public) {
            echo "ERROR: Unknown key format\n";
            return 1;
        }
        
        if ($is_private) {
            $key_hex = parse_x448_pkcs8_private($pem_data, $password);
        } else {
            $key_hex = parse_x448_pkcs8_public($pem_data);
        }
        
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
        
        foreach ($lines as $line) {
            if (str_starts_with($line, '-----END')) {
                echo $line . "\n";
                break;
            }
        }
        
        if ($is_encrypted) {
            echo "\nEncryption: CURUPIRA-192-CBC\n";
            if ($password) {
                echo "Status: ✓ Decrypted successfully\n";
            } else {
                echo "Status: ✗ Not decrypted (no password provided)\n";
            }
        }
        
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
    $name = 'x448';
    $password = null;
    
    foreach ($args as $arg) {
        if (strpos($arg, '--out=') === 0) {
            $output_dir = substr($arg, 6);
            if (!is_dir($output_dir)) {
                mkdir($output_dir, 0755, true);
            }
        } elseif (strpos($arg, '--name=') === 0) {
            $name = substr($arg, 7);
        } elseif ($arg === '--password') {
            $password = get_password("Enter password for private key encryption: ", true);
        }
    }
    
    if ($password) {
        echo "Generating X448 key pair with encrypted private key (CURUPIRA-192-CBC)...\n";
    } else {
        echo "Generating X448 key pair (PKCS#8 RFC 8410 format)...\n";
    }
    
    $private_key = X448::generate_private_key();
    $public_key = X448::x448_get_public_key($private_key);
    
    $private_file = rtrim($output_dir, '/') . '/' . $name . '_private.pem';
    $public_file = rtrim($output_dir, '/') . '/' . $name . '_public.pem';
    
    $private_pem = x448_private_to_pkcs8($private_key, $password);
    $public_pem = x448_public_to_pkcs8($public_key);
    
    file_put_contents($private_file, $private_pem);
    file_put_contents($public_file, $public_pem);
    
    echo "✓ Key pair generated successfully:\n";
    echo "  Private: $private_file" . ($password ? " (ENCRYPTED)" : "") . "\n";
    echo "  Public:  $public_file\n";
    
    if ($password) {
        echo "  Cipher:  CURUPIRA-192-CBC\n";
    }
    
    $fingerprint = hash('sha256', hex2bin($public_key));
    echo "\nFingerprint (SHA256):\n";
    echo "  " . $fingerprint . "\n";
    echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
    
    if (!$password) {
        echo "\n⚠ Warning: Private key is NOT encrypted. Consider using --password option.\n";
    }
    
    return 0;
}

function cmd_publickey($args) {
    $priv_file = null;
    $password = null;
    
    foreach ($args as $arg) {
        if (strpos($arg, '--priv=') === 0) {
            $priv_file = substr($arg, 7);
        }
    }
    
    if (!$priv_file) {
        echo "ERROR: Private key not specified\n";
        echo "       Use --priv=FILE\n";
        return 1;
    }
    
    echo "Loading private key from: $priv_file\n";
    $pem_data = file_get_contents($priv_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $priv_file\n";
        return 1;
    }
    
    $is_encrypted = (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false);
    
    if ($is_encrypted) {
        $password = get_password("Enter password to decrypt private key: ");
    }
    
    try {
        $private_key = parse_x448_pkcs8_private($pem_data, $password);
        echo "✓ Private key loaded" . ($is_encrypted ? " (decrypted)" : "") . "\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    echo "\nCalculating public key...\n";
    $public_key = X448::x448_get_public_key($private_key);
    
    echo "✓ Public key derived\n\n";
    
    echo "Public-Key: (448 bit)\n";
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
    $pem = x448_public_to_pkcs8($public_key);
    echo $pem;
    
    return 0;
}

function cmd_sharedsecret($args) {
    $priv_file = null;
    $peer_file = null;
    $password = null;
    $output_file = null;
    
    foreach ($args as $arg) {
        if (strpos($arg, '--priv=') === 0) {
            $priv_file = substr($arg, 7);
        } elseif (strpos($arg, '--peer=') === 0) {
            $peer_file = substr($arg, 7);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_file = substr($arg, 6);
        }
    }
    
    if (!$priv_file || !$peer_file) {
        echo "ERROR: Both private and peer keys must be specified\n";
        echo "       Use --priv=FILE and --peer=FILE\n";
        return 1;
    }
    
    echo "Loading private key from: $priv_file\n";
    $pem_data = file_get_contents($priv_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read private key file: $priv_file\n";
        return 1;
    }
    
    $is_encrypted = (strpos($pem_data, "Proc-Type: 4,ENCRYPTED") !== false);
    
    if ($is_encrypted) {
        $password = get_password("Enter password to decrypt private key: ");
    }
    
    try {
        $private_key = parse_x448_pkcs8_private($pem_data, $password);
        echo "✓ Private key loaded" . ($is_encrypted ? " (decrypted)" : "") . "\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    echo "Loading peer public key from: $peer_file\n";
    $peer_pem = file_get_contents($peer_file);
    if (!$peer_pem) {
        echo "ERROR: Cannot read peer key file: $peer_file\n";
        return 1;
    }
    
    try {
        $peer_key = parse_x448_pkcs8_public($peer_pem);
        echo "✓ Peer public key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load peer key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    echo "\nCalculating shared secret...\n";
    $shared_secret = X448::x448_shared_secret($private_key, $peer_key);
    
    echo "✓ Shared secret calculated\n";
    echo $shared_secret . "\n";
    
    if ($output_file) {
        file_put_contents($output_file, $shared_secret);
        echo "Saved to: $output_file\n";
    }
    
    return 0;
}

function cmd_parse($args) {
    $key_file = null;
    $password = null;
    
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        }
    }
    
    if ($key_file) {
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
    
    if ($argc < 2) {
        show_help();
        return 1;
    }
    
    $command = $argv[1];
    $args = array_slice($argv, 2);
    
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
                echo "       Use 'php x448_cli.php help' for available commands.\n";
                return 1;
        }
    } catch (Exception $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        return 1;
    }
}

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    exit(main());
}

return;
?>
