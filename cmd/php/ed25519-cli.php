<?php
// ed25519_cli.php - ED25519 CLI Tool (edgetk-style parsing)
// Usage: php ed25519_cli.php [command] [options]

require_once('ed25519.php');

// ====================================================================
// CLI HELPER FUNCTIONS (EDGETK STYLE)
// ====================================================================

function show_help() {
    echo "ED25519 CLI TOOL - DIGITAL SIGNATURE ALGORITHM\n";
    echo "===============================================\n\n";
    echo "Usage: php ed25519-cli.php [command] [options]\n\n";
    echo "COMMANDS:\n";
    echo "  help                - Show this help\n";
    echo "  version             - Show version\n";
    echo "\n  generate            - Generate new key pair\n";
    echo "    --password        - Encrypt private key with password\n";
    echo "    --out=DIR         - Output directory (default: ./)\n";
    echo "    --name=NAME       - Base name for key files\n";
    echo "\n  sign                - Sign file or text\n";
    echo "    --key=FILE        - Private key file\n";
    echo "    --file=FILE       - File to sign\n";
    echo "    --text=TEXT       - Text to sign (alternative to --file)\n";
    echo "    --out=FILE        - Output signature file\n";
    echo "\n  verify              - Verify signature\n";
    echo "    --key=FILE        - Public key file\n";
    echo "    --file=FILE       - File to verify\n";
    echo "    --text=TEXT       - Text to verify (alternative to --file)\n";
    echo "    --sig=FILE        - Signature file\n";
    echo "    --sig-hex=HEX     - Signature in hexadecimal\n";
    echo "\n  parse               - Parse and display key information (edgetk style)\n";
    echo "    --key=FILE        - Key file to parse\n";
    echo "    --debug           - Show debug information\n";
    echo "\nEXAMPLES:\n";
    echo "  php ed25519_cli.php generate --password\n";
    echo "  php ed25519_cli.php sign --key=private.pem --file=document.txt\n";
    echo "  php ed25519_cli.php verify --key=public.pem --file=document.txt --sig=signature.sig\n";
    echo "  php ed25519_cli.php parse --key=public.pem\n";
}

function show_version() {
    echo "ED25519 CLI Tool v1.0\n";
    echo "ED25519 Digital Signature Algorithm (RFC 8032)\n";
    echo "Based on Twisted Edwards Curve\n";
    echo "OID: 1.3.101.112\n";
}

function get_password($confirm = false) {
    echo "Password: ";
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
            echo "ERROR: Passwords do not match!\n";
            exit(1);
        }
    }
    
    return $password;
}

// ====================================================================
// EDGETK-STYLE PARSING FUNCTIONS
// ====================================================================

function edgetk_style_parse_key($key_file, $debug = false) {
    try {
        $pem_data = file_get_contents($key_file);
        if ($pem_data === false) {
            echo "ERROR: Cannot read key file: $key_file\n";
            return 1;
        }
        
        $lines = explode("\n", trim($pem_data));
        
        // Check if encrypted
        $is_encrypted = false;
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        // Parse private key
        if (strpos($pem_data, "PRIVATE KEY") !== false) {
            
            if ($is_encrypted) {
                echo "Enter password to decrypt private key: ";
                system('stty -echo');
                $password = trim(fgets(STDIN));
                system('stty echo');
                echo "\n";
                
                try {
                    $private_key_hex = ED25519_PEM::parse_private_pem_pkcs8($pem_data, $password);
                    echo "✓ Key decrypted successfully\n";
                    
                    // Parse the decrypted key
                    $private_key = $private_key_hex;
                } catch (Exception $e) {
                    echo "✖ Decryption failed: " . $e->getMessage() . "\n";
                    return 1;
                }
            } else {
                // Parse the key
                $private_key = ED25519_PEM::parse_private_pem_pkcs8($pem_data);
            }
            
            $private_bytes = hex2bin($private_key);
            
            // EDGETK-STYLE OUTPUT FOR PRIVATE KEY
            echo "Private-Key: (" . (strlen($private_bytes)*8) . " bit)\n";
            echo "priv:\n";
            
            $hex_str = $private_key;
            // Format like edgetk: 32 bytes = 64 hex chars, break every 30 hex chars (15 bytes)
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                // Format as colon-separated pairs
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            // Calculate and show public key
            $public_key = ED25519Pure::getPublicKey($private_key);
            $public_bytes = hex2bin($public_key);
            
            echo "pub:\n";
            $hex_str = $public_key;
            // Format public key exactly like private key - multiple lines
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            echo "ASN1 OID: 1.3.101.112\n";
            echo "Curve: Ed25519\n";
            
            // Show additional info like edgetk
            echo "\nAdditional Information:\n";
            echo "  Private key size: " . (strlen($private_bytes)*8) . " bits\n";
            echo "  Public key size: " . (strlen($public_bytes)*8) . " bits\n";
            echo "  Curve parameters:\n";
            echo "    Prime P: 2^255 - 19\n";
            echo "    Order N: 2^252 + 27742317777372353535851937790883648493\n";
            echo "    Cofactor: 8\n";
            
            echo "\n✓ Private key parsed successfully\n";
            
        // Parse public key
        } elseif (strpos($pem_data, "PUBLIC KEY") !== false) {
            
            // Public keys are never encrypted
            // Parse public key
            $public_key_hex = ED25519_PEM::parse_public_pem_pkcs8($pem_data);
            $public_bytes = hex2bin($public_key_hex);
            
            // EDGETK-STYLE OUTPUT FOR PUBLIC KEY
            echo "Public-Key: (" . (strlen($public_bytes)*8) . " bit)\n";
            echo "pub:\n";
            
            $hex_str = $public_key_hex;
            // Format exactly like private key display - multiple lines with colon-separated bytes
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            echo "ASN1 OID: 1.3.101.112\n";
            echo "Curve: Ed25519\n";
            
            // Calculate fingerprint like edgetk
            $fingerprint = hash('sha256', $public_bytes);
            echo "\nFingerprint:\n";
            echo "  SHA256: " . $fingerprint . "\n";
            echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
            
            echo "\n✓ Public key parsed successfully\n";
        
        } else {
            echo "✖ Unknown key format\n";
            return 1;
        }
        
        return 0; // Success
        
    } catch (Exception $e) {
        echo "✖ Error: " . $e->getMessage() . "\n";
        if ($debug) {
            echo $e->getTraceAsString() . "\n";
        }
        return 1;
    }
}

// ====================================================================
// MAIN COMMAND FUNCTIONS
// ====================================================================

function cmd_generate($args) {
    $password = null;
    $output_dir = './';
    $name = 'ed25519';
    
    // Parse arguments
    foreach ($args as $arg) {
        if ($arg === '--password') {
            $password = get_password(true);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_dir = substr($arg, 6);
            if (!is_dir($output_dir)) {
                mkdir($output_dir, 0755, true);
            }
        } elseif (strpos($arg, '--name=') === 0) {
            $name = substr($arg, 7);
        }
    }
    
    echo "Generating Ed25519 key pair...\n";
    
    // Generate keys
    list($private_key, $public_key) = ED25519Pure::generateKeyPair();
    
    // Generate filenames
    $private_file = rtrim($output_dir, '/') . '/' . $name . '_private.pem';
    $public_file = rtrim($output_dir, '/') . '/' . $name . '_public.pem';
    
    // Save keys
    $private_pem = ED25519_PEM::private_to_pem_pkcs8($private_key, $password);
    $public_pem = ED25519_PEM::public_to_pem_pkcs8($public_key);
    
    file_put_contents($private_file, $private_pem);
    file_put_contents($public_file, $public_pem);
    
    echo "✓ Key pair generated successfully:\n";
    echo "  Private: $private_file " . ($password ? "(encrypted)" : "") . "\n";
    echo "  Public:  $public_file\n";
    
    // Show fingerprint like edgetk
    $fingerprint = hash('sha256', hex2bin($public_key));
    echo "\nFingerprint (SHA256):\n";
    echo "  " . $fingerprint . "\n";
    echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
    
    return 0;
}

function cmd_sign($args) {
    $key_file = null;
    $input_file = null;
    $input_text = null;
    $output_file = null;
    $password = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif (strpos($arg, '--file=') === 0) {
            $input_file = substr($arg, 7);
        } elseif (strpos($arg, '--text=') === 0) {
            $input_text = substr($arg, 7);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_file = substr($arg, 6);
        }
    }
    
    // Validate arguments
    if (!$key_file) {
        echo "ERROR: Private key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    if (!$input_file && !$input_text) {
        echo "ERROR: No input specified for signing\n";
        echo "       Use --file=FILE or --text=TEXT\n";
        return 1;
    }
    
    // Load private key
    echo "Loading private key...\n";
    $pem_data = file_get_contents($key_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $key_file\n";
        return 1;
    }
    
    try {
        // Check if key is encrypted
        $is_encrypted = false;
        $lines = explode("\n", trim($pem_data));
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        if ($is_encrypted) {
            // Ask for password if key is encrypted
            echo "Enter password to decrypt private key: ";
            system('stty -echo');
            $password = trim(fgets(STDIN));
            system('stty echo');
            echo "\n";
        }
        
        // Parse the (possibly decrypted) key
        $private_key = ED25519_PEM::parse_private_pem_pkcs8($pem_data, $password);
        echo "✓ Private key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        if ($is_encrypted) {
            echo "       Make sure you entered the correct password.\n";
        }
        return 1;
    }
    
    // Load data to sign
    if ($input_file) {
        echo "Reading file to sign: $input_file\n";
        $message = file_get_contents($input_file);
        if (!$message) {
            echo "ERROR: Cannot read file: $input_file\n";
            return 1;
        }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to sign (" . strlen($message) . " bytes)\n";
    }
    
    // Sign the message
    echo "\nSigning...\n";
    $signature = ED25519Pure::sign($private_key, $message);
    
    echo "✓ Signature generated (" . strlen($signature) . " bytes)\n";
    
    // Save or display signature
    if ($output_file) {
        file_put_contents($output_file, $signature);
        echo "\n✓ Signature saved to: $output_file\n";
        
        // Also save as hex for convenience
        $hex_file = $output_file . '.hex';
        file_put_contents($hex_file, bin2hex($signature));
        echo "  Hex saved to: $hex_file\n";
        
        // Show signature in edgetk style
        echo "\nSignature (hex):\n";
        $hex_str = bin2hex($signature);
        $formatted = implode(':', str_split($hex_str, 2));
        echo "    " . $formatted . "\n";
    } else {
        echo "\nSignature (hexadecimal):\n";
        $hex_str = bin2hex($signature);
        echo $hex_str . "\n";
    }
    
    return 0;
}

function cmd_verify($args) {
    $key_file = null;
    $input_file = null;
    $input_text = null;
    $sig_file = null;
    $sig_hex = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif (strpos($arg, '--file=') === 0) {
            $input_file = substr($arg, 7);
        } elseif (strpos($arg, '--text=') === 0) {
            $input_text = substr($arg, 7);
        } elseif (strpos($arg, '--sig=') === 0) {
            $sig_file = substr($arg, 6);
        } elseif (strpos($arg, '--sig-hex=') === 0) {
            $sig_hex = substr($arg, 10);
        }
    }
    
    // Validate arguments
    if (!$key_file) {
        echo "ERROR: Public key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    if (!$input_file && !$input_text) {
        echo "ERROR: No input specified for verification\n";
        echo "       Use --file=FILE or --text=TEXT\n";
        return 1;
    }
    
    if (!$sig_file && !$sig_hex) {
        echo "ERROR: No signature specified\n";
        echo "       Use --sig=FILE or --sig-hex=HEX\n";
        return 1;
    }
    
    // Load public key
    echo "Loading public key...\n";
    $pem_data = file_get_contents($key_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $key_file\n";
        return 1;
    }
    
    try {
        $public_key = ED25519_PEM::parse_public_pem_pkcs8($pem_data);
        echo "✓ Public key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load public key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    // Load data to verify
    if ($input_file) {
        echo "Reading file to verify: $input_file\n";
        $message = file_get_contents($input_file);
        if (!$message) {
            echo "ERROR: Cannot read file: $input_file\n";
            return 1;
        }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to verify (" . strlen($message) . " bytes)\n";
    }
    
    // Load signature
    if ($sig_file) {
        echo "Reading signature: $sig_file\n";
        $signature = file_get_contents($sig_file);
        if (!$signature) {
            echo "ERROR: Cannot read signature: $sig_file\n";
            return 1;
        }
        echo "✓ Signature read (" . strlen($signature) . " bytes)\n";
    } else {
        $signature = hex2bin($sig_hex);
        if (!$signature) {
            echo "ERROR: Invalid hexadecimal signature\n";
            return 1;
        }
        echo "✓ Signature decoded from hex (" . strlen($signature) . " bytes)\n";
    }
    
    // Verify signature
    echo "\nVerifying signature...\n";
    $valid = ED25519Pure::verify($public_key, $message, $signature);
    
    if ($valid) {
        echo "✓ SIGNATURE VALID\n";
        echo "\nThe signature is valid and matches the message and public key.\n";
        
        // Show signature components like edgetk
        $R = substr($signature, 0, 32);
        $s = substr($signature, 32, 32);
        
        echo "\nSignature components:\n";
        echo "  R (compressed): " . bin2hex($R) . "\n";
        echo "  s (scalar):     " . bin2hex($s) . "\n";
        
        return 0;
    } else {
        echo "✖ SIGNATURE INVALID\n";
        echo "\nThe signature is NOT valid. Possible reasons:\n";
        echo "1. The message has been modified\n";
        echo "2. The signature is corrupted\n";
        echo "3. Wrong public key used for verification\n";
        echo "4. Different algorithm was used for signing\n";
        return 1;
    }
}

function cmd_parse($args) {
    $key_file = null;
    $debug = false;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif ($arg === '--debug') {
            $debug = true;
        }
    }
    
    if (!$key_file) {
        echo "ERROR: Key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    // Parse and display key info in edgetk style
    return edgetk_style_parse_key($key_file, $debug);
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
    
    // Set BC scale for high precision
    bcscale(0);
    
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
                
            case 'sign':
                return cmd_sign($args);
                
            case 'verify':
                return cmd_verify($args);
                
            case 'parse':
                return cmd_parse($args);
                
            default:
                echo "ERROR: Unknown command: $command\n";
                echo "       Use 'php ed25519_cli.php help' for available commands.\n";
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
?>
