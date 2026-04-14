#!/usr/bin/env php
<?php
/**
 * Kuznechik CLI - GOST 34.12-2015 Block Cipher
 * Modes: CTR and GCM
 * 
 * Usage:
 *   php kuznechik-cli.php encrypt --key KEY_HEX [--aad AAD] [--infile FILE] [--outfile FILE] [--nonce NONCE_HEX]
 *   php kuznechik-cli.php decrypt --key KEY_HEX [--aad AAD] [--infile FILE] [--outfile FILE]
 *   php kuznechik-cli.php ctr --key KEY_HEX --iv IV_HEX [--infile FILE] [--outfile FILE]
 *   php kuznechik-cli.php test
 *   php kuznechik-cli.php info
 */

require_once __DIR__ . '/kuznechik.php';

function normalize_hex($hex) {
    $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
    if (strlen($hex) % 2 !== 0) {
        $hex = '0' . $hex;
    }
    return $hex;
}

function read_input($infile = null) {
    if ($infile) {
        $data = file_get_contents($infile);
        if ($data === false) {
            throw new Exception("Failed to read input file: $infile");
        }
        return $data;
    }
    return stream_get_contents(STDIN);
}

function write_output($outfile = null, $data) {
    if ($outfile) {
        file_put_contents($outfile, $data);
    } else {
        fwrite(STDOUT, $data);
    }
}

function cmd_encrypt($key_hex, $infile, $outfile, $aad, $nonce_hex) {
    $key_hex = normalize_hex($key_hex);
    if (strlen($key_hex) !== 64) {
        throw new Exception("Key must be 32 bytes (64 hex)");
    }
    
    $key = hex2bin($key_hex);
    $cipher = new Kuznechik($key);
    
    $plaintext = read_input($infile);
    
    if ($nonce_hex) {
        $nonce_hex = normalize_hex($nonce_hex);
        if (strlen($nonce_hex) !== 24) {
            throw new Exception("Nonce must be 12 bytes (24 hex)");
        }
        $nonce = hex2bin($nonce_hex);
    } else {
        $nonce = random_bytes(12);
    }
    
    $gcm = new KuznechikGCM($cipher, $nonce, 16);
    list($ciphertext, $tag) = $gcm->encrypt($plaintext, $aad ?? '');
    
    $output = $nonce . $ciphertext . $tag;
    write_output($outfile, $output);
}

function cmd_decrypt($key_hex, $infile, $outfile, $aad) {
    $key_hex = normalize_hex($key_hex);
    if (strlen($key_hex) !== 64) {
        throw new Exception("Key must be 32 bytes (64 hex)");
    }
    
    $key = hex2bin($key_hex);
    $cipher = new Kuznechik($key);
    
    $data = read_input($infile);
    
    if (strlen($data) < 28) {
        throw new Exception("Data too short: need at least 28 bytes (nonce:12 + tag:16)");
    }
    
    $nonce = substr($data, 0, 12);
    $tag = substr($data, -16);
    $ciphertext = substr($data, 12, -16);
    
    $gcm = new KuznechikGCM($cipher, $nonce, 16);
    $plaintext = $gcm->decrypt($ciphertext, $tag, $aad ?? '');
    
    if ($plaintext === null) {
        throw new Exception("Authentication failed! Invalid tag or corrupted data");
    }
    
    write_output($outfile, $plaintext);
}

function cmd_ctr($key_hex, $iv_hex, $infile, $outfile) {
    $key_hex = normalize_hex($key_hex);
    if (strlen($key_hex) !== 64) {
        throw new Exception("Key must be 32 bytes (64 hex)");
    }
    
    $iv_hex = normalize_hex($iv_hex);
    if (strlen($iv_hex) !== 32) {
        throw new Exception("IV must be 16 bytes (32 hex)");
    }
    
    $key = hex2bin($key_hex);
    $iv = hex2bin($iv_hex);
    $cipher = new Kuznechik($key);
    
    $data = read_input($infile);
    $result = $cipher->ctr($data, $iv);
    
    write_output($outfile, $result);
}

function cmd_test() {
    fprintf(STDERR, "=== Kuznechik GCM Self-Test ===\n\n");
    
    $test_key = "0000000000000000000000000000000000000000000000000000000000000000";
    $test_nonce = "000000000000000000000000";
    $test_plaintext = "Test message for Kuznechik GCM mode!";
    $test_aad = "metadata";
    
    fprintf(STDERR, "Key: %s\n", $test_key);
    fprintf(STDERR, "Nonce: %s\n", $test_nonce);
    fprintf(STDERR, "Plaintext: %s\n", $test_plaintext);
    fprintf(STDERR, "AAD: %s\n\n", $test_aad);
    
    try {
        $key = hex2bin($test_key);
        $nonce = hex2bin($test_nonce);
        $cipher = new Kuznechik($key);
        $gcm = new KuznechikGCM($cipher, $nonce, 16);
        
        fprintf(STDERR, "1. Encryption test:\n");
        list($ciphertext, $tag) = $gcm->encrypt($test_plaintext, $test_aad);
        fprintf(STDERR, "   Ciphertext size: %d bytes\n", strlen($ciphertext));
        fprintf(STDERR, "   Tag: %s\n", bin2hex($tag));
        
        fprintf(STDERR, "\n2. Decryption test:\n");
        $decrypted = $gcm->decrypt($ciphertext, $tag, $test_aad);
        fprintf(STDERR, "   Decrypted: %s\n", $decrypted);
        fprintf(STDERR, "   Match: %s\n", $decrypted === $test_plaintext ? "✓" : "✗");
        
        fprintf(STDERR, "\n3. Wrong AAD test (should fail):\n");
        $decrypted = $gcm->decrypt($ciphertext, $tag, "wrong_aad");
        fprintf(STDERR, "   Result: %s\n", $decrypted === null ? "✓ (rejected)" : "✗");
        
        fprintf(STDERR, "\n4. Wrong tag test (should fail):\n");
        $wrong_tag = str_repeat("\x00", 16);
        $decrypted = $gcm->decrypt($ciphertext, $wrong_tag, $test_aad);
        fprintf(STDERR, "   Result: %s\n", $decrypted === null ? "✓ (rejected)" : "✗");
        
        fprintf(STDERR, "\n✓ Self-test completed\n");
    } catch (Exception $e) {
        fprintf(STDERR, "✗ Error: %s\n", $e->getMessage());
    }
}

function cmd_info() {
    fprintf(STDERR, "Kuznechik Block Cipher - GOST 34.12-2015\n");
    fprintf(STDERR, "=========================================\n\n");
    fprintf(STDERR, "Block size: 16 bytes (128 bits)\n");
    fprintf(STDERR, "Key size: 32 bytes (256 bits)\n");
    fprintf(STDERR, "Nonce size (GCM): 12 bytes (96 bits)\n");
    fprintf(STDERR, "Tag size (GCM): 16 bytes (128 bits)\n");
    fprintf(STDERR, "IV size (CTR): 16 bytes (128 bits)\n");
    fprintf(STDERR, "Modes: CTR (stream), GCM (AEAD)\n");
    fprintf(STDERR, "Reference: GOST R 34.12-2015\n");
}

function print_help() {
    $script = basename(__FILE__);
    fprintf(STDERR, "Kuznechik CLI - GOST 34.12-2015 Block Cipher\n");
    fprintf(STDERR, "=============================================\n\n");
    fprintf(STDERR, "Usage:\n");
    fprintf(STDERR, "  php %s encrypt --key KEY_HEX [OPTIONS]   (GCM mode)\n", $script);
    fprintf(STDERR, "  php %s decrypt --key KEY_HEX [OPTIONS]   (GCM mode)\n", $script);
    fprintf(STDERR, "  php %s ctr --key KEY_HEX --iv IV_HEX [OPTIONS]\n", $script);
    fprintf(STDERR, "  php %s test\n", $script);
    fprintf(STDERR, "  php %s info\n", $script);
    fprintf(STDERR, "\nOptions:\n");
    fprintf(STDERR, "  -k, --key HEX        Key (32 bytes, 64 hex)\n");
    fprintf(STDERR, "  --iv HEX             IV for CTR mode (16 bytes, 32 hex)\n");
    fprintf(STDERR, "  --nonce HEX          Nonce for GCM mode (12 bytes, 24 hex)\n");
    fprintf(STDERR, "  -a, --aad TEXT       Additional Authenticated Data (GCM mode)\n");
    fprintf(STDERR, "  -f, --infile FILE    Input file (stdin if not provided)\n");
    fprintf(STDERR, "  -o, --outfile FILE   Output file (stdout if not provided)\n");
    fprintf(STDERR, "  -h, --help           Show this help\n");
    fprintf(STDERR, "\nOutput format (GCM):\n");
    fprintf(STDERR, "  [nonce 12 bytes][ciphertext][tag 16 bytes]\n");
    fprintf(STDERR, "\nOutput format (CTR):\n");
    fprintf(STDERR, "  [ciphertext] (no header)\n");
}

function main() {
    global $argv;
    
    $args = [
        'action' => null,
        'key' => null,
        'iv' => null,
        'nonce' => null,
        'aad' => null,
        'infile' => null,
        'outfile' => null,
        'help' => false,
        'test' => false,
        'info' => false
    ];
    
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case 'encrypt': $args['action'] = 'encrypt'; break;
            case 'decrypt': $args['action'] = 'decrypt'; break;
            case 'ctr': $args['action'] = 'ctr'; break;
            case 'test': $args['test'] = true; break;
            case 'info': $args['info'] = true; break;
            case '-k': case '--key': $args['key'] = $argv[++$i] ?? ''; break;
            case '--iv': $args['iv'] = $argv[++$i] ?? ''; break;
            case '--nonce': $args['nonce'] = $argv[++$i] ?? ''; break;
            case '-a': case '--aad': $args['aad'] = $argv[++$i] ?? ''; break;
            case '-f': case '--infile': $args['infile'] = $argv[++$i] ?? null; break;
            case '-o': case '--outfile': $args['outfile'] = $argv[++$i] ?? null; break;
            case '-h': case '--help': $args['help'] = true; break;
            default:
                if ($args['action'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['action'] = $argv[$i];
                } elseif ($args['key'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['key'] = $argv[$i];
                } elseif ($args['iv'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['iv'] = $argv[$i];
                }
                break;
        }
    }
    
    if ($args['help']) {
        print_help();
        exit(0);
    }
    
    if ($args['test']) {
        cmd_test();
        exit(0);
    }
    
    if ($args['info']) {
        cmd_info();
        exit(0);
    }
    
    if (!$args['action']) {
        fprintf(STDERR, "✖ Error: No action specified\n");
        print_help();
        exit(1);
    }
    
    try {
        switch ($args['action']) {
            case 'encrypt':
                if (!$args['key']) throw new Exception("Key required");
                cmd_encrypt($args['key'], $args['infile'], $args['outfile'], $args['aad'], $args['nonce']);
                break;
            case 'decrypt':
                if (!$args['key']) throw new Exception("Key required");
                cmd_decrypt($args['key'], $args['infile'], $args['outfile'], $args['aad']);
                break;
            case 'ctr':
                if (!$args['key']) throw new Exception("Key required");
                if (!$args['iv']) throw new Exception("IV required for CTR mode");
                cmd_ctr($args['key'], $args['iv'], $args['infile'], $args['outfile']);
                break;
            default:
                throw new Exception("Unknown action: {$args['action']}");
        }
    } catch (Exception $e) {
        fprintf(STDERR, "✖ Error: %s\n", $e->getMessage());
        exit(1);
    }
}

if (PHP_SAPI === 'cli') {
    main();
}
?>
