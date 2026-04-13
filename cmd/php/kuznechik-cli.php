#!/usr/bin/env php
<?php
/**
 * Kuznechik MGM CLI - EDGE Toolkit Bridge
 * 
 * Usa o binário edgetk para encrypt/decrypt com modo MGM
 * Garante compatibilidade total com o formato do EDGE Toolkit
 * 
 * Usage:
 *   php kuznechik-mgm.php encrypt --key KEY_HEX [--aad AAD] [--infile FILE] [--outfile FILE]
 *   php kuznechik-mgm.php decrypt --key KEY_HEX [--aad AAD] [--infile FILE] [--outfile FILE]
 *   php kuznechik-mgm.php test
 *   php kuznechik-mgm.php info [KEY_HEX]
 */

class KuznechikMGM_CLI {
    private $key;
    private $edgetk_path;
    
    public function __construct($key_hex = null) {
        // Find edgetk in PATH
        $this->edgetk_path = trim(shell_exec('which edgetk 2>/dev/null'));
        if (empty($this->edgetk_path)) {
            // Try common paths
            $paths = ['/usr/local/bin/edgetk', '/usr/bin/edgetk', './edgetk'];
            foreach ($paths as $path) {
                if (file_exists($path) && is_executable($path)) {
                    $this->edgetk_path = $path;
                    break;
                }
            }
        }
        
        if (empty($this->edgetk_path)) {
            throw new Exception("edgetk not found. Please install EDGE Toolkit first.");
        }
        
        if ($key_hex !== null) {
            $key_hex = preg_replace('/[^0-9a-fA-F]/', '', $key_hex);
            if (!ctype_xdigit($key_hex)) {
                throw new Exception("Key contains invalid hex characters");
            }
            if (strlen($key_hex) !== 64) {
                throw new Exception("Key must be 32 bytes (64 hex characters)");
            }
            $this->key = $key_hex;
        }
    }
    
    /**
     * Execute edgetk command
     */
    private function executeEdgetk($action, $input, $aad = '') {
        $cmd = sprintf('%s -crypt %s -cipher kuznechik -mode mgm -key %s -info %s',
            escapeshellcmd($this->edgetk_path),
            escapeshellarg($action),
            escapeshellarg($this->key),
            escapeshellarg($aad)
        );
        
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        
        $proc = proc_open($cmd, $descriptors, $pipes);
        
        if (!is_resource($proc)) {
            throw new Exception("Failed to execute edgetk");
        }
        
        fwrite($pipes[0], $input);
        fclose($pipes[0]);
        
        $output = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        $exit = proc_close($proc);
        
        if ($exit !== 0) {
            throw new Exception("edgetk error: " . trim($stderr));
        }
        
        return $output;
    }
    
    /**
     * MGM encryption
     */
    public function encrypt($infile = null, $outfile = null, $aad = '') {
        // Read input
        if ($infile) {
            $plaintext = file_get_contents($infile);
            if ($plaintext === false) {
                throw new Exception("Failed to read input file: $infile");
            }
        } else {
            $plaintext = stream_get_contents(STDIN);
            if ($plaintext === false) {
                throw new Exception("Failed to read from stdin");
            }
        }
        
        // Encrypt using edgetk
        $output = $this->executeEdgetk('enc', $plaintext, $aad);
        
        if ($outfile) {
            file_put_contents($outfile, $output);
            fprintf(STDERR, "✓ Encrypted to %s\n", $outfile);
            fprintf(STDERR, "  Plaintext size: %d bytes\n", strlen($plaintext));
            fprintf(STDERR, "  Output size: %d bytes\n", strlen($output));
            fprintf(STDERR, "  AAD: %s\n", $aad ?: '(none)');
        } else {
            fwrite(STDOUT, $output);
        }
    }
    
    /**
     * MGM decryption
     */
    public function decrypt($infile = null, $outfile = null, $aad = '') {
        // Read input
        if ($infile) {
            $data = file_get_contents($infile);
            if ($data === false) {
                throw new Exception("Failed to read input file: $infile");
            }
        } else {
            $data = stream_get_contents(STDIN);
            if ($data === false) {
                throw new Exception("Failed to read from stdin");
            }
        }
        
        // Decrypt using edgetk
        $output = $this->executeEdgetk('dec', $data, $aad);
        
        if ($outfile) {
            file_put_contents($outfile, $output);
            fprintf(STDERR, "✓ Decrypted to %s\n", $outfile);
            fprintf(STDERR, "  Input size: %d bytes\n", strlen($data));
            fprintf(STDERR, "  Output size: %d bytes\n", strlen($output));
            fprintf(STDERR, "  AAD: %s\n", $aad ?: '(none)');
        } else {
            fwrite(STDOUT, $output);
        }
    }
    
    /**
     * Self-test using EDGE Toolkit
     */
    public function test() {
        fprintf(STDERR, "=== Kuznechik MGM Self-Test (via EDGE Toolkit) ===\n\n");
        
        $test_key = "0000000000000000000000000000000000000000000000000000000000000000";
        $test_plaintext = "Test message for Kuznechik MGM mode";
        $test_aad = "metadata";
        
        fprintf(STDERR, "Test key: %s\n", $test_key);
        fprintf(STDERR, "Plaintext: %s\n", $test_plaintext);
        fprintf(STDERR, "AAD: %s\n\n", $test_aad);
        
        try {
            $this->key = $test_key;
            
            // Encrypt
            fprintf(STDERR, "1. Encryption test:\n");
            $encrypted = $this->executeEdgetk('enc', $test_plaintext, $test_aad);
            fprintf(STDERR, "   Encrypted size: %d bytes\n", strlen($encrypted));
            
            // Decrypt
            fprintf(STDERR, "\n2. Decryption test:\n");
            $decrypted = $this->executeEdgetk('dec', $encrypted, $test_aad);
            fprintf(STDERR, "   Decrypted match: %s\n", $decrypted === $test_plaintext ? "✓" : "✗");
            
            // Test with wrong AAD
            fprintf(STDERR, "\n3. Wrong AAD test (should fail):\n");
            try {
                $this->executeEdgetk('dec', $encrypted, 'wrong_aad');
                fprintf(STDERR, "   ✗ Decrypted with wrong AAD (should have failed!)\n");
            } catch (Exception $e) {
                fprintf(STDERR, "   ✓ Authentication failed: %s\n", $e->getMessage());
            }
            
            fprintf(STDERR, "\n✓ Self-test completed\n");
            
        } catch (Exception $e) {
            fprintf(STDERR, "✗ Error: %s\n", $e->getMessage());
        }
    }
    
    /**
     * Display information
     */
    public function info($key_hex = null) {
        fprintf(STDERR, "Kuznechik MGM CLI - EDGE Toolkit Bridge\n");
        fprintf(STDERR, "========================================\n\n");
        fprintf(STDERR, "EDGE Toolkit path: %s\n", $this->edgetk_path);
        fprintf(STDERR, "Cipher: Kuznechik (GOST 34.12-2015)\n");
        fprintf(STDERR, "Mode: MGM (Multilinear Galois Mode) - AEAD\n");
        fprintf(STDERR, "Block size: 16 bytes (128 bits)\n");
        fprintf(STDERR, "Key size: 32 bytes (256 bits)\n");
        fprintf(STDERR, "Tag size: 16 bytes (128 bits)\n");
        fprintf(STDERR, "Nonce size: 16 bytes (128 bits)\n\n");
        fprintf(STDERR, "Output format (EDGE Toolkit compatible):\n");
        fprintf(STDERR, "  [nonce 16 bytes][ciphertext][tag 16 bytes]\n\n");
        
        if ($key_hex) {
            $key_hex = preg_replace('/[^0-9a-fA-F]/', '', $key_hex);
            if (strlen($key_hex) === 64) {
                fprintf(STDERR, "Key: %s\n", $key_hex);
            } else {
                fprintf(STDERR, "Invalid key length: %d (expected 64 hex)\n", strlen($key_hex));
            }
        }
        
        // Show edgetk version
        fprintf(STDERR, "\nEDGE Toolkit version:\n");
        $version = shell_exec($this->edgetk_path . ' -version 2>&1');
        if ($version) {
            fprintf(STDERR, "  %s", trim($version));
        }
        fprintf(STDERR, "\n");
    }
}

// ====================================================================
// CLI PARSING
// ====================================================================

function parse_cli_args() {
    global $argv;
    
    $args = [
        'action' => null,
        'key' => null,
        'infile' => null,
        'outfile' => null,
        'aad' => '',
        'help' => false,
        'test' => false,
        'info' => false
    ];
    
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case 'encrypt':
                $args['action'] = 'encrypt';
                break;
            case 'decrypt':
                $args['action'] = 'decrypt';
                break;
            case 'test':
            case '--test':
            case '-t':
                $args['test'] = true;
                break;
            case 'info':
            case '--info':
            case '-i':
                $args['info'] = true;
                break;
            case '--key':
            case '-k':
                if ($i + 1 < count($argv)) {
                    $args['key'] = $argv[++$i];
                }
                break;
            case '--aad':
            case '-a':
                if ($i + 1 < count($argv)) {
                    $args['aad'] = $argv[++$i];
                }
                break;
            case '--infile':
            case '-f':
                if ($i + 1 < count($argv)) {
                    $args['infile'] = $argv[++$i];
                }
                break;
            case '--outfile':
            case '-o':
                if ($i + 1 < count($argv)) {
                    $args['outfile'] = $argv[++$i];
                }
                break;
            case '--help':
            case '-h':
                $args['help'] = true;
                break;
            default:
                if ($args['action'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['action'] = $argv[$i];
                } elseif ($args['key'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['key'] = $argv[$i];
                }
                break;
        }
    }
    
    return $args;
}

function print_help() {
    global $argv;
    $script = basename($argv[0]);
    fprintf(STDERR, "Kuznechik MGM CLI - EDGE Toolkit Bridge\n");
    fprintf(STDERR, "========================================\n\n");
    fprintf(STDERR, "Usage:\n");
    fprintf(STDERR, "  %s encrypt [OPTIONS]   - Encrypt using MGM mode\n", $script);
    fprintf(STDERR, "  %s decrypt [OPTIONS]   - Decrypt using MGM mode\n", $script);
    fprintf(STDERR, "  %s test                - Run self-test\n", $script);
    fprintf(STDERR, "  %s info [KEY]          - Display information\n\n", $script);
    fprintf(STDERR, "Options:\n");
    fprintf(STDERR, "  -k, --key HEX          Encryption key (32 bytes, 64 hex)\n");
    fprintf(STDERR, "  -a, --aad TEXT         Additional Authenticated Data\n");
    fprintf(STDERR, "  -f, --infile FILE      Input file (stdin if not provided)\n");
    fprintf(STDERR, "  -o, --outfile FILE     Output file (stdout if not provided)\n");
    fprintf(STDERR, "  -h, --help             Show this help\n\n");
    fprintf(STDERR, "Output format (EDGE Toolkit compatible):\n");
    fprintf(STDERR, "  [nonce 16 bytes][ciphertext][tag 16 bytes]\n\n");
    fprintf(STDERR, "Examples:\n");
    fprintf(STDERR, "  Encrypt:\n");
    fprintf(STDERR, "    %s encrypt -k 00...00 -f plain.txt -o cipher.bin -a 'metadata'\n", $script);
    fprintf(STDERR, "  Decrypt:\n");
    fprintf(STDERR, "    %s decrypt -k 00...00 -f cipher.bin -o plain.txt -a 'metadata'\n", $script);
    fprintf(STDERR, "  Pipe:\n");
    fprintf(STDERR, "    echo -n 'Hello' | %s encrypt -k 00...00 -a 'metadata' | %s decrypt -k 00...00 -a 'metadata'\n", $script, $script);
}

function main() {
    $args = parse_cli_args();
    
    if ($args['help']) {
        print_help();
        exit(0);
    }
    
    if ($args['test']) {
        try {
            $cli = new KuznechikMGM_CLI();
            $cli->test();
            exit(0);
        } catch (Exception $e) {
            fprintf(STDERR, "✖ Error: %s\n", $e->getMessage());
            exit(1);
        }
    }
    
    if ($args['info']) {
        try {
            $cli = new KuznechikMGM_CLI();
            $cli->info($args['key']);
            exit(0);
        } catch (Exception $e) {
            fprintf(STDERR, "✖ Error: %s\n", $e->getMessage());
            exit(1);
        }
    }
    
    if (!$args['action']) {
        fprintf(STDERR, "✖ Error: No action specified (encrypt or decrypt)\n");
        print_help();
        exit(1);
    }
    
    if (!$args['key']) {
        fprintf(STDERR, "✖ Error: Key not specified (use --key)\n");
        print_help();
        exit(1);
    }
    
    try {
        $cli = new KuznechikMGM_CLI($args['key']);
        
        if ($args['action'] === 'encrypt') {
            $cli->encrypt($args['infile'], $args['outfile'], $args['aad']);
        } elseif ($args['action'] === 'decrypt') {
            $cli->decrypt($args['infile'], $args['outfile'], $args['aad']);
        } else {
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
