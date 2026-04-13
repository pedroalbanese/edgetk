<?php
/**
 * Curupira1 CLI - LetterSoup AEAD Mode
 * Usage: php curupira1-cli.php [encrypt|decrypt] KEY_HEX [OPTIONS]
 * 
 * Requer: curupira1.php (implementação da cifra)
 */

require_once __DIR__ . '/curupira1.php';

class Curupira1_CLI {
    private $key;
    
    public function __construct($key_hex = null) {
        // Se não houver chave, não validar (para comandos test/info sem chave)
        if ($key_hex === null || $key_hex === '') {
            $this->key = null;
            return;
        }
        
        // Remove espaços e caracteres especiais
        $key_hex = preg_replace('/[^0-9a-fA-F]/', '', $key_hex);
        
        // Verifica se é hex válido
        if (!ctype_xdigit($key_hex)) {
            throw new Exception("Key contains invalid hex characters");
        }
        
        // Garante comprimento par
        if (strlen($key_hex) % 2 !== 0) {
            $key_hex = '0' . $key_hex;
        }
        
        // Converte para bytes
        $this->key = hex2bin($key_hex);
        if ($this->key === false) {
            throw new Exception("Invalid hex key");
        }
        
        // Valida tamanho da chave para Curupira1
        $key_len = strlen($this->key);
        $valid_sizes = [12, 18, 24];
        
        if (!in_array($key_len, $valid_sizes)) {
            throw new Exception(sprintf(
                "Invalid Curupira1 key size: %d bytes. Valid sizes: %s bytes (%s bits)",
                $key_len,
                implode(', ', $valid_sizes),
                implode(', ', array_map(function($b) { return $b * 8; }, $valid_sizes))
            ));
        }
    }
    
    public function encrypt($infile = null, $outfile = null, $aad = '') {
        if ($this->key === null) {
            throw new Exception("Key required for encryption");
        }
        
        // Read input
        if ($infile) {
            $plaintext = file_get_contents($infile);
            if ($plaintext === false) {
                throw new Exception("Failed to read input file: $infile");
            }
        } else {
            // Read from stdin
            $plaintext = stream_get_contents(STDIN);
            if ($plaintext === false || $plaintext === '') {
                if (posix_isatty(STDIN)) {
                    fprintf(STDERR, "Enter message to encrypt (Ctrl+D to finish):\n");
                    $plaintext = stream_get_contents(STDIN);
                }
            }
        }
        
        // Encrypt using LetterSoup
        $ciphertext = lettersoup_encrypt($this->key, $plaintext, $aad);
        
        if ($outfile) {
            file_put_contents($outfile, $ciphertext);
            fprintf(STDERR, "✓ Encrypted to %s\n", $outfile);
            fprintf(STDERR, "  Input size: %d bytes\n", strlen($plaintext));
            fprintf(STDERR, "  Output size: %d bytes\n", strlen($ciphertext));
            fprintf(STDERR, "  AAD: %s\n", $aad ?: '(none)');
        } else {
            echo $ciphertext;
        }
    }
    
    public function decrypt($infile = null, $outfile = null, $aad = '') {
        if ($this->key === null) {
            throw new Exception("Key required for decryption");
        }
        
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
        
        // Decrypt using LetterSoup
        $plaintext = lettersoup_decrypt($this->key, $data, $aad);
        
        if ($outfile) {
            file_put_contents($outfile, $plaintext);
            fprintf(STDERR, "✓ Decrypted to %s\n", $outfile);
            fprintf(STDERR, "  Input size: %d bytes\n", strlen($data));
            fprintf(STDERR, "  Output size: %d bytes\n", strlen($plaintext));
            fprintf(STDERR, "  AAD: %s\n", $aad ?: '(none)');
        } else {
            echo $plaintext;
        }
    }
    
    public function test() {
        fprintf(STDERR, "=== Curupira1 LetterSoup Self-Test ===\n\n");
        
        $test_key = hex2bin("0228674ed28f695ed88a39ec0228674ed28f695ed88a39ec");
        $test_plaintext = "Test message for LetterSoup";
        $test_aad = "metadata";
        
        fprintf(STDERR, "Test key: %s\n", bin2hex($test_key));
        fprintf(STDERR, "Plaintext: %s\n", $test_plaintext);
        fprintf(STDERR, "AAD: %s\n\n", $test_aad);
        
        // Test encrypt/decrypt
        fprintf(STDERR, "1. Basic encrypt/decrypt test:\n");
        try {
            $encrypted = lettersoup_encrypt($test_key, $test_plaintext, $test_aad);
            fprintf(STDERR, "   Encrypted: %d bytes\n", strlen($encrypted));
            
            $decrypted = lettersoup_decrypt($test_key, $encrypted, $test_aad);
            fprintf(STDERR, "   Decrypted: %s\n", $decrypted);
            fprintf(STDERR, "   Match: %s\n", $decrypted === $test_plaintext ? "✓" : "✗");
        } catch (Exception $e) {
            fprintf(STDERR, "   ✗ Error: %s\n", $e->getMessage());
        }
        
        // Test with empty AAD
        fprintf(STDERR, "\n2. Test with empty AAD:\n");
        try {
            $encrypted = lettersoup_encrypt($test_key, $test_plaintext, '');
            $decrypted = lettersoup_decrypt($test_key, $encrypted, '');
            fprintf(STDERR, "   Match: %s\n", $decrypted === $test_plaintext ? "✓" : "✗");
        } catch (Exception $e) {
            fprintf(STDERR, "   ✗ Error: %s\n", $e->getMessage());
        }
        
        // Test with wrong AAD
        fprintf(STDERR, "\n3. Test with wrong AAD (should fail):\n");
        try {
            $encrypted = lettersoup_encrypt($test_key, $test_plaintext, 'correct_aad');
            $decrypted = lettersoup_decrypt($test_key, $encrypted, 'wrong_aad');
            fprintf(STDERR, "   ✗ Decrypted with wrong AAD (should have failed!)\n");
        } catch (Exception $e) {
            fprintf(STDERR, "   ✓ Authentication failed as expected: %s\n", $e->getMessage());
        }
        
        fprintf(STDERR, "\n✓ Self-test completed\n");
    }
    
    public function info($key_hex = null) {
        if ($key_hex) {
            try {
                $temp = new Curupira1_CLI($key_hex);
                $key = $temp->key;
                $key_len = strlen($key);
                $key_bits = $key_len * 8;
                
                fprintf(STDERR, "Curupira1 Block Cipher Information\n");
                fprintf(STDERR, "====================================\n\n");
                fprintf(STDERR, "Key size: %d bytes (%d bits)\n", $key_len, $key_bits);
                fprintf(STDERR, "Block size: %d bytes\n", Curupira1Block::BLOCK_SIZE);
                fprintf(STDERR, "Mode: LetterSoup AEAD\n");
                fprintf(STDERR, "Authentication: Marvin MAC\n");
                fprintf(STDERR, "Tag size: 96 bits (12 bytes)\n");
                fprintf(STDERR, "Nonce size: 96 bits (12 bytes)\n\n");
                fprintf(STDERR, "Key (hex): %s\n", bin2hex($key));
                
                if ($key_len === 12) {
                    fprintf(STDERR, "Rounds: 10\n");
                } elseif ($key_len === 18) {
                    fprintf(STDERR, "Rounds: 14\n");
                } elseif ($key_len === 24) {
                    fprintf(STDERR, "Rounds: 18\n");
                }
            } catch (Exception $e) {
                fprintf(STDERR, "✖ Error: %s\n", $e->getMessage());
                exit(1);
            }
        } else {
            fprintf(STDERR, "Curupira1 Block Cipher Information\n");
            fprintf(STDERR, "====================================\n\n");
            fprintf(STDERR, "Block size: %d bytes\n", Curupira1Block::BLOCK_SIZE);
            fprintf(STDERR, "Mode: LetterSoup AEAD\n");
            fprintf(STDERR, "Authentication: Marvin MAC\n");
            fprintf(STDERR, "Tag size: 96 bits (12 bytes)\n");
            fprintf(STDERR, "Nonce size: 96 bits (12 bytes)\n\n");
            fprintf(STDERR, "Valid key sizes: 12, 18 or 24 bytes (96, 144 or 192 bits)\n");
            fprintf(STDERR, "Rounds: 10 (96 bits), 14 (144 bits), 18 (192 bits)\n");
        }
    }
}

// ====================================================================
// CLI PARSING
// ====================================================================

function normalize_hex_key($key_hex) {
    $key_hex = preg_replace('/[^0-9a-fA-F]/', '', $key_hex);
    if (strlen($key_hex) % 2 !== 0) {
        $key_hex = '0' . $key_hex;
    }
    return $key_hex;
}

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
            case '--encrypt':
            case '-e':
                $args['action'] = 'encrypt';
                break;
                
            case 'decrypt':
            case '--decrypt':
            case '-d':
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
                    $args['key'] = normalize_hex_key($argv[++$i]);
                }
                break;
                
            case '--infile':
            case '--in':
            case '-f':
                if ($i + 1 < count($argv)) {
                    $args['infile'] = $argv[++$i];
                }
                break;
                
            case '--outfile':
            case '--out':
            case '-o':
                if ($i + 1 < count($argv)) {
                    $args['outfile'] = $argv[++$i];
                }
                break;
                
            case '--aad':
            case '-a':
                if ($i + 1 < count($argv)) {
                    $args['aad'] = $argv[++$i];
                }
                break;
                
            case '--help':
            case '-h':
                $args['help'] = true;
                break;
                
            case '--':
                break 2;
                
            default:
                if ($args['action'] === null && !str_starts_with($argv[$i], '-')) {
                    $args['action'] = $argv[$i];
                } elseif ($args['key'] === null && !str_starts_with($argv[$i], '-') && 
                        $i > 1 && $argv[$i-1] === $args['action']) {
                    $args['key'] = normalize_hex_key($argv[$i]);
                }
                break;
        }
    }
    
    return $args;
}

function print_help() {
    $script = basename(__FILE__);
    fprintf(STDERR, "Curupira1 CLI Tool - LetterSoup AEAD Mode\n");
    fprintf(STDERR, "=========================================\n\n");
    fprintf(STDERR, "Usage:\n");
    fprintf(STDERR, "  %s encrypt KEY_HEX [OPTIONS]\n", $script);
    fprintf(STDERR, "  %s decrypt KEY_HEX [OPTIONS]\n", $script);
    fprintf(STDERR, "  %s test\n", $script);
    fprintf(STDERR, "  %s info [KEY_HEX]\n", $script);
    fprintf(STDERR, "\nCommands:\n");
    fprintf(STDERR, "  encrypt    - Encrypt data using LetterSoup AEAD\n");
    fprintf(STDERR, "  decrypt    - Decrypt data using LetterSoup AEAD\n");
    fprintf(STDERR, "  test       - Run self-test\n");
    fprintf(STDERR, "  info       - Show key information\n");
    fprintf(STDERR, "\nOptions:\n");
    fprintf(STDERR, "  -k, --key HEX        Encryption key (12, 18 or 24 bytes in hex)\n");
    fprintf(STDERR, "  -f, --infile FILE    Input file (stdin if not provided)\n");
    fprintf(STDERR, "  -o, --outfile FILE   Output file (stdout if not provided)\n");
    fprintf(STDERR, "  -a, --aad TEXT       Additional authenticated data\n");
    fprintf(STDERR, "  -h, --help           Show this help\n");
    fprintf(STDERR, "\nKey sizes:\n");
    fprintf(STDERR, "  12 bytes (96 bits)  - 10 rounds\n");
    fprintf(STDERR, "  18 bytes (144 bits) - 14 rounds\n");
    fprintf(STDERR, "  24 bytes (192 bits) - 18 rounds\n");
    fprintf(STDERR, "\nExamples:\n");
    fprintf(STDERR, "  Encrypt file:    %s encrypt 0123456789abcdef01234567 -f plain.txt -o encrypted.bin -a 'metadata'\n", $script);
    fprintf(STDERR, "  Decrypt file:    %s decrypt 0123456789abcdef01234567 -f encrypted.bin -o decrypted.txt -a 'metadata'\n", $script);
    fprintf(STDERR, "  Encrypt stdin:   echo 'Hello World' | %s encrypt 0123456789abcdef01234567\n", $script);
    fprintf(STDERR, "  Self-test:       %s test\n", $script);
}

function main() {
    $args = parse_cli_args();
    
    if ($args['help']) {
        print_help();
        exit(0);
    }
    
    // Handle test command
    if ($args['test']) {
        $cli = new Curupira1_CLI();
        $cli->test();
        exit(0);
    }
    
    // Handle info command
    if ($args['info']) {
        $cli = new Curupira1_CLI();
        $cli->info($args['key']);
        exit(0);
    }
    
    // Validate action and key
    if (!$args['action']) {
        fprintf(STDERR, "✖ Error: No action specified (encrypt or decrypt)\n");
        print_help();
        exit(1);
    }
    
    if (!$args['key']) {
        fprintf(STDERR, "✖ Error: Key not specified\n");
        print_help();
        exit(1);
    }
    
    try {
        $cli = new Curupira1_CLI($args['key']);
        
        if ($args['action'] === 'encrypt') {
            $cli->encrypt($args['infile'], $args['outfile'], $args['aad']);
        } elseif ($args['action'] === 'decrypt') {
            $cli->decrypt($args['infile'], $args['outfile'], $args['aad']);
        } else {
            fprintf(STDERR, "✖ Error: Unknown action '%s'\n", $args['action']);
            print_help();
            exit(1);
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
