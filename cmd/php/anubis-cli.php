<?php
/**
 * CLI interface for Anubis-GCM
 */

require_once __DIR__ . '/anubis-gcm.php';

class AnubisGCM_CLI {
    private $key;
    private $cipher;
    
    public function __construct($key_hex) {
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
        
        // Valida tamanho da chave para Anubis
        $key_bits = strlen($this->key) * 8;
        $valid_sizes = [128, 160, 192, 224, 256, 288, 320];
        
        if (!in_array($key_bits, $valid_sizes)) {
            throw new Exception(sprintf(
                "Invalid Anubis key size: %d bits. Valid sizes: %s",
                $key_bits,
                implode(', ', $valid_sizes)
            ));
        }
        
        $this->cipher = new Anubis($this->key);
    }
    
    public function run($action, $infile = null, $outfile = null, $aad = '', $nonce_hex = null) {
        if ($action === 'encrypt') {
            // Read input
            if ($infile) {
                $plaintext = file_get_contents($infile);
                if ($plaintext === false) {
                    throw new Exception("Failed to read input file: $infile");
                }
            } else {
                // Read from stdin
                $plaintext = stream_get_contents(STDIN);
            }
            
            if ($nonce_hex) {
                $nonce_hex = preg_replace('/[^0-9a-fA-F]/', '', $nonce_hex);
                if (strlen($nonce_hex) % 2 !== 0) {
                    $nonce_hex = '0' . $nonce_hex;
                }
                $nonce = hex2bin($nonce_hex);
                if ($nonce === false) {
                    throw new Exception("Invalid hex nonce");
                }
                if (strlen($nonce) !== 12) {
                    throw new Exception("Nonce must be 12 bytes (24 hex chars)");
                }
                $gcm = new AnubisGCM($this->cipher, $nonce);
            } else {
                $gcm = new AnubisGCM($this->cipher);
            }
            
            list($ciphertext, $tag) = $gcm->encrypt($plaintext, $aad);
            $output = $gcm->getNonce() . $ciphertext . $tag;
            
            if ($outfile) {
                file_put_contents($outfile, $output);
                fprintf(STDERR, "✓ Encrypted to %s\n", $outfile);
                fprintf(STDERR, "  Nonce: %s\n", bin2hex($gcm->getNonce()));
                fprintf(STDERR, "  Tag: %s\n", bin2hex($tag));
                fprintf(STDERR, "  Output size: %d bytes\n", strlen($output));
            } else {
                echo $output;
            }
            
        } elseif ($action === 'decrypt') {
            // Read input
            if ($infile) {
                $data = file_get_contents($infile);
                if ($data === false) {
                    throw new Exception("Failed to read input file: $infile");
                }
            } else {
                // Read from stdin
                $data = stream_get_contents(STDIN);
            }
            
            // Minimum data needed: nonce (12) + tag (16)
            if (strlen($data) < 28) {
                throw new Exception("Data too short (need at least 28 bytes)");
            }
            
            $nonce = substr($data, 0, 12);
            $tag = substr($data, -16);
            $ciphertext = substr($data, 12, -16);
            
            $gcm = new AnubisGCM($this->cipher, $nonce);
            $plaintext = $gcm->decrypt($ciphertext, $tag, $aad);
            
            if ($plaintext === null) {
                throw new Exception("Authentication failed - invalid tag or corrupted data");
            }
            
            if ($outfile) {
                file_put_contents($outfile, $plaintext);
                fprintf(STDERR, "✓ Decrypted to %s\n", $outfile);
            } else {
                echo $plaintext;
            }
        } else {
            throw new Exception("Unknown action: $action");
        }
    }
}

// Função para validar e corrigir chave hex
function normalize_hex_key($key_hex) {
    // Remove caracteres não hex
    $key_hex = preg_replace('/[^0-9a-fA-F]/', '', $key_hex);
    
    // Garante comprimento par
    if (strlen($key_hex) % 2 !== 0) {
        $key_hex = '0' . $key_hex;
    }
    
    return $key_hex;
}

// CLI parsing
function parse_cli_args() {
    global $argv;
    
    $args = [
        'action' => null,
        'key' => null,
        'infile' => null,
        'outfile' => null,
        'aad' => '',
        'nonce' => null,
        'help' => false
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
                
            case '--key':
            case '-k':
                if ($i + 1 < count($argv)) {
                    $args['key'] = normalize_hex_key($argv[++$i]);
                }
                break;
                
            case '--infile':
            case '-i':
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
                
            case '--aad':
            case '-a':
                if ($i + 1 < count($argv)) {
                    $args['aad'] = $argv[++$i];
                }
                break;
                
            case '--nonce':
            case '-n':
                if ($i + 1 < count($argv)) {
                    $args['nonce'] = normalize_hex_key($argv[++$i]);
                }
                break;
                
            case '--help':
            case '-h':
                $args['help'] = true;
                break;
                
            case '--':
                // Fim das opções
                break 2;
                
            default:
                // Se não começa com -, assume que é a ação ou chave
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
    fprintf(STDERR, "Anubis-GCM CLI Tool\n");
    fprintf(STDERR, "===================\n\n");
    fprintf(STDERR, "Usage:\n");
    fprintf(STDERR, "  %s encrypt KEY_HEX [OPTIONS]\n", $script);
    fprintf(STDERR, "  %s decrypt KEY_HEX [OPTIONS]\n", $script);
    fprintf(STDERR, "\nExamples:\n");
    fprintf(STDERR, "  Encrypt file:    %s encrypt KEY_HEX --infile test.txt --outfile encrypted.bin --aad 'my data'\n", $script);
    fprintf(STDERR, "  Decrypt file:    %s decrypt KEY_HEX --infile encrypted.bin --outfile decrypted.txt --aad 'my data'\n", $script);
    fprintf(STDERR, "\nOptions:\n");
    fprintf(STDERR, "  -i, --infile FILE    Input file (stdin if not provided)\n");
    fprintf(STDERR, "  -o, --outfile FILE   Output file (stdout if not provided)\n");
    fprintf(STDERR, "  -a, --aad TEXT       Additional authenticated data\n");
    fprintf(STDERR, "  -n, --nonce HEX      Nonce in hex (12 bytes = 24 hex chars)\n");
    fprintf(STDERR, "  -h, --help           Show this help\n");
}

function main() {
    $args = parse_cli_args();
    
    if ($args['help']) {
        print_help();
        exit(0);
    }
    
    if (!$args['action'] || !$args['key']) {
        print_help();
        exit(1);
    }
    
    try {
        $cli = new AnubisGCM_CLI($args['key']);
        $cli->run(
            $args['action'],
            $args['infile'],
            $args['outfile'],
            $args['aad'],
            $args['nonce']
        );
    } catch (Exception $e) {
        fprintf(STDERR, "✖ Error: %s\n", $e->getMessage());
        exit(1);
    }
}

if (PHP_SAPI === 'cli') {
    main();
}
