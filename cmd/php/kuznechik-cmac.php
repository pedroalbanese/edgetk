#!/usr/bin/env php
<?php
/**
 * Kuznechik CMAC Command Line Interface
 * Baseado em NIST SP 800-38B
 * ARQUIVO INDEPENDENTE - Contém a classe Kuznechik completa
 */

// ============================================================
// CLASSE KUZNECHIK
// ============================================================

class Kuznechik {
    public const BLOCK_SIZE = 16;
    private static $initialized = false;
    
    private static $Pi_table = [
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
        0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
        0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
        0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
        0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
        0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
        0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
        0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
        0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
        0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
        0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
        0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
        0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
        0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
        0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    ];
    
    private static $Pi_inverse_table = [
        0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
        0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
        0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
        0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
        0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
        0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
        0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
        0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
        0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
        0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
        0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
        0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
        0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
        0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
        0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
        0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
        0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
        0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
        0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
        0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
        0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
        0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
        0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
        0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
        0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
        0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
        0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
        0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
        0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
        0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
        0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
    ];
    
    private static $L_vector = [0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01];
    private static $LS_enc_lookup = [];
    private static $L_inv_lookup = [];
    private static $SL_dec_lookup = [];
    private $enc_keys;
    private $dec_keys;
    private static $gf_mul_cache = [];
    
    private static function gf2_mul($x, $y) {
        $key = ($x << 8) | $y;
        if (isset(self::$gf_mul_cache[$key])) {
            return self::$gf_mul_cache[$key];
        }
        $z = 0;
        while ($y != 0) {
            if ($y & 1) $z ^= $x;
            if ($x & 0x80) $x = ($x << 1) ^ 0xC3;
            else $x = $x << 1;
            $y >>= 1;
        }
        $result = $z & 0xFF;
        self::$gf_mul_cache[$key] = $result;
        return $result;
    }
    
    private static function L(array $block) {
        $block = array_values($block);
        for ($j = 0; $j < 16; $j++) {
            $x = $block[15];
            for ($i = 14; $i >= 0; $i--) {
                $block[$i + 1] = $block[$i];
                $x ^= self::gf2_mul($block[$i], self::$L_vector[$i]);
            }
            $block[0] = $x;
        }
        return $block;
    }
    
    private static function L_inv(array $block) {
        $block = array_values($block);
        for ($j = 0; $j < 16; $j++) {
            $x = $block[0];
            for ($i = 0; $i < 15; $i++) {
                $block[$i] = $block[$i + 1];
                $x ^= self::gf2_mul($block[$i], self::$L_vector[$i]);
            }
            $block[15] = $x;
        }
        return $block;
    }
    
    private static function stretchKey(array $key) {
        $x = array_slice($key, 0, 16);
        $y = array_slice($key, 16, 16);
        $rkeys = [];
        $rkeys[0] = $x;
        $rkeys[1] = $y;
        
        for ($i = 1; $i <= 32; $i++) {
            $C = array_fill(0, 16, 0);
            $C[15] = $i;
            $C = self::L($C);
            
            $z = array_fill(0, 16, 0);
            for ($k = 0; $k < 16; $k++) {
                $z[$k] = self::$Pi_table[$x[$k] ^ $C[$k]];
            }
            $z = self::L($z);
            for ($k = 0; $k < 16; $k++) {
                $z[$k] ^= $y[$k];
            }
            $y = $x;
            $x = $z;
            
            if ($i % 8 == 0) {
                $rkeys[$i >> 2] = $x;
                $rkeys[($i >> 2) + 1] = $y;
            }
        }
        return $rkeys;
    }
    
    private static function getDecryptRoundKeys(array $rkeys) {
        $rkeys_L = [];
        for ($k = 1; $k < 10; $k++) {
            $rkeys_L[$k] = self::L_inv($rkeys[$k]);
        }
        $rkeys_L[0] = $rkeys[0];
        return $rkeys_L;
    }
    
    private static function encryptK(array $rkeys, array $block) {
        $ct = array_values($block);
        
        for ($i = 0; $i < 9; $i++) {
            for ($k = 0; $k < 16; $k++) {
                $ct[$k] ^= $rkeys[$i][$k];
            }
            
            $r = array_fill(0, 16, 0);
            for ($k = 0; $k < 16; $k++) {
                $r[$k] = self::$LS_enc_lookup[0][$ct[0]][$k];
            }
            for ($j = 1; $j <= 15; $j++) {
                for ($k = 0; $k < 16; $k++) {
                    $r[$k] ^= self::$LS_enc_lookup[$j][$ct[$j]][$k];
                }
            }
            $ct = $r;
        }
        
        for ($k = 0; $k < 16; $k++) {
            $ct[$k] ^= $rkeys[9][$k];
        }
        
        return $ct;
    }
    
    private static function initCipher() {
        if (self::$initialized) return;
        
        for ($i = 0; $i < 16; $i++) {
            for ($j = 0; $j < 256; $j++) {
                $x = array_fill(0, 16, 0);
                $x[$i] = self::$Pi_table[$j];
                $x = self::L($x);
                self::$LS_enc_lookup[$i][$j] = $x;
                
                $x = array_fill(0, 16, 0);
                $x[$i] = $j;
                $x = self::L_inv($x);
                self::$L_inv_lookup[$i][$j] = $x;
                
                $x = array_fill(0, 16, 0);
                $x[$i] = self::$Pi_inverse_table[$j];
                $x = self::L_inv($x);
                self::$SL_dec_lookup[$i][$j] = $x;
            }
        }
        
        self::$initialized = true;
    }
    
    public function __construct($key) {
        if (strlen($key) !== 32) {
            throw new Exception("Kuznyechik cipher: invalid key size! Must be 32 bytes - got: " . strlen($key));
        }
        
        self::initCipher();
        
        $keyArr = array_values(unpack('C*', $key));
        $this->enc_keys = self::stretchKey($keyArr);
        $this->dec_keys = self::getDecryptRoundKeys($this->enc_keys);
    }
    
    public function encryptBlock($block) {
        if (strlen($block) < self::BLOCK_SIZE) {
            throw new Exception("Input length less than full block!");
        }
        
        $blockArr = array_values(unpack('C*', substr($block, 0, self::BLOCK_SIZE)));
        $result = self::encryptK($this->enc_keys, $blockArr);
        return pack('C*', ...$result);
    }
}

// ============================================================
// CLASSE KUZNECHIK CMAC
// ============================================================

class KuznechikCMAC {
    private $cipher;
    private $K1;
    private $K2;
    
    public function __construct($cipher) {
        $this->cipher = $cipher;
        $this->_generate_subkeys();
    }
    
    private function _generate_subkeys() {
        $zero_block = str_repeat("\x00", 16);
        $L = $this->cipher->encryptBlock($zero_block);
        $this->K1 = $this->_left_shift_and_reduce($L);
        $this->K2 = $this->_left_shift_and_reduce($this->K1);
    }
    
    private function _left_shift_and_reduce($block) {
        $bytes = array_values(unpack('C*', $block));
        $result = array_fill(0, 16, 0);
        
        $msb = ($bytes[0] & 0x80) ? 1 : 0;
        
        for ($i = 0; $i < 15; $i++) {
            $result[$i] = (($bytes[$i] << 1) & 0xFF) | (($bytes[$i + 1] >> 7) & 0x01);
        }
        $result[15] = ($bytes[15] << 1) & 0xFF;
        
        if ($msb) {
            $result[15] ^= 0x87;
        }
        
        return pack('C*', ...$result);
    }
    
    private function _pad_block($block) {
        $padded = $block . "\x80";
        while (strlen($padded) < 16) {
            $padded .= "\x00";
        }
        return substr($padded, 0, 16);
    }
    
    public function generate($message, $tag_size = 16) {
        if ($tag_size < 1 || $tag_size > 16) {
            throw new Exception("tag_size must be between 1 and 16 bytes");
        }
        
        $message_len = strlen($message);
        if ($message_len === 0) {
            // Mensagem vazia
            $blocks = [''];
            $num_blocks = 1;
            $last_block_full = false;
        } else {
            $blocks = str_split($message, 16);
            $num_blocks = count($blocks);
            $last_block_full = ($message_len % 16 == 0);
        }
        
        // Processa o último bloco
        if (!$last_block_full) {
            $last_block = $this->_pad_block($blocks[$num_blocks - 1]);
            $blocks[$num_blocks - 1] = $last_block;
            $key = $this->K2;
        } else {
            $key = $this->K1;
        }
        
        $X = str_repeat("\x00", 16);
        
        // Processa todos os blocos exceto o último
        for ($i = 0; $i < $num_blocks - 1; $i++) {
            $xored = '';
            for ($j = 0; $j < 16; $j++) {
                $xored .= chr(ord($X[$j]) ^ ord($blocks[$i][$j]));
            }
            $X = $this->cipher->encryptBlock($xored);
        }
        
        // Processa o último bloco com XOR da subchave
        $last_index = $num_blocks - 1;
        $xored = '';
        for ($j = 0; $j < 16; $j++) {
            $xored .= chr(ord($X[$j]) ^ ord($blocks[$last_index][$j]) ^ ord($key[$j]));
        }
        $X = $this->cipher->encryptBlock($xored);
        
        return substr($X, 0, $tag_size);
    }
    
    public function verify($message, $tag, $tag_size = 16) {
        $expected_tag = $this->generate($message, $tag_size);
        return hash_equals($tag, $expected_tag);
    }
}

// ============================================================
// CLI INTERFACE
// ============================================================

function printHelp() {
    echo "Kuznechik CMAC CLI\n";
    echo "==================\n\n";
    echo "SYNOPSIS\n";
    echo "    php " . basename(__FILE__) . " [OPTIONS]\n\n";
    echo "DESCRIPTION\n";
    echo "    Generate or verify CMAC (Cipher-based Message Authentication Code)\n";
    echo "    using the Kuznechik block cipher (GOST 34.12-2015).\n\n";
    echo "OPTIONS\n";
    echo "    -g, --generate          Generate CMAC tag\n";
    echo "    -v, --verify            Verify CMAC tag\n";
    echo "    -m, --message TEXT      Input message\n";
    echo "    -M, --message-file FILE Read message from file\n";
    echo "    -k, --key KEY           Encryption key (32 bytes hex - 64 chars)\n";
    echo "    -K, --key-file FILE     Read key from file\n";
    echo "    -t, --tag TAG           CMAC tag for verification (hex)\n";
    echo "    -T, --tag-file FILE     Read tag from file\n";
    echo "    -s, --size SIZE         Tag size in bytes (1-16, default: 16)\n";
    echo "    -q, --quiet             Quiet mode (no output except result)\n";
    echo "    -h, --help              Display this help\n\n";
    echo "EXAMPLES\n";
    echo "    Generate CMAC:\n";
    echo "        php " . basename(__FILE__) . " -g -m \"secret data\" -k 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n\n";
    echo "    Verify CMAC:\n";
    echo "        php " . basename(__FILE__) . " -v -m \"secret data\" -k 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF \\\n";
    echo "            -t a1b2c3d4e5f67890a1b2c3d4e5f67890\n\n";
    echo "    Read from files:\n";
    echo "        php " . basename(__FILE__) . " -g -M data.txt -K key.bin -s 12\n";
    exit(0);
}

function readInput($source) {
    if ($source === '-') {
        return stream_get_contents(STDIN);
    }
    
    if (file_exists($source)) {
        return file_get_contents($source);
    }
    
    return $source;
}

function main() {
    $args = getopt("gvm:M:k:K:t:T:s:qh", [
        "generate",
        "verify",
        "message:",
        "message-file:",
        "key:",
        "key-file:",
        "tag:",
        "tag-file:",
        "size:",
        "quiet",
        "help"
    ]);
    
    if (isset($args['h']) || isset($args['help'])) {
        printHelp();
    }
    
    $generate = isset($args['g']) || isset($args['generate']);
    $verify = isset($args['v']) || isset($args['verify']);
    $quiet = isset($args['q']) || isset($args['quiet']);
    $tag_size = isset($args['s']) ? (int)$args['s'] : (isset($args['size']) ? (int)$args['size'] : 16);
    
    if ($tag_size < 1 || $tag_size > 16) {
        fwrite(STDERR, "Error: Tag size must be between 1 and 16\n");
        exit(1);
    }
    
    if (!$generate && !$verify) {
        fwrite(STDERR, "Error: Specify operation mode (--generate or --verify)\n");
        exit(1);
    }
    
    if ($generate && $verify) {
        fwrite(STDERR, "Error: Cannot both generate and verify\n");
        exit(1);
    }
    
    // Get message
    $message = '';
    if (isset($args['m']) || isset($args['message'])) {
        $message = $args['m'] ?? $args['message'];
        $message = readInput($message);
    } elseif (isset($args['M']) || isset($args['message-file'])) {
        $file = $args['M'] ?? $args['message-file'];
        $message = readInput($file);
    }
    
    if (empty($message) && $message !== '0') {
        fwrite(STDERR, "Error: No message provided\n");
        exit(1);
    }
    
    // Get key
    $key = '';
    if (isset($args['k']) || isset($args['key'])) {
        $key = $args['k'] ?? $args['key'];
        $key = readInput($key);
        
        // Se a chave está em hex, converte para binário
        if (strlen($key) === 64 && ctype_xdigit($key)) {
            $key = hex2bin($key);
        }
    } elseif (isset($args['K']) || isset($args['key-file'])) {
        $file = $args['K'] ?? $args['key-file'];
        $key = readInput($file);
    }
    
    if (strlen($key) !== 32) {
        fwrite(STDERR, "Error: Key must be 32 bytes (64 hex characters)\n");
        fwrite(STDERR, "Key length: " . strlen($key) . " bytes\n");
        exit(1);
    }
    
    // Create cipher and CMAC
    try {
        $cipher = new Kuznechik($key);
        $cmac = new KuznechikCMAC($cipher);
    } catch (Exception $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
    
    // Perform operation
    if ($generate) {
        $tag = $cmac->generate($message, $tag_size);
        echo bin2hex($tag) . "\n";
        exit(0);
    }
    
    if ($verify) {
        // Get tag for verification
        $tag = '';
        if (isset($args['t']) || isset($args['tag'])) {
            $tag = $args['t'] ?? $args['tag'];
            $tag = readInput($tag);
        } elseif (isset($args['T']) || isset($args['tag-file'])) {
            $file = $args['T'] ?? $args['tag-file'];
            $tag = readInput($file);
        }
        
        if (empty($tag)) {
            fwrite(STDERR, "Error: No tag provided for verification\n");
            exit(1);
        }
        
        // Se a tag está em hex, converte para binário
        if (strlen($tag) === $tag_size * 2 && ctype_xdigit($tag)) {
            $tag = hex2bin($tag);
        }
        
        if (strlen($tag) !== $tag_size) {
            fwrite(STDERR, "Error: Tag size mismatch. Expected " . $tag_size . " bytes, got " . strlen($tag) . "\n");
            exit(1);
        }
        
        $isValid = $cmac->verify($message, $tag, $tag_size);
        
        if (!$quiet) {
            echo $isValid ? "CMAC verification: VALID\n" : "CMAC verification: INVALID\n";
        }
        
        exit($isValid ? 0 : 1);
    }
}

// Run the application
if (PHP_SAPI === 'cli') {
    main();
} else {
    echo "This script must be run from the command line.\n";
    exit(1);
}
?>
