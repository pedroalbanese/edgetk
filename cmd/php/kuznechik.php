<?php

/**
 * GOST 34.12-2015 128-bit Кузнечик (Kuznechik) block cipher
 * PHP implementation with CTR and GCM modes
 */

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
    
    private static function gf2_mul($x, $y) {
        $z = 0;
        while ($y != 0) {
            if ($y & 1) $z ^= $x;
            if ($x & 0x80) $x = ($x << 1) ^ 0xC3;
            else $x = $x << 1;
            $y >>= 1;
        }
        return $z & 0xFF;
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
    
    private static function decryptK(array $rkeys, array $block) {
        $pt = array_values($block);
        
        $r = array_fill(0, 16, 0);
        for ($k = 0; $k < 16; $k++) {
            $r[$k] = self::$L_inv_lookup[0][$pt[0]][$k];
        }
        for ($j = 1; $j <= 15; $j++) {
            for ($k = 0; $k < 16; $k++) {
                $r[$k] ^= self::$L_inv_lookup[$j][$pt[$j]][$k];
            }
        }
        $pt = $r;
        
        for ($i = 9; $i > 1; $i--) {
            for ($k = 0; $k < 16; $k++) {
                $pt[$k] ^= $rkeys[$i][$k];
            }
            
            $r = array_fill(0, 16, 0);
            for ($k = 0; $k < 16; $k++) {
                $r[$k] = self::$SL_dec_lookup[0][$pt[0]][$k];
            }
            for ($j = 1; $j <= 15; $j++) {
                for ($k = 0; $k < 16; $k++) {
                    $r[$k] ^= self::$SL_dec_lookup[$j][$pt[$j]][$k];
                }
            }
            $pt = $r;
        }
        
        for ($k = 0; $k < 16; $k++) {
            $pt[$k] ^= $rkeys[1][$k];
        }
        
        for ($k = 0; $k < 16; $k++) {
            $pt[$k] = self::$Pi_inverse_table[$pt[$k]];
        }
        
        for ($k = 0; $k < 16; $k++) {
            $pt[$k] ^= $rkeys[0][$k];
        }
        
        return $pt;
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
    
    public function decryptBlock($block) {
        if (strlen($block) < self::BLOCK_SIZE) {
            throw new Exception("Input length less than full block!");
        }
        
        $blockArr = array_values(unpack('C*', substr($block, 0, self::BLOCK_SIZE)));
        $result = self::decryptK($this->dec_keys, $blockArr);
        return pack('C*', ...$result);
    }
    
    /**
     * CTR mode encryption/decryption (stream mode)
     */
    public function ctr($data, $iv) {
        if (strlen($iv) !== self::BLOCK_SIZE) {
            throw new Exception("IV must be exactly " . self::BLOCK_SIZE . " bytes");
        }
        
        $result = '';
        $counter = $iv;
        
        for ($i = 0; $i < strlen($data); $i += self::BLOCK_SIZE) {
            $keystream = $this->encryptBlock($counter);
            $chunk = substr($data, $i, self::BLOCK_SIZE);
            $result .= $chunk ^ substr($keystream, 0, strlen($chunk));
            
            // Increment counter (big-endian)
            $counterArr = array_values(unpack('C*', $counter));
            for ($j = self::BLOCK_SIZE - 1; $j >= 0; $j--) {
                $counterArr[$j]++;
                if ($counterArr[$j] !== 0) break;
            }
            $counter = pack('C*', ...$counterArr);
        }
        
        return $result;
    }
}

/**
 * Kuznechik GCM Mode Implementation
 * Compatible with EDGE Toolkit
 */
class KuznechikGCM {
    const BLOCK_SIZE = 16;
    
    private $cipher;
    private $nonce;
    private $tag_size;
    private $_ghash_key;
    
    public function __construct($cipher, $nonce = null, $tag_size = 16) {
        if ($tag_size < 12 || $tag_size > 16) {
            throw new Exception("tag_size must be between 12 and 16 bytes");
        }
        
        $this->cipher = $cipher;
        $this->tag_size = $tag_size;
        
        if ($nonce === null) {
            $this->nonce = random_bytes(12);
        } else {
            if (strlen($nonce) !== 12) {
                throw new Exception("Nonce must be exactly 12 bytes for GCM");
            }
            $this->nonce = $nonce;
        }
        
        $this->_init_ghash();
    }
    
    private function _init_ghash() {
        $zero_block = str_repeat("\x00", self::BLOCK_SIZE);
        $this->_ghash_key = $this->cipher->encryptBlock($zero_block);
    }
    
    private function _ghash($data) {
        if (strlen($data) === 0) {
            return str_repeat("\x00", self::BLOCK_SIZE);
        }
        
        if (strlen($data) % self::BLOCK_SIZE !== 0) {
            $padding = self::BLOCK_SIZE - (strlen($data) % self::BLOCK_SIZE);
            $data .= str_repeat("\x00", $padding);
        }
        
        $H = $this->_bytes_to_int128($this->_ghash_key);
        $result = gmp_init(0);
        
        $blocks = str_split($data, self::BLOCK_SIZE);
        foreach ($blocks as $block) {
            $block_int = $this->_bytes_to_int128($block);
            $result = gmp_xor($result, $block_int);
            $result = $this->_gmult($result, $H);
        }
        
        return $this->_int128_to_bytes($result);
    }
    
    private function _gmult($x, $y) {
        $z = gmp_init(0);
        $v = $y;
        
        for ($i = 127; $i >= 0; $i--) {
            // Get i-th bit of x
            $mask = gmp_pow(2, $i);
            if (gmp_cmp(gmp_and($x, $mask), 0) > 0) {
                $z = gmp_xor($z, $v);
            }
            
            // Reduce v if LSB is set
            $lsb = gmp_and($v, 1);
            $v = gmp_div($v, 2); // shift right
            
            if (gmp_cmp($lsb, 0) > 0) {
                $v = gmp_xor($v, gmp_init('0xE1000000000000000000000000000000', 16));
            }
        }
        
        return $z;
    }
    
    private function _bytes_to_int128($bytes) {
        if (strlen($bytes) !== 16) {
            throw new Exception("Input must be 16 bytes");
        }
        
        $hex = bin2hex($bytes);
        return gmp_init('0x' . $hex, 16);
    }
    
    private function _int128_to_bytes($int) {
        $hex = gmp_strval($int, 16);
        $hex = str_pad($hex, 32, '0', STR_PAD_LEFT);
        return hex2bin($hex);
    }
    
    private function _inc32($counter_block) {
        $counter_int = unpack('N', substr($counter_block, 12, 4))[1];
        $counter_int = ($counter_int + 1) & 0xFFFFFFFF;
        return substr($counter_block, 0, 12) . pack('N', $counter_int);
    }
    
    private function _compute_tag($ciphertext, $associated_data) {
        $len_a = strlen($associated_data) * 8;
        $len_c = strlen($ciphertext) * 8;
        
        // Pack as 64-bit big-endian integers
        $len_block = pack('J', $len_a) . pack('J', $len_c);
        
        $auth_data = $associated_data;
        if (strlen($auth_data) % self::BLOCK_SIZE !== 0) {
            $padding = self::BLOCK_SIZE - (strlen($auth_data) % self::BLOCK_SIZE);
            $auth_data .= str_repeat("\x00", $padding);
        }
        
        $cipher_data = $ciphertext;
        if (strlen($cipher_data) % self::BLOCK_SIZE !== 0) {
            $padding = self::BLOCK_SIZE - (strlen($cipher_data) % self::BLOCK_SIZE);
            $cipher_data .= str_repeat("\x00", $padding);
        }
        
        $ghash_input = $auth_data . $cipher_data . $len_block;
        $S = $this->_ghash($ghash_input);
        
        // J0 = nonce || 0x00000001 (for 12-byte nonce)
        if (strlen($this->nonce) == 12) {
            $J0 = $this->nonce . "\x00\x00\x00\x01";
        } else {
            throw new Exception("Nonce must be 12 bytes for GCM");
        }
        
        $tag_full = $this->_gctr($J0, $S);
        return substr($tag_full, 0, $this->tag_size);
    }
    
    private function _gctr($icb, $X) {
        if (strlen($X) === 0) {
            return '';
        }
        
        $n = (int)ceil(strlen($X) / self::BLOCK_SIZE);
        $Y = '';
        $cb = $icb;
        
        for ($i = 0; $i < $n; $i++) {
            $encrypted_cb = $this->cipher->encryptBlock($cb);
            
            if ($i == $n - 1) {
                $block_size = strlen($X) % self::BLOCK_SIZE;
                if ($block_size == 0) {
                    $block_size = self::BLOCK_SIZE;
                }
            } else {
                $block_size = self::BLOCK_SIZE;
            }
            
            $block_start = $i * self::BLOCK_SIZE;
            $X_block = substr($X, $block_start, $block_size);
            
            $Y_block = '';
            for ($j = 0; $j < $block_size; $j++) {
                $Y_block .= chr(ord($X_block[$j]) ^ ord($encrypted_cb[$j]));
            }
            
            $Y .= $Y_block;
            $cb = $this->_inc32($cb);
        }
        
        return $Y;
    }
    
    public function encrypt($plaintext, $associated_data = '') {
        // J0 = nonce || 0x00000001 (for 12-byte nonce)
        if (strlen($this->nonce) == 12) {
            $J0 = $this->nonce . "\x00\x00\x00\x01";
        } else {
            throw new Exception("Nonce must be 12 bytes for GCM");
        }
        
        $cb = $this->_inc32($J0);
        $ciphertext = $this->_gctr($cb, $plaintext);
        $tag = $this->_compute_tag($ciphertext, $associated_data);
        
        return [$ciphertext, $tag];
    }
    
    public function decrypt($ciphertext, $tag, $associated_data = '') {
        $expected_tag = $this->_compute_tag($ciphertext, $associated_data);
        
        if (!$this->_constant_time_compare($tag, $expected_tag)) {
            return null;
        }
        
        // J0 = nonce || 0x00000001 (for 12-byte nonce)
        if (strlen($this->nonce) == 12) {
            $J0 = $this->nonce . "\x00\x00\x00\x01";
        } else {
            throw new Exception("Nonce must be 12 bytes for GCM");
        }
        
        $cb = $this->_inc32($J0);
        $plaintext = $this->_gctr($cb, $ciphertext);
        
        return $plaintext;
    }
    
    private function _constant_time_compare($a, $b) {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        
        $result = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        
        return $result === 0;
    }
    
    public function getNonce() {
        return $this->nonce;
    }
}
?>
