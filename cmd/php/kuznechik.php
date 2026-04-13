<?php

/**
 * GOST 34.12-2015 128-bit Кузнечик (Kuznechik) block cipher
 * PHP implementation with CTR and MGM modes
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
    
    /**
     * GF(2^8) multiplication
     */
    private static function gf2_mul($x, $y) {
        $z = 0;
        while ($y != 0) {
            if ($y & 1) {
                $z ^= $x;
            }
            if ($x & 0x80) {
                $x = ($x << 1) ^ 0xC3;
            } else {
                $x = $x << 1;
            }
            $y >>= 1;
        }
        return $z & 0xFF;
    }
    
    /**
     * L transformation
     */
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
    
    /**
     * Inverse L transformation
     */
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
    
    /**
     * Key stretching
     */
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
    
    /**
     * Get decrypt round keys
     */
    private static function getDecryptRoundKeys(array $rkeys) {
        $rkeys_L = [];
        for ($k = 1; $k < 10; $k++) {
            $rkeys_L[$k] = self::L_inv($rkeys[$k]);
        }
        $rkeys_L[0] = $rkeys[0];
        return $rkeys_L;
    }
    
    /**
     * Encrypt with round keys
     */
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
    
    /**
     * Decrypt with round keys
     */
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
    
    /**
     * Initialize lookup tables
     */
    private static function initCipher() {
        if (self::$initialized) {
            return;
        }
        
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
    
    /**
     * Constructor
     */
    public function __construct($key) {
        if (strlen($key) !== 32) {
            throw new Exception("Kuznyechik cipher: invalid key size! Must be 32 bytes - got: " . strlen($key));
        }
        
        self::initCipher();
        
        $keyArr = array_values(unpack('C*', $key));
        $this->enc_keys = self::stretchKey($keyArr);
        $this->dec_keys = self::getDecryptRoundKeys($this->enc_keys);
    }
    
    /**
     * Encrypt a single block
     */
    public function encryptBlock($block) {
        if (strlen($block) < self::BLOCK_SIZE) {
            throw new Exception("Input length less than full block!");
        }
        
        $blockArr = array_values(unpack('C*', substr($block, 0, self::BLOCK_SIZE)));
        $result = self::encryptK($this->enc_keys, $blockArr);
        return pack('C*', ...$result);
    }
    
    /**
     * Decrypt a single block
     */
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
            
            // Increment counter
            $counterArr = array_values(unpack('C*', $counter));
            for ($j = self::BLOCK_SIZE - 1; $j >= 0; $j--) {
                $counterArr[$j]++;
                if ($counterArr[$j] !== 0) {
                    break;
                }
            }
            $counter = pack('C*', ...$counterArr);
        }
        
        return $result;
    }
    
    /**
     * GF(2^128) multiplication for MGM mode
     */
    private static function gf128Mul($x, $y) {
        $xArr = array_values(unpack('C*', $x));
        $yArr = array_values(unpack('C*', $y));
        
        $x1 = self::bytesToUint64($xArr, 0);
        $x0 = self::bytesToUint64($xArr, 8);
        $y1 = self::bytesToUint64($yArr, 0);
        $y0 = self::bytesToUint64($yArr, 8);
        
        $t = $y0;
        $z0 = 0;
        $z1 = 0;
        
        for ($i = 0; $i < 64; $i++) {
            if ($t & 1) {
                $z0 ^= $x0;
                $z1 ^= $x1;
            }
            $t >>= 1;
            $sign = ($x1 >> 63) & 1;
            $x1 = ($x1 << 1) | ($x0 >> 63);
            $x0 = ($x0 << 1) & 0xFFFFFFFFFFFFFFFF;
            if ($sign) {
                $x0 ^= 0x87;
            }
        }
        
        $t = $y1;
        for ($i = 0; $i < 63; $i++) {
            if ($t & 1) {
                $z0 ^= $x0;
                $z1 ^= $x1;
            }
            $t >>= 1;
            $sign = ($x1 >> 63) & 1;
            $x1 = ($x1 << 1) | ($x0 >> 63);
            $x0 = ($x0 << 1) & 0xFFFFFFFFFFFFFFFF;
            if ($sign) {
                $x0 ^= 0x87;
            }
        }
        
        if ($t & 1) {
            $z0 ^= $x0;
            $z1 ^= $x1;
        }
        
        $result = '';
        $result .= pack('J', $z1);  // Big-endian
        $result .= pack('J', $z0);
        return $result;
    }
    
    private static function bytesToUint64($bytes, $offset) {
        $val = 0;
        for ($i = 0; $i < 8; $i++) {
            $val = ($val << 8) | $bytes[$offset + $i];
        }
        return $val;
    }
    
    /**
     * Increment lower half of the block (for MGM)
     */
    private static function incrHalf(&$data) {
        $len = 8;
        for ($i = $len - 1; $i >= 0; $i--) {
            $data[$i]++;
            if ($data[$i] !== 0) {
                break;
            }
        }
    }
    
    /**
     * XOR two strings
     */
    private static function xorBytes($dst, $src1, $src2) {
        $len = strlen($src1);
        for ($i = 0; $i < $len; $i++) {
            $dst[$i] = $src1[$i] ^ $src2[$i];
        }
    }
    
    /**
     * MGM AEAD mode - authentication
     */
    private function mgmAuth($text, $additionalData, $nonce, &$tag) {
        $adLen = strlen($additionalData);
        $textLen = strlen($text);
        
        $icn = substr($nonce, 0, self::BLOCK_SIZE);
        $icnArr = array_values(unpack('C*', $icn));
        $icnArr[0] |= 0x80;
        $icn = pack('C*', ...$icnArr);
        
        $z = $icn;
        $sum = str_repeat("\x00", self::BLOCK_SIZE);
        $bufP = $this->encryptBlock($z);
        
        // Process additional data
        $ad = $additionalData;
        while (strlen($ad) >= self::BLOCK_SIZE) {
            $bufC = $this->encryptBlock($bufP);
            $sum = self::gf128Mul($bufC, substr($ad, 0, self::BLOCK_SIZE));
            $bufPArr = array_values(unpack('C*', $bufP));
            self::incrHalf($bufPArr);
            $bufP = pack('C*', ...$bufPArr);
            $ad = substr($ad, self::BLOCK_SIZE);
        }
        
        if (strlen($ad) > 0) {
            $padded = str_pad($ad, self::BLOCK_SIZE, "\x00");
            $bufC = $this->encryptBlock($bufP);
            $sum = self::gf128Mul($bufC, $padded);
            $bufPArr = array_values(unpack('C*', $bufP));
            self::incrHalf($bufPArr);
            $bufP = pack('C*', ...$bufPArr);
        }
        
        // Process ciphertext
        $ct = $text;
        while (strlen($ct) >= self::BLOCK_SIZE) {
            $bufC = $this->encryptBlock($bufP);
            $sum = self::gf128Mul($bufC, substr($ct, 0, self::BLOCK_SIZE));
            $bufPArr = array_values(unpack('C*', $bufP));
            self::incrHalf($bufPArr);
            $bufP = pack('C*', ...$bufPArr);
            $ct = substr($ct, self::BLOCK_SIZE);
        }
        
        if (strlen($ct) > 0) {
            $padded = str_pad($ct, self::BLOCK_SIZE, "\x00");
            $bufC = $this->encryptBlock($bufP);
            $sum = self::gf128Mul($bufC, $padded);
            $bufPArr = array_values(unpack('C*', $bufP));
            self::incrHalf($bufPArr);
            $bufP = pack('C*', ...$bufPArr);
        }
        
        // Finalize: H_{h+q+1} = E_K(Z_{h+q+1})
        $bufP = $this->encryptBlock($bufP);
        
        // len(A) || len(C) in bits
        $lenBlock = pack('J', $adLen * 8) . pack('J', $textLen * 8);
        $sum = self::gf128Mul($lenBlock, $bufP);
        
        // E_K(sum)
        $tag = $this->encryptBlock($sum);
        $tag = substr($tag, 0, self::BLOCK_SIZE);
    }
    
    /**
     * MGM mode encryption (authenticated encryption)
     */
    public function mgmEncrypt($plaintext, $nonce, $additionalData, &$tag) {
        if (strlen($nonce) !== self::BLOCK_SIZE) {
            throw new Exception("Nonce must be exactly " . self::BLOCK_SIZE . " bytes");
        }
        
        $icn = $nonce;
        $icnArr = array_values(unpack('C*', $icn));
        $icnArr[0] &= 0x7F;
        $icn = pack('C*', ...$icnArr);
        
        $y = $icn;
        $ciphertext = '';
        
        for ($i = 0; $i < strlen($plaintext); $i += self::BLOCK_SIZE) {
            $ekY = $this->encryptBlock($y);
            $chunk = substr($plaintext, $i, self::BLOCK_SIZE);
            $cipherChunk = $chunk ^ substr($ekY, 0, strlen($chunk));
            $ciphertext .= $cipherChunk;
            
            // Increment lower half of Y
            $yArr = array_values(unpack('C*', $y));
            self::incrHalf($yArr);
            $y = pack('C*', ...$yArr);
        }
        
        $this->mgmAuth($ciphertext, $additionalData, $nonce, $tag);
        return $ciphertext;
    }
    
    /**
     * MGM mode decryption (authenticated decryption)
     */
    public function mgmDecrypt($ciphertext, $nonce, $additionalData, $tag) {
        if (strlen($nonce) !== self::BLOCK_SIZE) {
            throw new Exception("Nonce must be exactly " . self::BLOCK_SIZE . " bytes");
        }
        
        // Verify tag first
        $computedTag = '';
        $this->mgmAuth($ciphertext, $additionalData, $nonce, $computedTag);
        if (!hash_equals(substr($computedTag, 0, self::BLOCK_SIZE), substr($tag, 0, self::BLOCK_SIZE))) {
            throw new Exception("Invalid authentication tag");
        }
        
        $icn = $nonce;
        $icnArr = array_values(unpack('C*', $icn));
        $icnArr[0] &= 0x7F;
        $icn = pack('C*', ...$icnArr);
        
        $y = $icn;
        $plaintext = '';
        
        for ($i = 0; $i < strlen($ciphertext); $i += self::BLOCK_SIZE) {
            $ekY = $this->encryptBlock($y);
            $chunk = substr($ciphertext, $i, self::BLOCK_SIZE);
            $plaintext .= $chunk ^ substr($ekY, 0, strlen($chunk));
            
            $yArr = array_values(unpack('C*', $y));
            self::incrHalf($yArr);
            $y = pack('C*', ...$yArr);
        }
        
        return $plaintext;
    }
}

// Example usage:
/*
$key = str_repeat("\x00", 32);
$cipher = new Kuznechik($key);

// CTR mode
$iv = str_repeat("\x00", 16);
$plaintext = "Hello, World! This is a test message.";
$ciphertext = $cipher->ctr($plaintext, $iv);
$decrypted = $cipher->ctr($ciphertext, $iv);

// MGM mode (AEAD)
$nonce = str_repeat("\x00", 16);
$additionalData = "header data";
$tag = '';
$ciphertext = $cipher->mgmEncrypt($plaintext, $nonce, $additionalData, $tag);
$decrypted = $cipher->mgmDecrypt($ciphertext, $nonce, $additionalData, $tag);
*/
?>
