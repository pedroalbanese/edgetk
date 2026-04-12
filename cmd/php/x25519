<?php

class X25519
{
    // 2^255 - 19
    private static $P = '57896044618658097711785492504343953926634992332820282019728792003956564819949';
    
    /**
     * X25519 scalar multiplication
     */
    public static function x25519_scalar_mult($scalar_hex, $u_hex)
    {
        // Decode scalar with clamping
        $a = self::decode_scalar_25519($scalar_hex);
        
        // Decode u-coordinate
        $u_int = self::decode_u_coordinate($u_hex);
        
        // Montgomery ladder
        $x1 = $u_int;
        $x2 = '1';
        $z2 = '0';
        $x3 = $u_int;
        $z3 = '1';
        
        $swap = 0;
        
        // Get bits from LSB to MSB (0 to 254)
        $bits = [];
        for ($i = 0; $i < 255; $i++) {
            $bits[$i] = (int)bcmod(bcdiv($a, bcpow('2', (string)$i)), '2');
        }
        
        // Process bits from 254 to 0
        for ($t = 254; $t >= 0; $t--) {
            $k_t = $bits[$t];
            $swap ^= $k_t;
            
            // Conditional swap
            if ($swap) {
                list($x2, $x3) = array($x3, $x2);
                list($z2, $z3) = array($z3, $z2);
            }
            
            $swap = $k_t;
            
            // Montgomery ladder step
            $A = self::modp_add($x2, $z2);
            $AA = self::modp_sqr($A);
            $B = self::modp_sub($x2, $z2);
            $BB = self::modp_sqr($B);
            $E = self::modp_sub($AA, $BB);
            $C = self::modp_add($x3, $z3);
            $D = self::modp_sub($x3, $z3);
            $DA = self::modp_mul($D, $A);
            $CB = self::modp_mul($C, $B);
            
            $x3 = self::modp_sqr(self::modp_add($DA, $CB));
            $z3 = self::modp_mul($u_int, self::modp_sqr(self::modp_sub($DA, $CB)));
            $x2 = self::modp_mul($AA, $BB);
            $z2 = self::modp_mul($E, self::modp_add($AA, self::modp_mul('121665', $E)));
        }
        
        // Final conditional swap
        if ($swap) {
            list($x2, $x3) = array($x3, $x2);
            list($z2, $z3) = array($z3, $z2);
        }
        
        // Compute result: x2 * z2^(p-2) mod p
        if (bccomp($z2, '0') == 0) {
            return str_repeat('00', 32);
        }
        
        $z2_inv = self::modp_inv($z2);
        $result_int = self::modp_mul($x2, $z2_inv);
        
        return self::encode_u_coordinate($result_int);
    }
    
    /**
     * Decode scalar with clamping
     */
    private static function decode_scalar_25519($scalar_hex)
    {
        if (strlen($scalar_hex) != 64 || !ctype_xdigit($scalar_hex)) {
            throw new Exception("Scalar must be 64 hex characters");
        }
        
        $bytes = hex2bin($scalar_hex);
        if ($bytes === false) {
            throw new Exception("Invalid hex string");
        }
        
        // Apply clamping
        $bytes[0] = chr(ord($bytes[0]) & 0xF8);  // Clear bottom 3 bits
        $bytes[31] = chr((ord($bytes[31]) & 0x7F) | 0x40); // Clear highest bit, set second highest
        
        // Convert to integer (little-endian)
        $result = '0';
        for ($i = 0; $i < 32; $i++) {
            $byte = ord($bytes[$i]);
            $power = bcpow('2', (string)(8 * $i));
            $result = bcadd($result, bcmul((string)$byte, $power));
        }
        
        return $result;
    }
    
    /**
     * Decode u-coordinate
     */
    private static function decode_u_coordinate($u_hex)
    {
        if (strlen($u_hex) != 64 || !ctype_xdigit($u_hex)) {
            throw new Exception("u-coordinate must be 64 hex characters");
        }
        
        $bytes = hex2bin($u_hex);
        if ($bytes === false) {
            throw new Exception("Invalid hex string");
        }
        
        // Clear the high bit for uniformity
        $bytes[31] = chr(ord($bytes[31]) & 0x7F);
        
        // Convert to integer (little-endian)
        $result = '0';
        for ($i = 0; $i < 32; $i++) {
            $byte = ord($bytes[$i]);
            $power = bcpow('2', (string)(8 * $i));
            $result = bcadd($result, bcmul((string)$byte, $power));
        }
        
        return $result;
    }
    
    /**
     * Encode u-coordinate to hex (little-endian)
     */
    private static function encode_u_coordinate($u_int)
    {
        if (bccomp($u_int, '0') < 0 || bccomp($u_int, self::$P) >= 0) {
            throw new Exception("u-coordinate out of range");
        }
        
        $result = '';
        $temp = $u_int;
        for ($i = 0; $i < 32; $i++) {
            $byte = bcmod($temp, '256');
            $result .= str_pad(dechex((int)$byte), 2, '0', STR_PAD_LEFT);
            $temp = bcdiv($temp, '256', 0);
        }
        
        return $result;
    }
    
    /**
     * Modular arithmetic functions
     */
    private static function modp_add($a, $b)
    {
        $sum = bcadd($a, $b);
        if (bccomp($sum, self::$P) >= 0) {
            $sum = bcsub($sum, self::$P);
        }
        return $sum;
    }
    
    private static function modp_sub($a, $b)
    {
        $diff = bcsub($a, $b);
        if (bccomp($diff, '0') < 0) {
            $diff = bcadd($diff, self::$P);
        }
        return $diff;
    }
    
    private static function modp_mul($a, $b)
    {
        return bcmod(bcmul($a, $b), self::$P);
    }
    
    private static function modp_sqr($a)
    {
        return bcmod(bcmul($a, $a), self::$P);
    }
    
    private static function modp_inv($a)
    {
        // a^(p-2) mod p
        return self::modp_pow($a, bcsub(self::$P, '2'));
    }
    
    private static function modp_pow($base, $exp)
    {
        $result = '1';
        $base = bcmod($base, self::$P);
        
        while (bccomp($exp, '0') > 0) {
            if (bcmod($exp, '2') == '1') {
                $result = bcmod(bcmul($result, $base), self::$P);
            }
            $base = bcmod(bcmul($base, $base), self::$P);
            $exp = bcdiv($exp, '2', 0);
        }
        
        return $result;
    }
    
    /**
     * Public key generation
     */
    public static function x25519_get_public_key($private_key_hex)
    {
        // Base point u = 9 in little-endian
        $base_point = '0900000000000000000000000000000000000000000000000000000000000000';
        return self::x25519_scalar_mult($private_key_hex, $base_point);
    }
    
    /**
     * Shared secret calculation
     */
    public static function x25519_shared_secret($private_key_hex, $peer_public_key_hex)
    {
        return self::x25519_scalar_mult($private_key_hex, $peer_public_key_hex);
    }
    
    /**
     * Generate random private key
     */
    public static function generate_private_key()
    {
        try {
            $bytes = random_bytes(32);
        } catch (Exception $e) {
            // Fallback
            $bytes = '';
            for ($i = 0; $i < 32; $i++) {
                $bytes .= chr(mt_rand(0, 255));
            }
        }
        
        // Apply clamping during generation
        $bytes[0] = chr(ord($bytes[0]) & 0xF8);
        $bytes[31] = chr((ord($bytes[31]) & 0x7F) | 0x40);
        
        return bin2hex($bytes);
    }
}

// ====================================================================
// CURUPIRA BLOCK CIPHER IMPLEMENTATION (EXATLY LIKE PYTHON)
// ====================================================================

class KeySizeError extends Exception {
    public function __construct($size) {
        parent::__construct("curupira1: invalid key size $size");
    }
}

class Curupira1 {
    const BLOCK_SIZE = 12;
    
    private $key;
    private $key_size;
    private $R;
    private $t;
    private $key_bits;
    private $encryption_round_keys;
    private $decryption_round_keys;
    private $xtimes_table;
    private $sbox_table;
    
    public function __construct($key) {
        $this->key = $key;
        $this->key_size = strlen($key);
        
        if ($this->key_size != 12 && $this->key_size != 18 && $this->key_size != 24) {
            throw new KeySizeError($this->key_size);
        }
        
        $this->_init_xtimes_table();
        $this->_init_sbox_table();
        $this->_expand_key();
    }
    
    private function _init_xtimes_table() {
        $this->xtimes_table = array_fill(0, 256, 0);
        for ($u = 0; $u < 256; $u++) {
            $d = $u << 1;
            if ($d >= 0x100) {
                $d = $d ^ 0x14D;
            }
            $this->xtimes_table[$u] = $d & 0xFF;
        }
    }
    
    private function _init_sbox_table() {
        $P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
              0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1];
        $Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
              0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8];
        
        $this->sbox_table = array_fill(0, 256, 0);
        
        for ($u = 0; $u < 256; $u++) {
            $uh1 = $P[($u >> 4) & 0xF];
            $ul1 = $Q[$u & 0xF];
            $uh2 = $Q[(($uh1 & 0xC) ^ (($ul1 >> 2) & 0x3)) & 0xF];
            $ul2 = $P[((($uh1 << 2) & 0xC) ^ ($ul1 & 0x3)) & 0xF];
            $uh1 = $P[(($uh2 & 0xC) ^ (($ul2 >> 2) & 0x3)) & 0xF];
            $ul1 = $Q[((($uh2 << 2) & 0xC) ^ ($ul2 & 0x3)) & 0xF];
            
            $this->sbox_table[$u] = (($uh1 << 4) ^ $ul1) & 0xFF;
        }
    }
    
    public function xtimes($u) {
        return $this->xtimes_table[$u & 0xFF];
    }
    
    public function ctimes($u) {
        return $this->xtimes(
            $this->xtimes(
                $this->xtimes(
                    $this->xtimes($u) ^ $u
                ) ^ $u
            )
        );
    }
    
    public function sbox($u) {
        return $this->sbox_table[$u & 0xFF];
    }
    
    private function _dtimesa($a, $j, &$b) {
        $d = 3 * $j;
        $v = $this->xtimes($a[0 + $d] ^ $a[1 + $d] ^ $a[2 + $d]);
        $w = $this->xtimes($v);
        
        $b[0 + $d] = $a[0 + $d] ^ $v;
        $b[1 + $d] = $a[1 + $d] ^ $w;
        $b[2 + $d] = $a[2 + $d] ^ $v ^ $w;
    }
    
    private function _etimesa($a, $j, &$b, $e) {
        $d = 3 * $j;
        $v = $a[0 + $d] ^ $a[1 + $d] ^ $a[2 + $d];
        
        if ($e) {
            $v = $this->ctimes($v);
        } else {
            $v = $this->ctimes($v) ^ $v;
        }
        
        $b[0 + $d] = $a[0 + $d] ^ $v;
        $b[1 + $d] = $a[1 + $d] ^ $v;
        $b[2 + $d] = $a[2 + $d] ^ $v;
    }
    
    private function _apply_nonlinear_layer($a) {
        $result = [];
        foreach ($a as $x) {
            $result[] = $this->sbox($x);
        }
        return $result;
    }
    
    private function _apply_permutation_layer($a) {
        $b = array_fill(0, 12, 0);
        
        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $b[$i + 3 * $j] = $a[$i + 3 * ($i ^ $j)];
            }
        }
        
        return $b;
    }
    
    private function _apply_linear_diffusion_layer($a) {
        $b = array_fill(0, 12, 0);
        
        for ($j = 0; $j < 4; $j++) {
            $this->_dtimesa($a, $j, $b);
        }
        
        return $b;
    }
    
    private function _apply_key_addition($a, $kr) {
        $result = [];
        for ($i = 0; $i < 12; $i++) {
            $result[] = $a[$i] ^ $kr[$i];
        }
        return $result;
    }
    
    private function _calculate_schedule_constant($s, $key_bits) {
        $t = (int)($key_bits / 48);
        $q = array_fill(0, 3 * 2 * $t, 0);
        
        if ($s == 0) {
            return $q;
        }
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $q[3 * $j] = $this->sbox(2 * $t * ($s - 1) + $j);
        }
        
        return $q;
    }
    
    private function _apply_constant_addition($Kr, $subkey_rank, $key_bits, $t) {
        $b = $Kr;
        $q = $this->_calculate_schedule_constant($subkey_rank, $key_bits);
        
        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < 2 * $t; $j++) {
                $idx = $i + 3 * $j;
                $b[$idx] ^= $q[$idx];
            }
        }
        
        return $b;
    }
    
    private function _apply_cyclic_shift($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $b[3 * $j] = $a[3 * $j];
            $b[1 + 3 * $j] = $a[1 + 3 * (($j + 1) % (2 * $t))];
            
            if ($j > 0) {
                $b[2 + 3 * $j] = $a[2 + 3 * (($j - 1) % (2 * $t))];
            } else {
                $b[2] = $a[2 + 3 * (2 * $t - 1)];
            }
        }
        
        return $b;
    }
    
    private function _apply_linear_diffusion($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $this->_etimesa($a, $j, $b, true);
        }
        
        return $b;
    }
    
    private function _calculate_next_subkey($Kr, $subkey_rank, $key_bits, $t) {
        return $this->_apply_linear_diffusion(
            $this->_apply_cyclic_shift(
                $this->_apply_constant_addition($Kr, $subkey_rank, $key_bits, $t),
                $t
            ),
            $t
        );
    }
    
    private function _select_round_key($Kr) {
        $kr = array_fill(0, 12, 0);
        
        for ($j = 0; $j < 4; $j++) {
            $kr[3 * $j] = $this->sbox($Kr[3 * $j]);
        }
        
        for ($i = 1; $i < 3; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $kr[$i + 3 * $j] = $Kr[$i + 3 * $j];
            }
        }
        
        return $kr;
    }
    
    private function _expand_key() {
        $key_bits = $this->key_size * 8;
        
        if ($key_bits == 96) {
            $this->R = 10;
        } elseif ($key_bits == 144) {
            $this->R = 14;
        } elseif ($key_bits == 192) {
            $this->R = 18;
        }
        
        $this->key_bits = $key_bits;
        $this->t = (int)($key_bits / 48);
        
        $Kr = array_values(unpack('C*', $this->key));
        
        $this->encryption_round_keys = array_fill(0, $this->R + 1, null);
        $this->decryption_round_keys = array_fill(0, $this->R + 1, null);
        
        $kr = $this->_select_round_key($Kr);
        $this->encryption_round_keys[0] = $kr;
        
        for ($r = 1; $r <= $this->R; $r++) {
            $Kr = $this->_calculate_next_subkey($Kr, $r, $this->key_bits, $this->t);
            $kr = $this->_select_round_key($Kr);
            
            $this->encryption_round_keys[$r] = $kr;
            $this->decryption_round_keys[$this->R - $r] = $this->_apply_linear_diffusion_layer($kr);
        }
        
        $this->decryption_round_keys[0] = $this->encryption_round_keys[$this->R];
        $this->decryption_round_keys[$this->R] = $this->encryption_round_keys[0];
    }
    
    private function _perform_whitening_round($a, $k0) {
        return $this->_apply_key_addition($a, $k0);
    }
    
    private function _perform_last_round($a, $kR) {
        return $this->_apply_key_addition(
            $this->_apply_permutation_layer(
                $this->_apply_nonlinear_layer($a)
            ),
            $kR
        );
    }
    
    private function _perform_round($a, $kr) {
        return $this->_apply_key_addition(
            $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer(
                    $this->_apply_nonlinear_layer($a)
                )
            ),
            $kr
        );
    }
    
    private function _process_block($data, $round_keys) {
        $tmp = array_values(unpack('C*', $data));
        $tmp = $this->_perform_whitening_round($tmp, $round_keys[0]);
        
        for ($r = 1; $r < $this->R; $r++) {
            $tmp = $this->_perform_round($tmp, $round_keys[$r]);
        }
        
        $tmp = $this->_perform_last_round($tmp, $round_keys[$this->R]);
        return pack('C*', ...$tmp);
    }
    
    public function encrypt($plaintext) {
        if (strlen($plaintext) != self::BLOCK_SIZE) {
            throw new Exception("Plaintext must be " . self::BLOCK_SIZE . " bytes");
        }
        return $this->_process_block($plaintext, $this->encryption_round_keys);
    }
    
    public function decrypt($ciphertext) {
        if (strlen($ciphertext) != self::BLOCK_SIZE) {
            throw new Exception("Ciphertext must be " . self::BLOCK_SIZE . " bytes");
        }
        return $this->_process_block($ciphertext, $this->decryption_round_keys);
    }
    
    public function sct($data) {
        if (strlen($data) != self::BLOCK_SIZE) {
            throw new Exception("Data must be " . self::BLOCK_SIZE . " bytes");
        }
        
        $tmp = array_values(unpack('C*', $data));
        
        $unkeyed_round = function($a) {
            return $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer(
                    $this->_apply_nonlinear_layer($a)
                )
            );
        };
        
        $tmp = $unkeyed_round($tmp);
        for ($i = 0; $i < 3; $i++) {
            $tmp = $unkeyed_round($tmp);
        }
        
        return pack('C*', ...$tmp);
    }
    
    public function BlockSize() {
        return self::BLOCK_SIZE;
    }
}

// ====================================================================
// CURUPIRA CBC MODE IMPLEMENTATION
// ====================================================================

/**
 * Pad data using PKCS#7 padding
 */
function pad_pkcs7($data, $block_size) {
    $padding_len = $block_size - (strlen($data) % $block_size);
    if ($padding_len == 0) {
        $padding_len = $block_size;
    }
    return $data . str_repeat(chr($padding_len), $padding_len);
}

/**
 * Remove PKCS#7 padding
 */
function unpad_pkcs7($data) {
    if (strlen($data) == 0) {
        throw new Exception("Empty data");
    }
    
    $padding_len = ord($data[strlen($data) - 1]);
    if ($padding_len > strlen($data)) {
        throw new Exception("Invalid padding length");
    }
    
    // Verify padding bytes
    for ($i = 0; $i < $padding_len; $i++) {
        if (ord($data[strlen($data) - $i - 1]) != $padding_len) {
            throw new Exception("Invalid padding bytes");
        }
    }
    
    return substr($data, 0, -$padding_len);
}

/**
 * Encrypt using Curupira in CBC mode
 */
function cbc_encrypt_curupira($key, $iv, $plaintext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    
    // Pad plaintext
    $padded_data = pad_pkcs7($plaintext, $block_size);
    
    // CBC encryption
    $ciphertext = '';
    $prev_block = $iv;
    
    for ($i = 0; $i < strlen($padded_data); $i += $block_size) {
        $block = substr($padded_data, $i, $block_size);
        
        // XOR with previous ciphertext (or IV for first block)
        $xored_block = '';
        for ($j = 0; $j < $block_size; $j++) {
            $xored_block .= chr(ord($block[$j]) ^ ord($prev_block[$j]));
        }
        
        // Encrypt with Curupira
        $encrypted_block = $cipher->encrypt($xored_block);
        $ciphertext .= $encrypted_block;
        $prev_block = $encrypted_block;
    }
    
    return $ciphertext;
}

/**
 * Decrypt using Curupira in CBC mode
 */
function cbc_decrypt_curupira($key, $iv, $ciphertext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    
    if (strlen($ciphertext) % $block_size != 0) {
        throw new Exception("Ciphertext length must be multiple of block size");
    }
    
    // CBC decryption
    $plaintext = '';
    $prev_block = $iv;
    
    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
        $encrypted_block = substr($ciphertext, $i, $block_size);
        
        // Decrypt with Curupira
        $decrypted_block = $cipher->decrypt($encrypted_block);
        
        // XOR with previous ciphertext (or IV for first block)
        $plain_block = '';
        for ($j = 0; $j < $block_size; $j++) {
            $plain_block .= chr(ord($decrypted_block[$j]) ^ ord($prev_block[$j]));
        }
        
        $plaintext .= $plain_block;
        $prev_block = $encrypted_block;
    }
    
    // Remove padding
    return unpad_pkcs7($plaintext);
}

// ====================================================================
// RFC 1423 ENCRYPTION WITH CURUPIRA-192-CBC
// ====================================================================

/**
 * Derive key according to RFC 1423 section 1.1 (PBKDF1-like)
 * Uses MD5 iteratively: D_i = MD5(D_{i-1} || P || S)
 */
function rfc1423_derive_key_md5($password, $salt, $key_size) {
    // Use first 8 bytes of salt for key derivation (as per RFC 1423)
    $iv_salt = substr($salt, 0, 8);
    
    // RFC 1423 uses MD5 iteratively
    $d = '';
    $result = '';
    
    while (strlen($result) < $key_size) {
        $d = md5($d . $password . $iv_salt, true);
        $result .= $d;
    }
    
    return substr($result, 0, $key_size);
}

/**
 * Encrypt private key data using RFC 1423 format with Curupira-192-CBC
 */
function encrypt_private_key_pem($data, $password, $cipher_name = "CURUPIRA-192-CBC") {
    if ($cipher_name != "CURUPIRA-192-CBC") {
        throw new Exception("Unsupported cipher: $cipher_name");
    }
    
    // Generate random IV (12 bytes for Curupira)
    $iv = random_bytes_bc(12);
    
    // Derive key using RFC 1423 method (192-bit = 24 bytes)
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    
    // Encrypt data with Curupira-192-CBC
    $encrypted_data = cbc_encrypt_curupira($key, $iv, $data);
    
    // Combine IV and encrypted data
    $full_data = $encrypted_data;
    
    // Encode as base64
    $b64_data = base64_encode($full_data);
    
    // Format as PEM with RFC 1423 headers
    $lines = [];
    $lines[] = "Proc-Type: 4,ENCRYPTED";
    $lines[] = "DEK-Info: $cipher_name," . strtoupper(bin2hex($iv));
    $lines[] = "";
    
    // Split base64 into 64-character lines
    $lines = array_merge($lines, str_split($b64_data, 64));
    
    return implode("\n", $lines);
}

/**
 * Decrypt RFC 1423 formatted private key data
 */
function decrypt_private_key_pem($pem_data, $password) {
    $lines = explode("\n", trim($pem_data));
    
    // Parse headers
    $proc_type = null;
    $dek_info = null;
    $b64_lines = [];
    
    $in_headers = true;
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            if ($in_headers) {
                $in_headers = false;
            }
            continue;
        }
        
        if (strpos($line, "-----") === 0) {
            continue;
        }
        
        if ($in_headers) {
            if (strpos($line, "Proc-Type:") === 0) {
                $proc_type = trim(substr($line, 10));
                if ($proc_type != "4,ENCRYPTED") {
                    throw new Exception("Not an encrypted PEM block");
                }
            } elseif (strpos($line, "DEK-Info:") === 0) {
                $dek_info = trim(substr($line, 10));
            }
        } else {
            $b64_lines[] = $line;
        }
    }
    
    if (!$dek_info) {
        throw new Exception("Missing DEK-Info header");
    }
    
    // Parse DEK-Info
    $dek_parts = explode(",", $dek_info, 2);
    if (count($dek_parts) != 2) {
        throw new Exception("Invalid DEK-Info format: $dek_info");
    }
    
    $cipher_name = trim($dek_parts[0]);
    $iv_hex = trim($dek_parts[1]);
    
    if ($cipher_name != "CURUPIRA-192-CBC") {
        throw new Exception("Unsupported cipher: $cipher_name");
    }
    
    $iv = hex2bin($iv_hex);
    if (!$iv || strlen($iv) != 12) {
        throw new Exception("Invalid IV length");
    }
    
    // Decode base64 data
    $b64_data = implode("", $b64_lines);
    $encrypted_data = base64_decode($b64_data);
    
    // Note: IV is NOT included in the encrypted data (only in header)
    $ciphertext = $encrypted_data;
    
    // Derive key
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    
    try {
        // Decrypt data with Curupira-192-CBC
        $decrypted_data = cbc_decrypt_curupira($key, $iv, $ciphertext);
        
        return $decrypted_data;
    } catch (Exception $e) {
        throw new Exception("Decryption failed (wrong password?): " . $e->getMessage());
    }
}

/**
 * Generate cryptographically secure random bytes
 */
function random_bytes_bc($length) {
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }
    
    if (function_exists('openssl_random_pseudo_bytes')) {
        return openssl_random_pseudo_bytes($length);
    }
    
    $bytes = '';
    for ($i = 0; $i < $length; $i++) {
        $bytes .= chr(random_int(0, 255));
    }
    return $bytes;
}

// ============================================================================
// PEM FUNCTIONS COM SUPORTE A CRIPTOGRAFIA CURUPIRA-192-CBC - CORRIGIDO
// ============================================================================

class X25519_PEM
{
    /**
     * Convert X25519 private key to PEM PKCS#8 format with optional encryption
     * EXATAMENTE como no Python (conforme seu exemplo)
     */
    public static function private_to_pem_pkcs8($private_key_hex, $password = null)
    {
        if (strlen($private_key_hex) != 64 || !ctype_xdigit($private_key_hex)) {
            throw new Exception("Invalid private key");
        }
        
        $private_key_bin = hex2bin($private_key_hex);
        
        // X25519 OID: 1.3.101.110 (0x06 0x03 0x2b 0x65 0x6e)
        $x25519_oid = "\x06\x03\x2b\x65\x6e";
        
        // inner = b'\x04\x20' + private_key_bytes
        $inner = "\x04\x20" . $private_key_bin;
        
        // private_key = b'\x04' + bytes([len(inner)]) + inner
        $private_key = "\x04" . chr(strlen($inner)) . $inner;
        
        // alg_id = b'\x30' + bytes([len(x25519_oid)]) + x25519_oid
        $alg_id = "\x30" . chr(strlen($x25519_oid)) . $x25519_oid;
        
        // version = b'\x02\x01\x00'
        $version = "\x02\x01\x00";
        
        // total_len = len(version + alg_id + private_key)
        $total = $version . $alg_id . $private_key;
        $total_len = strlen($total);
        
        // pkcs8 = b'\x30' + bytes([total_len]) + version + alg_id + private_key
        $pkcs8 = "\x30" . chr($total_len) . $total;
        
        if ($password) {
            // Encrypt using RFC 1423 with Curupira-192-CBC
            $encrypted_pem = encrypt_private_key_pem($pkcs8, $password, "CURUPIRA-192-CBC");
            return "-----BEGIN PRIVATE KEY-----\n" . $encrypted_pem . "\n-----END PRIVATE KEY-----\n";
        } else {
            $b64 = base64_encode($pkcs8);
            $lines = str_split($b64, 64);
            return "-----BEGIN PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END PRIVATE KEY-----\n";
        }
    }
    
    /**
     * Convert X25519 public key to PEM PKCS#8 format
     */
    public static function public_to_pem_pkcs8($public_key_hex)
    {
        if (strlen($public_key_hex) != 64 || !ctype_xdigit($public_key_hex)) {
            throw new Exception("Invalid public key");
        }
        
        $public_key_bin = hex2bin($public_key_hex);
        
        // X25519 OID: 1.3.101.110
        $x25519_oid = "\x06\x03\x2b\x65\x6e";
        
        // AlgorithmIdentifier SEQUENCE
        $alg_id = "\x30" . chr(strlen($x25519_oid)) . $x25519_oid;
        
        // SubjectPublicKey BIT STRING (unused bits = 0)
        $bit_string = "\x03\x21\x00" . $public_key_bin; // 0x21 = 33 bytes (32 + 1 for unused bits)
        
        // SubjectPublicKeyInfo SEQUENCE
        $content = $alg_id . $bit_string;
        $content_len = strlen($content);
        
        $der = "\x30" . chr($content_len) . $content;
        
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        
        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= implode("\n", $lines) . "\n";
        $pem .= "-----END PUBLIC KEY-----\n";
        
        return $pem;
    }
    
    /**
     * Parse private key from PEM PKCS#8 format (with optional encryption)
     */
    public static function parse_private_pem_pkcs8($pem_data, $password = null)
    {
        $pem_data = trim($pem_data);
        
        // Check if encrypted by looking for RFC 1423 headers
        $is_encrypted = false;
        $iv_hex = null;
        
        $lines = explode("\n", $pem_data);
        $b64_lines = [];
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            if (strpos($line, "-----BEGIN PRIVATE KEY-----") === 0) {
                continue;
            }
            
            if (strpos($line, "-----END PRIVATE KEY-----") === 0) {
                break;
            }
            
            if (strpos($line, "Proc-Type:") === 0) {
                if (strpos($line, "4,ENCRYPTED") !== false) {
                    $is_encrypted = true;
                }
                continue;
            }
            
            if (strpos($line, "DEK-Info:") === 0) {
                $parts = explode(",", $line);
                if (count($parts) >= 2 && strpos($parts[0], "CURUPIRA-192-CBC") !== false) {
                    $iv_hex = trim($parts[1]);
                }
                continue;
            }
            
            if (empty($line)) {
                continue;
            }
            
            $b64_lines[] = $line;
        }
        
        $b64_data = implode("", $b64_lines);
        
        if ($is_encrypted) {
            if (!$password) {
                throw new Exception("Password required for encrypted private key");
            }
            
            if (!$iv_hex) {
                throw new Exception("Missing IV in encrypted PEM");
            }
            
            $iv = hex2bin($iv_hex);
            if (!$iv || strlen($iv) != 12) {
                throw new Exception("Invalid IV length");
            }
            
            $encrypted_data = base64_decode($b64_data);
            if ($encrypted_data === false) {
                throw new Exception("Invalid base64 data");
            }
            
            // Derive key
            $key = rfc1423_derive_key_md5($password, $iv, 24);
            
            try {
                // Decrypt DER data with Curupira-192-CBC
                $der = cbc_decrypt_curupira($key, $iv, $encrypted_data);
            } catch (Exception $e) {
                throw new Exception("Decryption failed (wrong password?): " . $e->getMessage());
            }
        } else {
            $der = base64_decode($b64_data);
            if ($der === false) {
                throw new Exception("Invalid base64 data");
            }
        }
        
        // Parse DER (simplified parser)
        $private_key_bin = self::decode_pkcs8_private_key_simple($der);
        
        if (strlen($private_key_bin) != 32) {
            throw new Exception("Invalid private key length: " . strlen($private_key_bin));
        }
        
        return bin2hex($private_key_bin);
    }
    
    /**
     * Parse public key from PEM PKCS#8 format
     */
    public static function parse_public_pem_pkcs8($pem_data)
    {
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
        
        // Parse DER (simplified parser)
        $public_key_bin = self::decode_pkcs8_public_key_simple($der);
        
        if (strlen($public_key_bin) != 32) {
            throw new Exception("Invalid public key length: " . strlen($public_key_bin));
        }
        
        return bin2hex($public_key_bin);
    }
    
    /**
     * Simple PKCS#8 private key decoder
     */
    private static function decode_pkcs8_private_key_simple($der)
    {
        $pos = 0;
        
        // Outer SEQUENCE (0x30)
        if (ord($der[$pos]) !== 0x30) {
            throw new Exception("Not a SEQUENCE");
        }
        $pos++;
        
        // Skip length (assume single byte)
        $len = ord($der[$pos]);
        $pos++;
        
        // Version INTEGER (0x02 0x01 0x00)
        if (ord($der[$pos]) !== 0x02) {
            throw new Exception("Expected version INTEGER");
        }
        $pos++;
        $version_len = ord($der[$pos]);
        $pos += $version_len + 1;
        
        // AlgorithmIdentifier SEQUENCE
        if (ord($der[$pos]) !== 0x30) {
            throw new Exception("Expected AlgorithmIdentifier SEQUENCE");
        }
        $pos++;
        $alg_len = ord($der[$pos]);
        $pos += $alg_len + 1;
        
        // PrivateKey OCTET STRING (0x04)
        if (ord($der[$pos]) !== 0x04) {
            throw new Exception("Expected PrivateKey OCTET STRING");
        }
        $pos++;
        
        $outer_len = ord($der[$pos]);
        $pos++;
        
        // Inside the outer OCTET STRING, there's another OCTET STRING
        // Skip inner OCTET STRING tag (0x04)
        if (ord($der[$pos]) !== 0x04) {
            throw new Exception("Expected inner OCTET STRING");
        }
        $pos++;
        
        $inner_len = ord($der[$pos]);
        $pos++;
        
        // The actual private key (32 bytes)
        return substr($der, $pos, $inner_len);
    }
    
    /**
     * Simple PKCS#8 public key decoder
     */
    private static function decode_pkcs8_public_key_simple($der)
    {
        $pos = 0;
        
        // SEQUENCE (0x30)
        if (ord($der[$pos]) !== 0x30) {
            throw new Exception("Not a SEQUENCE");
        }
        $pos++;
        
        // Skip length (assume single byte)
        $len = ord($der[$pos]);
        $pos++;
        
        // AlgorithmIdentifier SEQUENCE
        if (ord($der[$pos]) !== 0x30) {
            throw new Exception("Expected AlgorithmIdentifier SEQUENCE");
        }
        $pos++;
        $alg_len = ord($der[$pos]);
        $pos += $alg_len + 1;
        
        // BIT STRING (0x03)
        if (ord($der[$pos]) !== 0x03) {
            throw new Exception("Expected BIT STRING");
        }
        $pos++;
        
        $bit_string_len = ord($der[$pos]);
        $pos++;
        
        // Skip unused bits (should be 0x00)
        $pos++;
        
        // The actual public key (32 bytes)
        return substr($der, $pos, 32);
    }
}

// ============================================================================
// CLI FUNCTIONS PARA TESTE
// ============================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && basename(__FILE__) === basename($argv[0])) {
    // Teste simples
    if (count($argv) < 2) {
        echo "Uso: php " . basename(__FILE__) . " [gerar|criptografar|teste|compatibilidade]\n";
        exit(1);
    }
    
    $command = $argv[1];
    
    if ($command === 'gerar') {
        // Gerar chave
        $private = X25519::generate_private_key();
        $public = X25519::x25519_get_public_key($private);
        
        echo "Chave privada: $private\n";
        echo "Chave pública: $public\n";
        
        // Salvar sem senha (PKCS#8)
        $pem_private = X25519_PEM::private_to_pem_pkcs8($private);
        $pem_public = X25519_PEM::public_to_pem_pkcs8($public);
        
        file_put_contents('teste_private.pem', $pem_private);
        file_put_contents('teste_public.pem', $pem_public);
        
        echo "Salvo em teste_private.pem e teste_public.pem\n";
        
    } elseif ($command === 'criptografar') {
        if (count($argv) < 4) {
            echo "Uso: php " . basename(__FILE__) . " criptografar <chave_privada_hex> <senha>\n";
            exit(1);
        }
        
        $private = $argv[2];
        $password = $argv[3];
        
        // Gerar PEM criptografado
        $pem_encrypted = X25519_PEM::private_to_pem_pkcs8($private, $password);
        
        file_put_contents('teste_encrypted.pem', $pem_encrypted);
        
        echo "Chave criptografada salva em teste_encrypted.pem\n";
        echo "Conteúdo:\n";
        echo $pem_encrypted;
        
        // Testar descriptografia
        try {
            $decrypted = X25519_PEM::parse_private_pem_pkcs8($pem_encrypted, $password);
            echo "\nDescriptografado com sucesso: " . ($decrypted === $private ? "✓" : "✗") . "\n";
        } catch (Exception $e) {
            echo "\nErro na descriptografia: " . $e->getMessage() . "\n";
        }
        
    } elseif ($command === 'teste') {
        // Teste completo
        echo "=== TESTE X25519 COM CURUPIRA-192-CBC ===\n\n";
        
        // 1. Gerar chave
        echo "1. Gerando chave X25519...\n";
        $private = X25519::generate_private_key();
        $public = X25519::x25519_get_public_key($private);
        echo "   Privada: " . substr($private, 0, 16) . "...\n";
        echo "   Pública: " . substr($public, 0, 16) . "...\n\n";
        
        // 2. Salvar sem senha
        echo "2. Salvando sem senha (PKCS#8)...\n";
        $pem_plain = X25519_PEM::private_to_pem_pkcs8($private);
        file_put_contents('test_plain.pem', $pem_plain);
        echo "   Salvo em test_plain.pem\n";
        
        // Verificar conteúdo
        $pem_content = file_get_contents('test_plain.pem');
        $first_lines = explode("\n", $pem_content, 4);
        echo "   Primeiras linhas:\n";
        for ($i = 0; $i < min(4, count($first_lines)); $i++) {
            echo "     " . $first_lines[$i] . "\n";
        }
        echo "\n";
        
        // 3. Salvar com senha
        echo "3. Salvando com senha 'teste123'...\n";
        $pem_enc = X25519_PEM::private_to_pem_pkcs8($private, 'teste123');
        file_put_contents('test_encrypted.pem', $pem_enc);
        echo "   Salvo em test_encrypted.pem\n\n";
        
        // 4. Ler sem senha
        echo "4. Lendo chave sem senha...\n";
        try {
            $read_plain = X25519_PEM::parse_private_pem_pkcs8($pem_plain);
            echo "   Chave lida: " . ($read_plain === $private ? "✓" : "✗") . "\n";
        } catch (Exception $e) {
            echo "   Erro: " . $e->getMessage() . "\n";
        }
        echo "\n";
        
        // 5. Ler com senha
        echo "5. Lendo chave com senha 'teste123'...\n";
        try {
            $read_enc = X25519_PEM::parse_private_pem_pkcs8($pem_enc, 'teste123');
            echo "   Chave lida: " . ($read_enc === $private ? "✓" : "✗") . "\n";
        } catch (Exception $e) {
            echo "   Erro: " . $e->getMessage() . "\n";
        }
        echo "\n";
        
        // 6. Ler com senha errada
        echo "6. Tentando ler com senha errada...\n";
        try {
            $read_wrong = X25519_PEM::parse_private_pem_pkcs8($pem_enc, 'senhaerrada');
            echo "   ERRO: Deveria ter falhado!\n";
        } catch (Exception $e) {
            echo "   ✓ Falhou como esperado: " . $e->getMessage() . "\n";
        }
        
        echo "\n=== TESTE CONCLUÍDO ===\n";
        
    } elseif ($command === 'compatibilidade') {
        // Teste de compatibilidade com x25519-cli.php
        echo "=== TESTE DE COMPATIBILIDADE ===\n\n";
        
        // Usar o mesmo vetor de teste do x25519-cli.php
        $test_private = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        $test_public = X25519::x25519_get_public_key($test_private);
        
        echo "Chave privada de teste: " . substr($test_private, 0, 16) . "...\n";
        echo "Chave pública calculada: " . substr($test_public, 0, 16) . "...\n\n";
        
        // Gerar PEMs
        echo "1. Gerando PEMs...\n";
        $private_pem = X25519_PEM::private_to_pem_pkcs8($test_private);
        $public_pem = X25519_PEM::public_to_pem_pkcs8($test_public);
        
        echo "Primeiras linhas do PEM privado:\n";
        $lines = explode("\n", $private_pem);
        for ($i = 0; $i < min(3, count($lines)); $i++) {
            echo "  " . $lines[$i] . "\n";
        }
        echo "...\n\n";
        
        // Analisar de volta
        echo "2. Analisando PEMs de volta...\n";
        try {
            $parsed_private = X25519_PEM::parse_private_pem_pkcs8($private_pem);
            $parsed_public = X25519_PEM::parse_public_pem_pkcs8($public_pem);
            
            echo "   Chave privada analisada: " . ($parsed_private === $test_private ? "✓" : "✗") . "\n";
            echo "   Chave pública analisada:  " . ($parsed_public === $test_public ? "✓" : "✗") . "\n";
            
            // Calcular pública da privada analisada
            $calc_public = X25519::x25519_get_public_key($parsed_private);
            echo "   Pública calculada:        " . ($calc_public === $test_public ? "✓" : "✗") . "\n";
            
        } catch (Exception $e) {
            echo "   Erro: " . $e->getMessage() . "\n";
        }
        
        echo "\n=== TESTE DE COMPATIBILIDADE CONCLUÍDO ===\n";
    }
}
