<?php
/**
 * X448 - Curve448 Diffie-Hellman Key Exchange
 * Compatível com edgetk (Go)
 * Com suporte a PKCS#8 PEM e criptografia Curupira-192-CBC
 */

// ====================================================================
// CURUPIRA BLOCK CIPHER IMPLEMENTATION (COMPLETA - IGUAL AO ED25519)
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
// X448 IMPLEMENTATION (Compatível com edgetk/Go)
// ====================================================================

class X448
{
    private static $P = '726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439';
    private static $A24 = '39081';
    
    private static function getBasePoint()
    {
        return "\x05" . str_repeat("\x00", 55);
    }
    
    public static function X448($scalar_bytes, $point_bytes)
    {
        if (strlen($scalar_bytes) != 56 || strlen($point_bytes) != 56) {
            throw new Exception("Bad length");
        }
        
        $k = $scalar_bytes;
        $k[0] = chr(ord($k[0]) & 252);
        $k[55] = chr(ord($k[55]) | 128);
        
        $u_int = '0';
        for ($i = 0; $i < 56; $i++) {
            $u_int = bcadd($u_int, bcmul((string)ord($point_bytes[$i]), bcpow('2', (string)(8 * $i))));
        }
        $x1 = bcmod($u_int, self::$P);
        
        $x2 = '1';
        $z2 = '0';
        $x3 = $x1;
        $z3 = '1';
        $swap = 0;
        
        for ($t = 447; $t >= 0; $t--) {
            $byte_idx = (int)($t / 8);
            $bit_idx = $t % 8;
            $kt = (ord($k[$byte_idx]) >> $bit_idx) & 1;
            
            $swap ^= $kt;
            
            if ($swap) {
                list($x2, $x3) = [$x3, $x2];
                list($z2, $z3) = [$z3, $z2];
            }
            
            $swap = $kt;
            
            $A = self::add($x2, $z2);
            $AA = self::mul($A, $A);
            $B = self::sub($x2, $z2);
            $BB = self::mul($B, $B);
            $E = self::sub($AA, $BB);
            $C = self::add($x3, $z3);
            $D = self::sub($x3, $z3);
            $DA = self::mul($D, $A);
            $CB = self::mul($C, $B);
            
            $x3 = self::add($DA, $CB);
            $x3 = self::mul($x3, $x3);
            
            $z3 = self::sub($DA, $CB);
            $z3 = self::mul($z3, $z3);
            $z3 = self::mul($z3, $x1);
            
            $x2 = self::mul($AA, $BB);
            
            $z2 = self::mul(self::$A24, $E);
            $z2 = self::add($z2, $AA);
            $z2 = self::mul($z2, $E);
        }
        
        if ($swap) {
            list($x2, $x3) = [$x3, $x2];
            list($z2, $z3) = [$z3, $z2];
        }
        
        if (bccomp($z2, '0') == 0) {
            throw new Exception("x448 bad input point: low order point");
        }
        
        $result = self::mul($x2, self::inv($z2));
        
        $bytes = '';
        for ($i = 0; $i < 56; $i++) {
            $bytes .= chr((int)bcmod($result, '256'));
            $result = bcdiv($result, '256', 0);
        }
        
        return $bytes;
    }
    
    private static function add($a, $b)
    {
        $s = bcadd($a, $b);
        if (bccomp($s, self::$P) >= 0) $s = bcsub($s, self::$P);
        return $s;
    }
    
    private static function sub($a, $b)
    {
        $s = bcsub($a, $b);
        if (bccomp($s, '0') < 0) $s = bcadd($s, self::$P);
        return $s;
    }
    
    private static function mul($a, $b)
    {
        return bcmod(bcmul($a, $b), self::$P);
    }
    
    private static function inv($a)
    {
        return bcpowmod($a, bcsub(self::$P, '2'), self::$P);
    }
    
    public static function x448_get_public_key($private_hex)
    {
        $priv_bytes = hex2bin($private_hex);
        $pub_bytes = self::X448($priv_bytes, self::getBasePoint());
        return bin2hex($pub_bytes);
    }
    
    public static function x448_shared_secret($private_hex, $peer_hex)
    {
        $priv_bytes = hex2bin($private_hex);
        $peer_bytes = hex2bin($peer_hex);
        $shared_bytes = self::X448($priv_bytes, $peer_bytes);
        return bin2hex($shared_bytes);
    }
    
    public static function generate_private_key()
    {
        $bytes = random_bytes(56);
        $bytes[0] = chr(ord($bytes[0]) & 0xFC);
        $bytes[55] = chr(ord($bytes[55]) | 0x80);
        return bin2hex($bytes);
    }
}

// ====================================================================
// FUNÇÕES DE CRIPTOGRAFIA (COM CURUPIRA COMPLETO)
// ====================================================================

function random_bytes_bc($length) {
    if (function_exists('random_bytes')) return random_bytes($length);
    if (function_exists('openssl_random_pseudo_bytes')) return openssl_random_pseudo_bytes($length);
    $bytes = '';
    for ($i = 0; $i < $length; $i++) $bytes .= chr(random_int(0, 255));
    return $bytes;
}

function rfc1423_derive_key_md5($password, $salt, $key_size) {
    $iv_salt = substr($salt, 0, 8);
    $d = '';
    $result = '';
    while (strlen($result) < $key_size) {
        $d = md5($d . $password . $iv_salt, true);
        $result .= $d;
    }
    return substr($result, 0, $key_size);
}

function pad_pkcs7($data, $block_size) {
    $padding_len = $block_size - (strlen($data) % $block_size);
    if ($padding_len == 0) $padding_len = $block_size;
    return $data . str_repeat(chr($padding_len), $padding_len);
}

function unpad_pkcs7($data) {
    $padding_len = ord($data[strlen($data) - 1]);
    if ($padding_len > strlen($data)) throw new Exception("Invalid padding");
    for ($i = 0; $i < $padding_len; $i++) {
        if (ord($data[strlen($data) - $i - 1]) != $padding_len) {
            throw new Exception("Invalid padding bytes");
        }
    }
    return substr($data, 0, -$padding_len);
}

function cbc_encrypt_curupira($key, $iv, $plaintext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    $padded = pad_pkcs7($plaintext, $block_size);
    
    $ciphertext = '';
    $prev = $iv;
    
    for ($i = 0; $i < strlen($padded); $i += $block_size) {
        $block = substr($padded, $i, $block_size);
        $xored = '';
        for ($j = 0; $j < $block_size; $j++) {
            $xored .= chr(ord($block[$j]) ^ ord($prev[$j]));
        }
        $encrypted = $cipher->encrypt($xored);
        $ciphertext .= $encrypted;
        $prev = $encrypted;
    }
    
    return $ciphertext;
}

function cbc_decrypt_curupira($key, $iv, $ciphertext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    
    $plaintext = '';
    $prev = $iv;
    
    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
        $encrypted = substr($ciphertext, $i, $block_size);
        $decrypted = $cipher->decrypt($encrypted);
        $plain_block = '';
        for ($j = 0; $j < $block_size; $j++) {
            $plain_block .= chr(ord($decrypted[$j]) ^ ord($prev[$j]));
        }
        $plaintext .= $plain_block;
        $prev = $encrypted;
    }
    
    return unpad_pkcs7($plaintext);
}

function encrypt_private_key_pem($data, $password) {
    $iv = random_bytes_bc(12);
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    $encrypted = cbc_encrypt_curupira($key, $iv, $data);
    $b64 = base64_encode($encrypted);
    $lines = ["Proc-Type: 4,ENCRYPTED", "DEK-Info: CURUPIRA-192-CBC," . strtoupper(bin2hex($iv)), ""];
    $lines = array_merge($lines, str_split($b64, 64));
    return implode("\n", $lines);
}

// ====================================================================
// X448 PKCS#8 PEM FUNCTIONS
// ====================================================================

class X448_PEM
{
    public static function private_to_pem_pkcs8($private_key_hex, $password = null)
    {
        if (strlen($private_key_hex) != 112 || !ctype_xdigit($private_key_hex)) {
            throw new Exception("Invalid private key");
        }
        
        $private_key_bin = hex2bin($private_key_hex);
        
        $x448_oid = "\x06\x03\x2b\x65\x6f";
        
        $inner = "\x04\x38" . $private_key_bin;
        $private_key = "\x04" . chr(strlen($inner)) . $inner;
        $alg_id = "\x30" . chr(strlen($x448_oid)) . $x448_oid;
        $version = "\x02\x01\x00";
        $total = $version . $alg_id . $private_key;
        $pkcs8 = "\x30" . chr(strlen($total)) . $total;
        
        if ($password) {
            $encrypted = encrypt_private_key_pem($pkcs8, $password);
            return "-----BEGIN X448 PRIVATE KEY-----\n" . $encrypted . "\n-----END X448 PRIVATE KEY-----\n";
        } else {
            $b64 = base64_encode($pkcs8);
            $lines = str_split($b64, 64);
            return "-----BEGIN X448 PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END X448 PRIVATE KEY-----\n";
        }
    }
    
    public static function public_to_pem_pkcs8($public_key_hex)
    {
        if (strlen($public_key_hex) != 112 || !ctype_xdigit($public_key_hex)) {
            throw new Exception("Invalid public key");
        }
        
        $public_key_bin = hex2bin($public_key_hex);
        
        $x448_oid = "\x06\x03\x2b\x65\x6f";
        $alg_id = "\x30" . chr(strlen($x448_oid)) . $x448_oid;
        $bit_string = "\x03\x39\x00" . $public_key_bin;
        $content = $alg_id . $bit_string;
        $der = "\x30" . chr(strlen($content)) . $content;
        
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        
        return "-----BEGIN X448 PUBLIC KEY-----\n" . implode("\n", $lines) . "\n-----END X448 PUBLIC KEY-----\n";
    }
    
    public static function parse_private_pem_pkcs8($pem_data, $password = null)
    {
        $pem_data = trim($pem_data);
        
        $is_encrypted = false;
        $iv_hex = null;
        
        $lines = explode("\n", $pem_data);
        $b64_lines = [];
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            if (strpos($line, "-----BEGIN X448 PRIVATE KEY-----") === 0) continue;
            if (strpos($line, "-----END X448 PRIVATE KEY-----") === 0) break;
            
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "4,ENCRYPTED") !== false) {
                $is_encrypted = true;
                continue;
            }
            
            if (strpos($line, "DEK-Info:") === 0) {
                $parts = explode(",", $line);
                if (count($parts) >= 2) $iv_hex = trim($parts[1]);
                continue;
            }
            
            if (empty($line)) continue;
            $b64_lines[] = $line;
        }
        
        $b64_data = implode("", $b64_lines);
        
        if ($is_encrypted) {
            if (!$password) throw new Exception("Password required");
            $iv = hex2bin($iv_hex);
            $encrypted = base64_decode($b64_data);
            $key = rfc1423_derive_key_md5($password, $iv, 24);
            $der = cbc_decrypt_curupira($key, $iv, $encrypted);
        } else {
            $der = base64_decode($b64_data);
        }
        
        $pos = strpos($der, "\x04\x38");
        if ($pos === false) throw new Exception("Invalid DER structure");
        $private_bytes = substr($der, $pos + 2, 56);
        
        if (strlen($private_bytes) != 56) {
            throw new Exception("Invalid private key length: " . strlen($private_bytes));
        }
        
        return bin2hex($private_bytes);
    }
    
    public static function parse_public_pem_pkcs8($pem_data)
    {
        $lines = explode("\n", trim($pem_data));
        $b64 = '';
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line && !str_starts_with($line, '-----')) $b64 .= $line;
        }
        
        $der = base64_decode($b64);
        if ($der === false) throw new Exception("Invalid base64 data");
        
        $pos = strpos($der, "\x03\x39\x00");
        if ($pos === false) throw new Exception("Invalid DER structure");
        $public_bytes = substr($der, $pos + 3, 56);
        
        return bin2hex($public_bytes);
    }
}

// ====================================================================
// TESTE
// ====================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && basename(__FILE__) === basename($argv[0])) {
    echo "=== X448 COM PEM CURUPIRA ===\n\n";
    
    $test_priv = "04a03e649a71f90ede016a64ca6da5fe07ad44a89dc617736c6f22b68ae9f85057b6a2c49228bc7be86b3359f421a26c4c5a97a51c41419b";
    $test_pub_expected = "44f1de6732cd0f39748444c6091a507b102e97de2d89c098c885bb6498aeff09ad873af6b127e9dbd679d1b45059731060ea4a6a321dd0ed";
    
    echo "0. Teste de compatibilidade:\n";
    $test_pub = X448::x448_get_public_key($test_priv);
    echo "   Public key match: " . ($test_pub === $test_pub_expected ? "✓" : "✗") . "\n";
    
    echo "\n1. Gerando chave X448...\n";
    $priv = X448::generate_private_key();
    $pub = X448::x448_get_public_key($priv);
    echo "   Privada: " . substr($priv, 0, 32) . "...\n";
    echo "   Pública: " . substr($pub, 0, 32) . "...\n\n";
    
    echo "2. Gerando PEM sem senha...\n";
    $pem_plain = X448_PEM::private_to_pem_pkcs8($priv);
    echo "   " . explode("\n", $pem_plain)[0] . "\n";
    
    echo "\n3. Gerando PEM com senha 'teste123'...\n";
    $pem_enc = X448_PEM::private_to_pem_pkcs8($priv, 'teste123');
    $lines = explode("\n", $pem_enc);
    echo "   " . $lines[0] . "\n";
    if (strpos($pem_enc, "Proc-Type:") !== false) {
        echo "   " . $lines[1] . "\n";
        echo "   " . $lines[2] . "\n";
    }
    
    echo "\n4. Parse do PEM criptografado...\n";
    $parsed = X448_PEM::parse_private_pem_pkcs8($pem_enc, 'teste123');
    echo "   Chave recuperada: " . ($parsed === $priv ? "✓" : "✗") . "\n";
    
    echo "\n5. Gerando PEM público...\n";
    $pem_pub = X448_PEM::public_to_pem_pkcs8($pub);
    echo "   " . explode("\n", $pem_pub)[0] . "\n";
    
    echo "\n6. Teste de shared secret...\n";
    $shared = X448::x448_shared_secret($priv, $pub);
    echo "   Self shared: " . substr($shared, 0, 32) . "...\n";
    
    echo "\n✓ X448 com PEM Curupira funcionando!\n";
}
?>
