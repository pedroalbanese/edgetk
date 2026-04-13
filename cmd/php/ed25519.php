<?php
/**
 * ED25519 - Pure PHP Implementation
 * Com suporte a PKCS#8 PEM e criptografia Curupira-192-CBC
 */

// ====================================================================
// CURUPIRA BLOCK CIPHER IMPLEMENTATION
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
// ED25519 IMPLEMENTATION
// ====================================================================

class ED25519Pure
{
    private static $P = '57896044618658097711785492504343953926634992332820282019728792003956564819949';
    private static $N = '7237005577332262213973186563042994240857116359379907606001950938285454250989';
    private static $D = '37095705934669439343138083508754565189542113879843219016388785533085940283555';
    private static $I = '19681161376707505956807079304988542015446066515923890162744021073123829784752';
    private static $Gx = '15112221349535400772501151409588531511454012693041857206046113283949847762202';
    private static $Gy = '46316835694926478169428394003475163141307993866256225615783033603165251855960';
    private static $BYTE_LEN = 32;
    
    private static function bytes_to_little_int($b) {
        $r = '0';
        for ($i = 0; $i < strlen($b); $i++) {
            $r = bcadd($r, bcmul((string)ord($b[$i]), bcpow('256', (string)$i)));
        }
        return $r;
    }
    
    private static function little_int_to_bytes($n, $len) {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr((int)bcmod($n, '256'));
            $n = bcdiv($n, '256', 0);
        }
        return $out;
    }
    
    private static function mod($x) {
        $x = bcmod($x, self::$P);
        if (bccomp($x, '0') < 0) $x = bcadd($x, self::$P);
        return $x;
    }
    
    private static function addmod($a, $b) { return self::mod(bcadd($a, $b)); }
    private static function submod($a, $b) { return self::mod(bcsub($a, $b)); }
    private static function mulmod($a, $b) { return self::mod(bcmul($a, $b)); }
    
    private static function inv($x) {
        return bcpowmod($x, bcsub(self::$P, '2'), self::$P);
    }
    
    private static function addPoint($p, $q) {
        list($x1, $y1) = $p;
        list($x2, $y2) = $q;
        
        $x1x2 = self::mulmod($x1, $x2);
        $y1y2 = self::mulmod($y1, $y2);
        $x1y2 = self::mulmod($x1, $y2);
        $y1x2 = self::mulmod($y1, $x2);
        
        $dxy = self::mulmod(self::$D, self::mulmod($x1x2, $y1y2));
        
        $x = self::mulmod(
            self::addmod($x1y2, $y1x2),
            self::inv(self::addmod('1', $dxy))
        );
        
        $y = self::mulmod(
            self::addmod($y1y2, $x1x2),
            self::inv(self::submod('1', $dxy))
        );
        
        return [$x, $y];
    }
    
    private static function scalarMult($s, $P) {
        $Q = ['0', '1'];
        $T = $P;
        
        for ($i = 0; $i < 256; $i++) {
            if (bcmod($s, '2') == '1') {
                $Q = self::addPoint($Q, $T);
            }
            $T = self::addPoint($T, $T);
            $s = bcdiv($s, '2', 0);
        }
        return $Q;
    }
    
    private static function compress($x, $y) {
        $b = self::little_int_to_bytes($y, 32);
        $lsb = bcmod($x, '2');
        
        $last = ord($b[31]);
        if ($lsb == '1') $last |= 0x80;
        else $last &= 0x7F;
        
        $b[31] = chr($last);
        return $b;
    }
    
    private static function decompress($data) {
        if (strlen($data) != 32) return [null, null];
        
        $last = ord($data[31]);
        $sign = ($last >> 7) & 1;
        
        $y_bytes = $data;
        $y_bytes[31] = chr($last & 0x7F);
        $y = self::bytes_to_little_int($y_bytes);
        
        if (bccomp($y, self::$P) >= 0) return [null, null];
        
        $y2 = self::mulmod($y, $y);
        
        $u = self::submod($y2, '1');
        $v = self::addmod(self::mulmod(self::$D, $y2), '1');
        
        $x2 = self::mulmod($u, self::inv($v));
        
        $exp = bcdiv(bcadd(self::$P, '3'), '8', 0);
        $x = bcpowmod($x2, $exp, self::$P);
        
        if (bccomp(self::mulmod($x, $x), $x2) != 0) {
            $x = self::mulmod($x, self::$I);
            if (bccomp(self::mulmod($x, $x), $x2) != 0) {
                return [null, null];
            }
        }
        
        if (bcmod($x, '2') != $sign) {
            $x = self::submod('0', $x);
        }
        
        return [$x, $y];
    }
    
    private static function H($m) {
        return hash('sha512', $m, true);
    }
    
    public static function getPublicKey($sk_hex) {
        $sk = hex2bin($sk_hex);
        $h = self::H($sk);
        
        $a = substr($h, 0, 32);
        $a[0] = chr(ord($a[0]) & 248);
        $a[31] = chr((ord($a[31]) & 127) | 64);
        
        $a_int = self::bytes_to_little_int($a);
        
        $A = self::scalarMult($a_int, [self::$Gx, self::$Gy]);
        
        return bin2hex(self::compress($A[0], $A[1]));
    }
    
    public static function sign($sk_hex, $m) {
        $sk = hex2bin($sk_hex);
        $h = self::H($sk);
        
        $a = substr($h, 0, 32);
        $a[0] = chr(ord($a[0]) & 248);
        $a[31] = chr((ord($a[31]) & 127) | 64);
        
        $a_int = self::bytes_to_little_int($a);
        
        $prefix = substr($h, 32, 32);
        
        $r = self::bytes_to_little_int(self::H($prefix . $m));
        $r = bcmod($r, self::$N);
        
        $R = self::scalarMult($r, [self::$Gx, self::$Gy]);
        $Renc = self::compress($R[0], $R[1]);
        
        $A = self::scalarMult($a_int, [self::$Gx, self::$Gy]);
        $Aenc = self::compress($A[0], $A[1]);
        
        $k = self::bytes_to_little_int(self::H($Renc . $Aenc . $m));
        $k = bcmod($k, self::$N);
        
        $S = bcmod(bcadd($r, bcmul($k, $a_int)), self::$N);
        
        return $Renc . self::little_int_to_bytes($S, 32);
    }
    
    public static function verify($pk_hex, $m, $sig) {
        if (strlen($sig) != 64) return false;
        
        $R_bytes = substr($sig, 0, 32);
        $S_bytes = substr($sig, 32, 32);
        
        $A_bytes = hex2bin($pk_hex);
        
        $R = self::decompress($R_bytes);
        $A = self::decompress($A_bytes);
        
        if ($R[0] === null || $A[0] === null) return false;
        
        $S = self::bytes_to_little_int($S_bytes);
        if (bccomp($S, self::$N) >= 0) return false;
        
        $k = self::bytes_to_little_int(self::H($R_bytes . $A_bytes . $m));
        $k = bcmod($k, self::$N);
        
        $sB = self::scalarMult($S, [self::$Gx, self::$Gy]);
        $kA = self::scalarMult($k, $A);
        
        $Rp = self::addPoint($R, $kA);
        
        return (bccomp($sB[0], $Rp[0]) == 0 && bccomp($sB[1], $Rp[1]) == 0);
    }
    
    public static function generateKeyPair() {
        $private = random_bytes(32);
        $privateHex = bin2hex($private);
        $publicHex = self::getPublicKey($privateHex);
        return [$privateHex, $publicHex];
    }
}

// ====================================================================
// FUNÇÕES DE CRIPTOGRAFIA
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
// ED25519 PKCS#8 PEM FUNCTIONS
// ====================================================================

class ED25519_PEM
{
    public static function private_to_pem_pkcs8($private_key_hex, $password = null)
    {
        if (strlen($private_key_hex) != 64 || !ctype_xdigit($private_key_hex)) {
            throw new Exception("Invalid private key");
        }
        
        $private_key_bin = hex2bin($private_key_hex);
        
        // ED25519 OID: 1.3.101.112
        $ed25519_oid = "\x06\x03\x2b\x65\x70";
        
        $inner = "\x04\x20" . $private_key_bin;
        $private_key = "\x04" . chr(strlen($inner)) . $inner;
        $alg_id = "\x30" . chr(strlen($ed25519_oid)) . $ed25519_oid;
        $version = "\x02\x01\x00";
        $total = $version . $alg_id . $private_key;
        $pkcs8 = "\x30" . chr(strlen($total)) . $total;
        
        if ($password) {
            $encrypted = encrypt_private_key_pem($pkcs8, $password);
            return "-----BEGIN PRIVATE KEY-----\n" . $encrypted . "\n-----END PRIVATE KEY-----\n";
        } else {
            $b64 = base64_encode($pkcs8);
            $lines = str_split($b64, 64);
            return "-----BEGIN PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END PRIVATE KEY-----\n";
        }
    }
    
    public static function public_to_pem_pkcs8($public_key_hex)
    {
        if (strlen($public_key_hex) != 64 || !ctype_xdigit($public_key_hex)) {
            throw new Exception("Invalid public key");
        }
        
        $public_key_bin = hex2bin($public_key_hex);
        
        $ed25519_oid = "\x06\x03\x2b\x65\x70";
        $alg_id = "\x30" . chr(strlen($ed25519_oid)) . $ed25519_oid;
        $bit_string = "\x03\x21\x00" . $public_key_bin;
        $content = $alg_id . $bit_string;
        $der = "\x30" . chr(strlen($content)) . $content;
        
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        
        return "-----BEGIN PUBLIC KEY-----\n" . implode("\n", $lines) . "\n-----END PUBLIC KEY-----\n";
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
            
            if (strpos($line, "-----BEGIN PRIVATE KEY-----") === 0) continue;
            if (strpos($line, "-----END PRIVATE KEY-----") === 0) break;
            
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
        
        $pos = strpos($der, "\x04\x20");
        if ($pos === false) {
            $pos = strpos($der, "\x04\x22");
            if ($pos !== false) {
                $private_bytes = substr($der, $pos + 2, 32);
            } else {
                throw new Exception("Invalid DER structure");
            }
        } else {
            $private_bytes = substr($der, $pos + 2, 32);
        }
        
        if (strlen($private_bytes) != 32) {
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
        
        $pos = strpos($der, "\x03\x21\x00");
        if ($pos === false) {
            throw new Exception("Invalid DER structure");
        }
        $public_bytes = substr($der, $pos + 3, 32);
        
        return bin2hex($public_bytes);
    }
}

// ====================================================================
// TESTE
// ====================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && basename(__FILE__) === basename($argv[0])) {
    echo "=== ED25519 COM PEM CURUPIRA ===\n\n";
    
    // Teste RFC 8032
    $test_priv = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    $expected_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    $expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    
    echo "0. Teste de compatibilidade RFC 8032:\n";
    $pub = ED25519Pure::getPublicKey($test_priv);
    echo "   Public key match: " . ($pub === $expected_pub ? "✓" : "✗") . "\n";
    
    $sig = ED25519Pure::sign($test_priv, "");
    $sig_hex = bin2hex($sig);
    echo "   Signature match: " . ($sig_hex === $expected_sig ? "✓" : "✗") . "\n";
    
    $valid = ED25519Pure::verify($expected_pub, "", $sig);
    echo "   Verify: " . ($valid ? "✓" : "✗") . "\n\n";
    
    // Gerar chave aleatória
    echo "1. Gerando chave ED25519...\n";
    list($priv, $pub) = ED25519Pure::generateKeyPair();
    echo "   Privada: " . substr($priv, 0, 32) . "...\n";
    echo "   Pública: " . substr($pub, 0, 32) . "...\n\n";
    
    // PEM sem senha
    echo "2. Gerando PEM sem senha...\n";
    $pem_plain = ED25519_PEM::private_to_pem_pkcs8($priv);
    echo "   " . explode("\n", $pem_plain)[0] . "\n";
    
    // PEM com senha
    echo "\n3. Gerando PEM com senha 'teste123'...\n";
    $pem_enc = ED25519_PEM::private_to_pem_pkcs8($priv, 'teste123');
    $lines = explode("\n", $pem_enc);
    echo "   " . $lines[0] . "\n";
    if (strpos($pem_enc, "Proc-Type:") !== false) {
        echo "   " . $lines[1] . "\n";
        echo "   " . $lines[2] . "\n";
    }
    
    // Parse de volta
    echo "\n4. Parse do PEM criptografado...\n";
    $parsed = ED25519_PEM::parse_private_pem_pkcs8($pem_enc, 'teste123');
    echo "   Chave recuperada: " . ($parsed === $priv ? "✓" : "✗") . "\n";
    
    // PEM pública
    echo "\n5. Gerando PEM público...\n";
    $pem_pub = ED25519_PEM::public_to_pem_pkcs8($pub);
    echo "   " . explode("\n", $pem_pub)[0] . "\n";
    
    echo "\n✓ ED25519 com PEM Curupira funcionando!\n";
}
?>
