<?php
// ====================================================================
// CURUPIRA BLOCK CIPHER - LETTERSOUP MODE
// ====================================================================

/**
 * Generate cryptographically secure random bytes
 */
function random_bytes_bc($length) {
    // Se random_bytes existir, use ele (PHP 7+)
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }

    // Fallback seguro para PHP <7, usando random_int
    $bytes = '';
    for ($i = 0; $i < $length; $i++) {
        $bytes .= chr(random_int(0, 255));
    }

    return $bytes;
}

// ====================================================================
// CURUPIRA1 BLOCK CIPHER IMPLEMENTATION
// ====================================================================

class KeySizeError extends Exception {
    public function __construct($size) {
        parent::__construct("curupira1: invalid key size $size");
    }
}

class Curupira1Block {
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
// MARVIN MAC IMPLEMENTATION FOR LETTERSOUP
// ====================================================================

class MarvinMAC {
    const C = 0x2A;  // Constant c
    
    private $cipher;
    private $block_bytes;
    private $letter_soup_mode;
    
    private $buffer;
    private $R;
    private $O;
    private $m_length;
    
    public function __construct(Curupira1Block $cipher, $R = null, $letter_soup_mode = false) {
        $this->cipher = $cipher;
        $this->block_bytes = $cipher->BlockSize();
        $this->letter_soup_mode = $letter_soup_mode;
        
        if ($R !== null) {
            $this->InitWithR($R);
        } else {
            $this->Init();
        }
    }
    
    private function _xor(&$a, $b) {
        $len = min(strlen($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] = chr(ord($a[$i]) ^ ord($b[$i]));
        }
    }
    
    public function Init() {
        // Step 2 of Algorithm 1 - Page 4
        $this->buffer = str_repeat("\x00", $this->block_bytes);
        $this->R = str_repeat("\x00", $this->block_bytes);
        $this->O = str_repeat("\x00", $this->block_bytes);
        
        // Step 2 of Algorithm 1 - Page 4
        $left_padded_c = str_repeat("\x00", $this->block_bytes);
        $left_padded_c[$this->block_bytes - 1] = chr(self::C);
        
        $encrypted = $this->cipher->encrypt($left_padded_c);
        
        // XOR in-place
        for ($i = 0; $i < $this->block_bytes; $i++) {
            $this->R[$i] = chr(ord($encrypted[$i]) ^ ord($left_padded_c[$i]));
        }
        
        $this->O = $this->R;
    }
    
    public function InitWithR($R) {
        $this->buffer = str_repeat("\x00", $this->block_bytes);
        $this->R = str_repeat("\x00", $this->block_bytes);
        $this->O = str_repeat("\x00", $this->block_bytes);
        
        $this->R = substr($R, 0, $this->block_bytes);
        $this->O = substr($R, 0, $this->block_bytes);
    }
    
    private function updateOffset() {
        // Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
        $O0 = ord($this->O[0]);
        
        // Shift left (equivalent to copy(O[0:], O[1:12]) in Go)
        for ($i = 0; $i < 11; $i++) {
            $this->O[$i] = $this->O[$i + 1];
        }
        
        // Note: In Go, operations are with uint8, so overflow is automatic
        $O9 = ord($this->O[9]);
        $O10 = ord($this->O[10]);
        
        $this->O[9] = chr(($O9 ^ $O0 ^ ($O0 >> 3) ^ ($O0 >> 5)) & 0xFF);
        $this->O[10] = chr(($O10 ^ (($O0 << 5) & 0xFF) ^ (($O0 << 3) & 0xFF)) & 0xFF);
        $this->O[11] = chr($O0);
    }
    
    public function Update($a_data) {
        $a_length = strlen($a_data);
        $block_bytes = $this->block_bytes;
        
        $M = str_repeat("\x00", $block_bytes);
        $A = str_repeat("\x00", $block_bytes);
        
        $q = (int)($a_length / $block_bytes);
        $r = $a_length % $block_bytes;
        
        // Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
        $this->_xor($this->buffer, $this->R);
        
        for ($i = 0; $i < $q; $i++) {
            $M = substr($a_data, $i * $block_bytes, $block_bytes);
            $this->updateOffset();
            
            // XOR M with O
            for ($j = 0; $j < $block_bytes; $j++) {
                $M[$j] = chr(ord($M[$j]) ^ ord($this->O[$j]));
            }
            
            $A_bytes = $this->cipher->sct($M);
            $this->_xor($this->buffer, $A_bytes);
        }
        
        if ($r != 0) {
            $M = substr($a_data, $q * $block_bytes, $r) . str_repeat("\x00", $block_bytes - $r);
            $this->updateOffset();
            
            // XOR M with O
            for ($j = 0; $j < $block_bytes; $j++) {
                $M[$j] = chr(ord($M[$j]) ^ ord($this->O[$j]));
            }
            
            $A_bytes = $this->cipher->sct($M);
            $this->_xor($this->buffer, $A_bytes);
        }
        
        $this->m_length = $a_length;
    }
    
    public function GetTag($tag = null, $tag_bits = 96) {
        if ($tag === null) {
            $tag = str_repeat("\x00", (int)($tag_bits / 8));
        }
        
        $block_bytes = $this->block_bytes;
        
        if ($this->letter_soup_mode) {
            $tag = substr($this->buffer, 0, $block_bytes);
            return substr($tag, 0, (int)($tag_bits / 8));
        }
        
        // Steps 6-9 of Algorithm 1 - Page 4
        $A = $this->buffer;
        $encrypted_a = str_repeat("\x00", $block_bytes);
        $aux_value1 = str_repeat("\x00", $block_bytes);
        $aux_value2 = str_repeat("\x00", $block_bytes);
        
        // auxValue1 = rpad(bin(n-tagBits)||1)
        $diff = $this->cipher->BlockSize() * 8 - $tag_bits;
        
        if ($diff == 0) {
            $aux_value1[0] = chr(0x80);
            $aux_value1[1] = chr(0x00);
        } elseif ($diff < 0) {
            $aux_value1[0] = chr($diff & 0xFF);
            $aux_value1[1] = chr(0x80);
        } else {
            $diff = ($diff << 1) | 0x01;
            // Go code does: for diff > 0 { diff = int8(diff << 1) }
            // This is equivalent to shifting until the most significant bit is 1
            while ($diff > 0 && ($diff & 0x80) == 0) {
                $diff = ($diff << 1) & 0xFF;
            }
            $aux_value1[0] = chr($diff & 0xFF);
            $aux_value1[1] = chr(0x00);
        }
        
        // auxValue2 = lpad(bin(|M|))
        $processed_bits = 8 * $this->m_length;
        for ($i = 0; $i < 4; $i++) {
            $aux_value2[$block_bytes - $i - 1] = chr(($processed_bits >> (8 * $i)) & 0xFF);
        }
        
        // XOR in-place
        for ($i = 0; $i < $block_bytes; $i++) {
            $A[$i] = chr(ord($A[$i]) ^ ord($aux_value1[$i]) ^ ord($aux_value2[$i]));
        }
        
        $encrypted_a = $this->cipher->encrypt($A);
        
        $tag_bytes = (int)($tag_bits / 8);
        $tag = substr($encrypted_a, 0, $tag_bytes);
        return $tag;
    }
}

// ====================================================================
// LETTERSOUP AEAD IMPLEMENTATION
// ====================================================================

class LetterSoupAEAD {
    private $cipher;
    private $block_bytes;
    private $mac;
    
    private $m_length;
    private $h_length;
    private $iv;
    private $A;
    private $D;
    private $R;
    private $L;
    
    public function __construct(Curupira1Block $cipher) {
        $this->cipher = $cipher;
        $this->block_bytes = $cipher->BlockSize();
        $this->mac = new MarvinMAC($cipher, null, true);
        
        $this->m_length = 0;
        $this->h_length = 0;
        $this->iv = "";
        $this->A = "";
        $this->D = "";
        $this->R = "";
        $this->L = "";
    }
    
    public function SetIV($iv) {
        $iv_length = strlen($iv);
        $block_bytes = $this->block_bytes;
        
        $this->iv = $iv;
        $this->L = "";
        
        // Step 2 of Algorithm 2 - Page 6
        $this->R = str_repeat("\x00", $block_bytes);
        $left_padded_n = str_repeat("\x00", $block_bytes);
        
        // copy(leftPaddedN[blockBytes - ivLength:], iv[:blockBytes])
        $start_idx = $block_bytes - $iv_length;
        if ($start_idx < 0) {
            $start_idx = 0;
        }
        $copy_len = min($iv_length, $block_bytes);
        for ($i = 0; $i < $copy_len; $i++) {
            $left_padded_n[$start_idx + $i] = $iv[$i];
        }
        
        // this.cipher.Encrypt(this.R, leftPaddedN)
        $this->R = $this->cipher->encrypt($left_padded_n);
        
        // xor(this.R, leftPaddedN)
        for ($i = 0; $i < $block_bytes; $i++) {
            $this->R[$i] = chr(ord($this->R[$i]) ^ ord($left_padded_n[$i]));
        }
    }
    
    public function Update($a_data) {
        $a_length = strlen($a_data);
        $block_bytes = $this->block_bytes;
        
        // Step 4 of Algorithm 2 - Page 6 (L and part of D)
        $this->L = str_repeat("\x00", $block_bytes);
        $this->D = str_repeat("\x00", $block_bytes);
        
        $empty = str_repeat("\x00", $block_bytes);
        
        $this->h_length = $a_length;
        $this->L = $this->cipher->encrypt($empty);
        
        $this->mac->InitWithR($this->L);
        $this->mac->Update($a_data);
        $this->D = $this->mac->GetTag($this->D, $this->cipher->BlockSize() * 8);
    }
    
    private function _xor(&$a, $b) {
        $len = min(strlen($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] = chr(ord($a[$i]) ^ ord($b[$i]));
        }
    }
    
    private function updateOffset(&$O) {
        // Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
        $O0 = ord($O[0]);
        
        // Shift left (equivalent to copy(O[0:], O[1:12]) in Go)
        for ($i = 0; $i < 11; $i++) {
            $O[$i] = $O[$i + 1];
        }
        
        // Note: In Go, operations are with uint8, so overflow is automatic
        $O9 = ord($O[9]);
        $O10 = ord($O[10]);
        
        $O[9] = chr(($O9 ^ $O0 ^ ($O0 >> 3) ^ ($O0 >> 5)) & 0xFF);
        $O[10] = chr(($O10 ^ (($O0 << 5) & 0xFF) ^ (($O0 << 3) & 0xFF)) & 0xFF);
        $O[11] = chr($O0);
    }
    
    private function LFSRC($m_data, &$c_data) {
        $m_length = strlen($m_data);
        $block_bytes = $this->block_bytes;
        
        $M = str_repeat("\x00", $block_bytes);
        $C = str_repeat("\x00", $block_bytes);
        $O = $this->R;
        
        $q = (int)($m_length / $block_bytes);
        $r = $m_length % $block_bytes;
        
        for ($i = 0; $i < $q; $i++) {
            $M = substr($m_data, $i * $block_bytes, $block_bytes);
            $this->updateOffset($O);
            $C = $this->cipher->encrypt($O);
            
            // XOR C with M
            for ($j = 0; $j < $block_bytes; $j++) {
                $C[$j] = chr(ord($C[$j]) ^ ord($M[$j]));
            }
            
            for ($j = 0; $j < $block_bytes; $j++) {
                $c_data[$i * $block_bytes + $j] = $C[$j];
            }
        }
        
        if ($r != 0) {
            $M = substr($m_data, $q * $block_bytes, $r) . str_repeat("\x00", $block_bytes - $r);
            $this->updateOffset($O);
            $C = $this->cipher->encrypt($O);
            
            // XOR C with M
            for ($j = 0; $j < $block_bytes; $j++) {
                $C[$j] = chr(ord($C[$j]) ^ ord($M[$j]));
            }
            
            for ($j = 0; $j < $r; $j++) {
                $c_data[$q * $block_bytes + $j] = $C[$j];
            }
        }
    }
    
    public function Encrypt(&$dst, $src) {
        $m_length = strlen($src);
        $block_bytes = $this->block_bytes;
        
        // Step 3 of Algorithm 2 - Page 6 (C and part of A)
        $this->A = str_repeat("\x00", $block_bytes);
        $this->m_length = $m_length;
        
        // if dst == nil { dst = make([]byte, blockBytes) }
        if (strlen($dst) == 0) {
            $dst = str_repeat("\x00", $block_bytes);
        }
        
        $this->LFSRC($src, $dst);
        
        $this->mac->InitWithR($this->R);
        $this->mac->Update($dst);
        $this->A = $this->mac->GetTag($this->A, $this->cipher->BlockSize() * 8);
    }
    
    public function Decrypt(&$dst, $src) {
        $this->LFSRC($src, $dst);
    }
    
    public function GetTag($tag = null, $tag_bits = 96) {
        if ($tag === null) {
            $tag = str_repeat("\x00", (int)($tag_bits / 8));
        }
        
        $block_bytes = $this->block_bytes;
        
        // Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
        $Atemp = $this->A;
        if (strlen($Atemp) > $block_bytes) {
            $Atemp = substr($Atemp, 0, $block_bytes);
        }
        
        $aux_value1 = str_repeat("\x00", $block_bytes);
        $aux_value2 = str_repeat("\x00", $block_bytes);
        
        // auxValue1 = rpad(bin(n-tagBits)||1)
        $diff = $this->cipher->BlockSize() * 8 - $tag_bits;
        
        if ($diff == 0) {
            $aux_value1[0] = chr(0x80);
            $aux_value1[1] = chr(0x00);
        } elseif ($diff < 0) {
            $aux_value1[0] = chr($diff & 0xFF);
            $aux_value1[1] = chr(0x80);
        } else {
            $diff = ($diff << 1) | 0x01;
            // Go code does: for diff > 0 { diff = int8(diff << 1) }
            while ($diff > 0 && ($diff & 0x80) == 0) {
                $diff = ($diff << 1) & 0xFF;
            }
            $aux_value1[0] = chr($diff & 0xFF);
            $aux_value1[1] = chr(0x00);
        }
        
        // auxValue2 = lpad(bin(|M|))
        for ($i = 0; $i < 4; $i++) {
            $aux_value2[$block_bytes - $i - 1] = chr(($this->m_length * 8 >> (8 * $i)) & 0xFF);
        }
        
        // copy(this.A[0:], Atemp[0:blockBytes]) - in Go, but doesn't seem necessary
        $this->_xor($Atemp, $aux_value1);
        $this->_xor($Atemp, $aux_value2);
        
        // Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
        if (strlen($this->L) != 0) {
            // auxValue2 = lpad(bin(|H|))
            $aux_value2 = str_repeat("\x00", $block_bytes);
            for ($i = 0; $i < 4; $i++) {
                $aux_value2[$block_bytes - $i - 1] = chr(($this->h_length * 8 >> (8 * $i)) & 0xFF);
            }
            
            $Dtemp = $this->D;
            if (strlen($Dtemp) > $block_bytes) {
                $Dtemp = substr($Dtemp, 0, $block_bytes);
            }
            
            $this->_xor($Dtemp, $aux_value1);
            $this->_xor($Dtemp, $aux_value2);
            $aux_value1_bytes = $this->cipher->sct($Dtemp);
            $this->_xor($Atemp, $aux_value1_bytes);
        }
        
        // Step 7 of Algorithm 2 - Page 6
        $aux_value1_bytes = $this->cipher->encrypt($Atemp);
        
        $tag_bytes = (int)($tag_bits / 8);
        $tag = substr($aux_value1_bytes, 0, $tag_bytes);
        return $tag;
    }
}

// ====================================================================
// LETTERSOUP AEAD WRAPPER FUNCTIONS
// ====================================================================

/**
 * Encrypt using LetterSoup AEAD mode
 */
function lettersoup_encrypt($key, $plaintext, $aad = '') {
    // Generate random nonce (12 bytes)
    $nonce = random_bytes_bc(12);
    
    // Create cipher
    $cipher = new Curupira1Block($key);
    
    // Create LetterSoup
    $aead = new LetterSoupAEAD($cipher);
    
    // Set IV
    $aead->SetIV($nonce);
    
    // Process AAD
    if ($aad !== '') {
        $aead->Update($aad);
    } else {
        $aead->Update('');
    }
    
    // Encrypt
    $ciphertext = str_repeat("\x00", strlen($plaintext));
    $aead->Encrypt($ciphertext, $plaintext);
    
    // Get tag
    $tag = $aead->GetTag(null, 96);
    
    // Output: nonce + tag + ciphertext
    return $nonce . $tag . $ciphertext;
}

/**
 * Decrypt using LetterSoup AEAD mode
 */
function lettersoup_decrypt($key, $encrypted_data, $aad = '') {
    // Check minimum size
    if (strlen($encrypted_data) < 24) {
        throw new Exception("Input too short. Must contain at least 24 bytes (nonce + tag)");
    }
    
    // Extract nonce, tag and ciphertext
    $nonce = substr($encrypted_data, 0, 12);
    $tag = substr($encrypted_data, 12, 12);
    $ciphertext = substr($encrypted_data, 24);
    
    // Create cipher
    $cipher = new Curupira1Block($key);
    
    // Create LetterSoup for decryption
    $aead = new LetterSoupAEAD($cipher);
    $aead->SetIV($nonce);
    
    // Process AAD
    if ($aad !== '') {
        $aead->Update($aad);
    } else {
        $aead->Update('');
    }
    
    // Decrypt
    $plaintext = str_repeat("\x00", strlen($ciphertext));
    $aead->Decrypt($plaintext, $ciphertext);
    
    // Verify authentication (re-encrypt to verify tag)
    $aead_verify = new LetterSoupAEAD($cipher);
    $aead_verify->SetIV($nonce);
    
    if ($aad !== '') {
        $aead_verify->Update($aad);
    } else {
        $aead_verify->Update('');
    }
    
    $test_ciphertext = str_repeat("\x00", strlen($plaintext));
    $aead_verify->Encrypt($test_ciphertext, $plaintext);
    $test_tag = $aead_verify->GetTag(null, 96);
    
    // Compare tags
    if ($tag !== $test_tag) {
        throw new Exception("Authentication failed! Expected tag: " . bin2hex($test_tag) . 
                          ", Received tag: " . bin2hex($tag));
    }
    
    return $plaintext;
}

// ====================================================================
// TEST FUNCTIONS
// ====================================================================

/**
 * Test LetterSoup AEAD functionality
 */
function test_lettersoup() {
    echo "=== Teste do modo LetterSoup AEAD ===\n\n";
    
    // Test key (24 bytes = 192 bits)
    $test_key = hex2bin("0228674ed28f695ed88a39ec0228674ed28f695ed88a39ec");
    $test_plaintext = "Test message for LetterSoup";
    $test_aad = "metadata";
    
    echo "Chave de teste: " . bin2hex($test_key) . "\n";
    echo "Texto simples: $test_plaintext\n";
    echo "AAD: $test_aad\n";
    
    // Test 1: Encrypt/decrypt básico
    echo "\n1. Teste básico de criptografia/descriptografia:\n";
    try {
        $encrypted = lettersoup_encrypt($test_key, $test_plaintext, $test_aad);
        echo "   Criptografado com sucesso (" . strlen($encrypted) . " bytes)\n";
        
        $decrypted = lettersoup_decrypt($test_key, $encrypted, $test_aad);
        echo "   Descriptografado: $decrypted\n";
        echo "   Igual ao original: " . (($decrypted === $test_plaintext) ? "SIM" : "NÃO") . "\n";
    } catch (Exception $e) {
        echo "   ERRO: " . $e->getMessage() . "\n";
    }
    
    // Test 2: AAD vazio
    echo "\n2. Teste com AAD vazio:\n";
    try {
        $encrypted_empty = lettersoup_encrypt($test_key, $test_plaintext, '');
        echo "   Criptografado com AAD vazio\n";
        
        $decrypted_empty = lettersoup_decrypt($test_key, $encrypted_empty, '');
        echo "   Descriptografado: $decrypted_empty\n";
        echo "   Igual ao original: " . (($decrypted_empty === $test_plaintext) ? "SIM" : "NÃO") . "\n";
    } catch (Exception $e) {
        echo "   ERRO: " . $e->getMessage() . "\n";
    }
    
    // Test 3: AAD diferente
    echo "\n3. Teste com AAD diferente:\n";
    try {
        $encrypted_diff = lettersoup_encrypt($test_key, $test_plaintext, 'different_aad');
        echo "   Criptografado com AAD diferente\n";
        
        // Tentar descriptografar com AAD errado (deve falhar)
        try {
            $decrypted_wrong = lettersoup_decrypt($test_key, $encrypted_diff, $test_aad);
            echo "   DESCRIPTADO COM AAD ERRADO (não deveria funcionar!)\n";
        } catch (Exception $e) {
            echo "   Falha de autenticação (esperada) com AAD errado\n";
        }
        
        // Descriptografar com AAD correto
        $decrypted_correct = lettersoup_decrypt($test_key, $encrypted_diff, 'different_aad');
        echo "   Descriptografado com AAD correto: $decrypted_correct\n";
        echo "   Igual ao original: " . (($decrypted_correct === $test_plaintext) ? "SIM" : "NÃO") . "\n";
    } catch (Exception $e) {
        echo "   ERRO: " . $e->getMessage() . "\n";
    }
    
    echo "\n=== Teste do LetterSoup concluído ===\n";
}

/**
 * Test basic Curupira cipher functionality
 */
function test_curupira_basic() {
    echo "=== Teste básico da cifra Curupira ===\n\n";
    
    // Teste com diferentes tamanhos de chave
    $test_cases = [
        [
            'name' => 'Chave 12 bytes (96 bits)',
            'key' => hex2bin('0123456789abcdef01234567'),
            'plaintext' => 'Hello World!'
        ],
        [
            'name' => 'Chave 18 bytes (144 bits)',
            'key' => hex2bin('0123456789abcdef0123456789abcdef012345'),
            'plaintext' => 'Hello World!'
        ],
        [
            'name' => 'Chave 24 bytes (192 bits)',
            'key' => hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef'),
            'plaintext' => 'Hello World!'
        ]
    ];
    
    foreach ($test_cases as $test) {
        echo $test['name'] . ":\n";
        try {
            $cipher = new Curupira1Block($test['key']);
            
            // Testar cifra básica
            $encrypted = $cipher->encrypt($test['plaintext']);
            $decrypted = $cipher->decrypt($encrypted);
            
            echo "  Plaintext: " . $test['plaintext'] . "\n";
            echo "  Criptografado (hex): " . bin2hex($encrypted) . "\n";
            echo "  Descriptografado: " . $decrypted . "\n";
            echo "  Correto: " . ($decrypted === $test['plaintext'] ? "SIM" : "NÃO") . "\n\n";
            
        } catch (Exception $e) {
            echo "  ERRO: " . $e->getMessage() . "\n\n";
        }
    }
}

// ====================================================================
// COMMAND LINE INTERFACE FOR LETTERSOUP
// ====================================================================

/**
 * Command line interface for LetterSoup operations
 */
function cli_lettersoup() {
    global $argc, $argv;
    
    if ($argc < 2) {
        echo "Uso: php " . basename(__FILE__) . " [comando]\n";
        echo "Comandos:\n";
        echo "  test           - Testar funcionalidade LetterSoup\n";
        echo "  encrypt        - Criptografar dados\n";
        echo "  decrypt        - Descriptografar dados\n";
        echo "  basic          - Testes básicos da cifra Curupira\n";
        exit(1);
    }
    
    $command = $argv[1];
    
    switch ($command) {
        case 'test':
            test_lettersoup();
            break;
            
        case 'encrypt':
            if ($argc < 3) {
                echo "Uso: php " . basename(__FILE__) . " encrypt <chave_hex> [aad]\n";
                echo "  Exemplo: php " . basename(__FILE__) . " encrypt 0228674ed28f695ed88a39ec0228674ed28f695ed88a39ec metadata\n";
                echo "  Tamanhos de chave suportados: 12, 18 ou 24 bytes (96, 144 ou 192 bits)\n";
                exit(1);
            }
            
            $key_hex = $argv[2];
            $aad = isset($argv[3]) ? $argv[3] : '';
            
            // Ler entrada do stdin
            if (posix_isatty(STDIN)) {
                echo "Digite a mensagem para criptografar (Ctrl+D para terminar):\n";
            }
            $input = stream_get_contents(STDIN);
            
            try {
                $key = hex2bin($key_hex);
                if (!$key) {
                    throw new Exception("Chave hexadecimal inválida");
                }
                
                $encrypted = lettersoup_encrypt($key, $input, $aad);
                
                // Saída binária
                fwrite(STDOUT, $encrypted);
            } catch (Exception $e) {
                echo "ERRO: " . $e->getMessage() . "\n";
                exit(1);
            }
            break;
            
        case 'decrypt':
            if ($argc < 3) {
                echo "Uso: php " . basename(__FILE__) . " decrypt <chave_hex> [aad]\n";
                echo "  Exemplo: php " . basename(__FILE__) . " decrypt 0228674ed28f695ed88a39ec0228674ed28f695ed88a39ec metadata\n";
                exit(1);
            }
            
            $key_hex = $argv[2];
            $aad = isset($argv[3]) ? $argv[3] : '';
            
            // Ler entrada do stdin
            $input = stream_get_contents(STDIN);
            
            try {
                $key = hex2bin($key_hex);
                if (!$key) {
                    throw new Exception("Chave hexadecimal inválida");
                }
                
                $decrypted = lettersoup_decrypt($key, $input, $aad);
                
                // Saída binária
                fwrite(STDOUT, $decrypted);
            } catch (Exception $e) {
                echo "ERRO: " . $e->getMessage() . "\n";
                exit(1);
            }
            break;
            
        case 'basic':
            test_curupira_basic();
            break;
            
        default:
            echo "Comando desconhecido: $command\n";
            break;
    }
}

// ====================================================================
// MAIN EXECUTION
// ====================================================================

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    // Run the CLI interface
    cli_lettersoup();
}

?>
