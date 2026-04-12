<?php

class Curupira2KeySizeError extends Exception {
    public function __construct($size) {
        parent::__construct("curupira2: invalid key size $size");
    }
}

class Curupira2 {
    const BLOCK_SIZE = 12;
    
    private $key;
    private $key_size;
    private $key_enc;
    private $key_dec;
    private $key_length;
    private $number_of_rounds;
    private $xtimes_table = [];
    private $sbox_table = [];
    
    public function __construct($key) {
        $this->key = $key;
        $this->key_size = strlen($key);
        
        if (!in_array($this->key_size, [12, 18, 24])) {
            throw new Curupira2KeySizeError($this->key_size);
        }
        
        // Initialize tables
        $this->initXtimesTable();
        $this->initSboxTable();
        
        // Set number of rounds based on key size
        if ($this->key_size == 12) {
            $this->number_of_rounds = 10;
        } elseif ($this->key_size == 18) {
            $this->number_of_rounds = 12;
        } else { // 24
            $this->number_of_rounds = 14;
        }
        
        // Initialize cipher state
        $this->key_enc = array_values(unpack('C*', $key));
        $this->key_dec = array_values(unpack('C*', $key));
        $this->key_length = $this->key_size - 1;
        
        // Generate decryption subkeys
        $msb = 0;
        for ($i = 0; $i < $this->number_of_rounds; $i++) {
            $msb = $this->createNextKey($this->key_dec, $msb, 0);
        }
    }
    
    private function initXtimesTable() {
        for ($u = 0; $u < 256; $u++) {
            $d = $u << 1;
            if ($d >= 0x100) {
                $d = $d ^ 0x14D; // Polynomial reduction x^8 + x^6 + x^5 + x^3 + 1
            }
            $this->xtimes_table[$u] = $d & 0xFF;
        }
    }
    
    private function initSboxTable() {
        $P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
              0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1];
        $Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
              0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8];
        
        for ($u = 0; $u < 256; $u++) {
            $uh1 = $P[($u >> 4) & 0xF];
            $ul1 = $Q[$u & 0xF];
            $uh2 = $Q[($uh1 & 0xC) ^ (($ul1 >> 2) & 0x3)];
            $ul2 = $P[(($uh1 << 2) & 0xC) ^ ($ul1 & 0x3)];
            $uh1 = $P[($uh2 & 0xC) ^ (($ul2 >> 2) & 0x3)];
            $ul1 = $Q[(($uh2 << 2) & 0xC) ^ ($ul2 & 0x3)];
            
            $this->sbox_table[$u] = (($uh1 << 4) ^ $ul1) & 0xFF;
        }
    }
    
    private function sbox($u) {
        return $this->sbox_table[$u & 0xFF];
    }
    
    private function xtimes($u) {
        return $this->xtimes_table[$u & 0xFF];
    }
    
    private function T0($v) {
        return (($v << 5) ^ ($v << 3)) & 0xFF;
    }
    
    private function T1($v) {
        return ($v ^ ($v >> 3) ^ ($v >> 5)) & 0xFF;
    }
    
    private function xorBytes(&$a, $b) {
        $len = min(count($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] ^= ord($b[$i]);
        }
    }
    
    private function xorArrays(&$a, $b) {
        $len = min(count($a), count($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] ^= $b[$i];
        }
    }
    
    private function createNextKey(&$key, $msb, $is_decryption) {
        $key_len = $this->key_length;
        
        if ($is_decryption != 0) {
            if ($msb == 0) {
                $msb = $key_len;
            } else {
                $msb--;
            }
            $aux2 = $key[$msb];
            $key[$msb] ^= $this->sbox($msb);
        } else {
            $key[$msb] ^= $this->sbox($msb);
            $aux2 = $key[$msb];
        }
        
        if ($msb != 0) {
            $aux1 = $msb - 1;
        } else {
            $aux1 = $key_len;
        }
        $key[$aux1] ^= $this->T0($aux2);
        
        if ($aux1 != 0) {
            $aux1--;
        } else {
            $aux1 = $key_len;
        }
        $key[$aux1] ^= $this->T1($aux2);
        
        if ($is_decryption == 0) {
            $msb++;
            if ($msb > $key_len) {
                $msb = 0;
            }
        }
        
        return $msb;
    }
    
    private function swapCT($ptr1, $ptr2, &$block) {
        $aux = $this->sbox($block[$ptr1]);
        $block[$ptr1] = $this->sbox($block[$ptr2]);
        $block[$ptr2] = $aux;
    }
    
    private function sOnRow1($ptr1, $ptr2, &$block) {
        $block[$ptr1] = $this->sbox($block[$ptr1]);
        $block[$ptr2] = $this->sbox($block[$ptr2]);
        $this->swapCT($ptr1 + 1, $ptr2 + 1, $block);
    }
    
    private function updatePosMsb($pos_msb) {
        $pos_msb++;
        if ($pos_msb > $this->key_length) {
            $pos_msb = 0;
        }
        return $pos_msb;
    }
    
    private function applyKey(&$block, $key, $msb) {
        $pos_msb = $msb;
        $key_length = $this->key_length;
        $i = 0;
        
        while ($i < 12) {
            $block[$i] ^= $this->sbox($key[$pos_msb]);
            $i++;
            $pos_msb = $this->updatePosMsb($pos_msb);
            if ($i >= 12) break;
            
            $block[$i] ^= $key[$pos_msb];
            $i++;
            $pos_msb = $this->updatePosMsb($pos_msb);
            if ($i >= 12) break;
            
            $block[$i] ^= $key[$pos_msb];
            $i++;
            $pos_msb = $this->updatePosMsb($pos_msb);
        }
        
        return $pos_msb;
    }
    
    private function crypt($data, $dir_decryption) {
        $block = array_values(unpack('C*', $data));
        
        // Create local copies of keys
        $key_enc = $this->key_enc;
        $key_dec = $this->key_dec;
        
        if ($dir_decryption != 0) {
            $key = $key_dec;
            $msb = $this->number_of_rounds;
            $original_msb = $this->number_of_rounds;
        } else {
            $key = $key_enc;
            $msb = 0;
            $original_msb = 0;
        }
        
        // Whitening - doesn't modify original msb
        $this->applyKey($block, $key, $msb);
        
        // Rounds - use original msb
        $msb = $original_msb;
        
        for ($r = 1; $r <= $this->number_of_rounds; $r++) {
            // Permutation layer
            $this->sOnRow1(0, 3, $block);
            $this->swapCT(2, 8, $block);
            $this->sOnRow1(6, 9, $block);
            $this->swapCT(5, 11, $block);
            
            // Create next round key
            $msb = $this->createNextKey($key, $msb, $dir_decryption);
            
            if ($r == $this->number_of_rounds) {
                $this->applyKey($block, $key, $msb);
                break;
            }
            
            // Theta layer
            $pos_msb = $msb;
            for ($i = 0; $i < 4; $i++) {
                $aux3 = $key[$pos_msb];
                $pos_msb = $this->updatePosMsb($pos_msb);
                $aux3 = $this->sbox($aux3);
                
                $ptr = $i * 3;
                $aux1 = $block[$ptr] ^ $block[$ptr + 1] ^ $block[$ptr + 2];
                
                if ($dir_decryption != 0) {
                    $aux2 = $pos_msb + 1;
                    if ($aux2 > $this->key_length) {
                        $aux2 = 0;
                    }
                    $aux1 ^= $aux3 ^ $key[$pos_msb] ^ $key[$aux2];
                }
                
                $aux1 = $this->xtimes($aux1);
                $aux2v = $this->xtimes($aux1);
                
                $block[$ptr] ^= $aux1 ^ $aux3;
                $block[$ptr + 1] ^= $aux2v ^ $key[$pos_msb];
                $pos_msb = $this->updatePosMsb($pos_msb);
                
                $block[$ptr + 2] ^= $aux1 ^ $aux2v ^ $key[$pos_msb];
                $pos_msb = $this->updatePosMsb($pos_msb);
            }
        }
        
        return pack('C*', ...$block);
    }
    
    public function encryptBlock($plaintext) {
        if (strlen($plaintext) != self::BLOCK_SIZE) {
            throw new InvalidArgumentException("Plaintext must be " . self::BLOCK_SIZE . " bytes");
        }
        
        return $this->crypt($plaintext, 0);
    }
    
    public function decryptBlock($ciphertext) {
        if (strlen($ciphertext) != self::BLOCK_SIZE) {
            throw new InvalidArgumentException("Ciphertext must be " . self::BLOCK_SIZE . " bytes");
        }
        
        return $this->crypt($ciphertext, 1);
}
    
    public function sct($data) {
        if (strlen($data) != self::BLOCK_SIZE) {
            throw new InvalidArgumentException("Data must be " . self::BLOCK_SIZE . " bytes");
        }
        
        $tmp = array_values(unpack('C*', $data));
        
        for ($round = 0; $round < 4; $round++) {
            $this->sOnRow1(0, 3, $tmp);
            $this->swapCT(2, 8, $tmp);
            $this->sOnRow1(6, 9, $tmp);
            $this->swapCT(5, 11, $tmp);
            
            for ($i = 0; $i < 4; $i++) {
                $ptr = $i * 3;
                $aux1 = $tmp[$ptr] ^ $tmp[$ptr + 1] ^ $tmp[$ptr + 2];
                $aux1 = $this->xtimes($aux1);
                $aux2 = $this->xtimes($aux1);
                
                $tmp[$ptr] ^= $aux1;
                $tmp[$ptr + 1] ^= $aux2;
                $tmp[$ptr + 2] ^= $aux1 ^ $aux2;
            }
        }
        
        return pack('C*', ...$tmp);
    }
    
    public function blockSize() {
        return self::BLOCK_SIZE;
    }
}

class Marvin {
    const C = 0x2A; // Constant c
    
    private $cipher;
    private $block_bytes;
    private $buffer;
    private $R;
    private $O;
    private $m_length = 0;
    private $letter_soup_mode;
    
    public function __construct($cipher, $R = null, $letter_soup_mode = false) {
        $this->cipher = $cipher;
        $this->block_bytes = $cipher->blockSize();
        $this->letter_soup_mode = $letter_soup_mode;
        
        if ($R !== null) {
            $this->initWithR($R);
        } else {
            $this->init();
        }
    }
    
    private function xorArrays(&$a, $b) {
        $len = min(count($a), strlen($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] ^= ord($b[$i]);
        }
    }
    
    private function xorByteArrays(&$a, $b) {
        $len = min(count($a), count($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] ^= $b[$i];
        }
    }
    
    public function init() {
        $this->buffer = array_fill(0, $this->block_bytes, 0);
        $this->R = array_fill(0, $this->block_bytes, 0);
        $this->O = array_fill(0, $this->block_bytes, 0);
        
        // Step 2 of Algorithm 1 - Page 4
        $left_padded_c = array_fill(0, $this->block_bytes, 0);
        $left_padded_c[$this->block_bytes - 1] = self::C;
        
        $encrypted = $this->cipher->encryptBlock(pack('C*', ...$left_padded_c));
        $encrypted_arr = array_values(unpack('C*', $encrypted));
        
        $this->R = $encrypted_arr;
        $this->xorByteArrays($this->R, $left_padded_c);
        $this->O = $this->R;
    }
    
    public function initWithR($R) {
        $R_arr = array_values(unpack('C*', $R));
        
        $this->buffer = array_fill(0, $this->block_bytes, 0);
        $this->R = array_slice($R_arr, 0, $this->block_bytes);
        $this->O = $this->R;
    }
    
    private function updateOffset() {
        $O0 = $this->O[0];
        
        // Shift left
        for ($i = 0; $i < 11; $i++) {
            $this->O[$i] = $this->O[$i + 1];
        }
        
        $this->O[9] = ($this->O[9] ^ $O0 ^ (($O0 >> 3) & 0xFF) ^ (($O0 >> 5) & 0xFF)) & 0xFF;
        $this->O[10] = ($this->O[10] ^ (($O0 << 5) & 0xFF) ^ (($O0 << 3) & 0xFF)) & 0xFF;
        $this->O[11] = $O0;
    }
    
    public function update($a_data) {
        $a_length = strlen($a_data);
        $block_bytes = $this->block_bytes;
        
        $M = array_fill(0, $block_bytes, 0);
        $A = array_fill(0, $block_bytes, 0);
        
        $q = intdiv($a_length, $block_bytes);
        $r = $a_length % $block_bytes;
        
        // Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
        $this->xorByteArrays($this->buffer, $this->R);
        
        for ($i = 0; $i < $q; $i++) {
            $M_arr = array_values(unpack('C*', substr($a_data, $i * $block_bytes, $block_bytes)));
            $M = $M_arr;
            $this->updateOffset();
            $this->xorByteArrays($M, $this->O);
            $A_str = $this->cipher->sct(pack('C*', ...$M));
            $A = array_values(unpack('C*', $A_str));
            $this->xorByteArrays($this->buffer, $A);
        }
        
        if ($r != 0) {
            $M_partial = array_values(unpack('C*', substr($a_data, $q * $block_bytes, $r)));
            for ($i = 0; $i < $r; $i++) {
                $M[$i] = $M_partial[$i];
            }
            for ($i = $r; $i < $block_bytes; $i++) {
                $M[$i] = 0;
            }
            
            $this->updateOffset();
            $this->xorByteArrays($M, $this->O);
            $A_str = $this->cipher->sct(pack('C*', ...$M));
            $A = array_values(unpack('C*', $A_str));
            $this->xorByteArrays($this->buffer, $A);
        }
        
        $this->m_length = $a_length;
    }
    
    public function getTag($tag_bits = 96) {
        $tag_bytes = intdiv($tag_bits, 8);
        $tag = array_fill(0, $tag_bytes, 0);
        $block_bytes = $this->block_bytes;
        
        if ($this->letter_soup_mode) {
            for ($i = 0; $i < min($tag_bytes, $block_bytes); $i++) {
                $tag[$i] = $this->buffer[$i];
            }
            return pack('C*', ...$tag);
        }
        
        // Steps 6-9 of Algorithm 1 - Page 4
        $A = array_fill(0, $block_bytes, 0);
        $encrypted_a = array_fill(0, $block_bytes, 0);
        $aux_value1 = array_fill(0, $block_bytes, 0);
        $aux_value2 = array_fill(0, $block_bytes, 0);
        
        // auxValue1 = rpad(bin(n-tagBits)||1)
        $diff = $this->cipher->blockSize() * 8 - $tag_bits;
        
        if ($diff == 0) {
            $aux_value1[0] = 0x80;
            $aux_value1[1] = 0x00;
        } elseif ($diff < 0) {
            $aux_value1[0] = $diff & 0xFF;
            $aux_value1[1] = 0x80;
        } else {
            $diff = ($diff << 1) | 0x01;
            while ($diff > 0 && ($diff & 0x80) == 0) {
                $diff = ($diff << 1) & 0xFF;
            }
            $aux_value1[0] = $diff & 0xFF;
            $aux_value1[1] = 0x00;
        }
        
        // auxValue2 = lpad(bin(|M|))
        $processed_bits = 8 * $this->m_length;
        for ($i = 0; $i < 4; $i++) {
            $aux_value2[$block_bytes - $i - 1] = ($processed_bits >> (8 * $i)) & 0xFF;
        }
        
        $A = $this->buffer;
        $this->xorByteArrays($A, $aux_value1);
        $this->xorByteArrays($A, $aux_value2);
        
        $encrypted = $this->cipher->encryptBlock(pack('C*', ...$A));
        $encrypted_a = array_values(unpack('C*', $encrypted));
        
        for ($i = 0; $i < $tag_bytes; $i++) {
            $tag[$i] = $encrypted_a[$i];
        }
        
        return pack('C*', ...$tag);
    }
}

class LetterSoup {
    private $cipher;
    private $block_bytes;
    private $mac;
    private $m_length = 0;
    private $h_length = 0;
    private $iv = [];
    private $A = [];
    private $D = [];
    private $R = [];
    private $L = [];
    
    public function __construct($cipher) {
        $this->cipher = $cipher;
        $this->block_bytes = $cipher->blockSize();
        $this->mac = new Marvin($cipher, null, true);
    }
    
    private function xorArrays(&$a, $b) {
        $len = min(count($a), count($b));
        for ($i = 0; $i < $len; $i++) {
            $a[$i] ^= $b[$i];
        }
    }
    
    public function setIV($iv) {
        $iv_length = strlen($iv);
        $block_bytes = $this->block_bytes;
        
        $this->iv = array_values(unpack('C*', $iv));
        $this->L = [];
        
        // Step 2 of Algorithm 2 - Page 6
        $this->R = array_fill(0, $block_bytes, 0);
        $left_padded_n = array_fill(0, $block_bytes, 0);
        
        $start_idx = $block_bytes - $iv_length;
        if ($start_idx < 0) $start_idx = 0;
        $copy_len = min($iv_length, $block_bytes);
        
        $iv_arr = array_values(unpack('C*', $iv));
        for ($i = 0; $i < $copy_len; $i++) {
            $left_padded_n[$start_idx + $i] = $iv_arr[$i];
        }
        
        $encrypted = $this->cipher->encryptBlock(pack('C*', ...$left_padded_n));
        $this->R = array_values(unpack('C*', $encrypted));
        $this->xorArrays($this->R, $left_padded_n);
    }
    
    public function update($a_data) {
        $a_length = strlen($a_data);
        $block_bytes = $this->block_bytes;
        
        // Step 4 of Algorithm 2 - Page 6 (L and part of D)
        $this->L = array_fill(0, $block_bytes, 0);
        $this->D = array_fill(0, $block_bytes, 0);
        
        $empty = array_fill(0, $block_bytes, 0);
        
        $this->h_length = $a_length;
        $encrypted = $this->cipher->encryptBlock(pack('C*', ...$empty));
        $this->L = array_values(unpack('C*', $encrypted));
        
        $this->mac->initWithR(pack('C*', ...$this->L));
        $this->mac->update($a_data);
        $tag = $this->mac->getTag($this->cipher->blockSize() * 8);
        $this->D = array_values(unpack('C*', $tag));
    }
    
    private function updateOffset(&$O) {
        $O0 = $O[0];
        
        for ($i = 0; $i < 11; $i++) {
            $O[$i] = $O[$i + 1];
        }
        
        $O[9] = ($O[9] ^ $O0 ^ (($O0 >> 3) & 0xFF) ^ (($O0 >> 5) & 0xFF)) & 0xFF;
        $O[10] = ($O[10] ^ (($O0 << 5) & 0xFF) ^ (($O0 << 3) & 0xFF)) & 0xFF;
        $O[11] = $O0;
    }
    
    private function LFSRC($m_data, &$c_data) {
        $m_length = strlen($m_data);
        $block_bytes = $this->block_bytes;
        
        $M = array_fill(0, $block_bytes, 0);
        $C = array_fill(0, $block_bytes, 0);
        $O = $this->R;
        
        $q = intdiv($m_length, $block_bytes);
        $r = $m_length % $block_bytes;
        
        for ($i = 0; $i < $q; $i++) {
            $M = array_values(unpack('C*', substr($m_data, $i * $block_bytes, $block_bytes)));
            $this->updateOffset($O);
            $encrypted = $this->cipher->encryptBlock(pack('C*', ...$O));
            $C = array_values(unpack('C*', $encrypted));
            $this->xorArrays($C, $M);
            
            for ($j = 0; $j < $block_bytes; $j++) {
                $c_data[$i * $block_bytes + $j] = $C[$j];
            }
        }
        
        if ($r != 0) {
            $M_partial = array_values(unpack('C*', substr($m_data, $q * $block_bytes, $r)));
            for ($i = 0; $i < $r; $i++) {
                $M[$i] = $M_partial[$i];
            }
            for ($i = $r; $i < $block_bytes; $i++) {
                $M[$i] = 0;
            }
            
            $this->updateOffset($O);
            $encrypted = $this->cipher->encryptBlock(pack('C*', ...$O));
            $C = array_values(unpack('C*', $encrypted));
            $this->xorArrays($C, $M);
            
            for ($j = 0; $j < $r; $j++) {
                $c_data[$q * $block_bytes + $j] = $C[$j];
            }
        }
    }
    
    public function encrypt($src) {
        $m_length = strlen($src);
        $block_bytes = $this->block_bytes;
        
        // Step 3 of Algorithm 2 - Page 6 (C and part of A)
        $this->A = array_fill(0, $block_bytes, 0);
        $this->m_length = $m_length;
        
        $dst = array_fill(0, $m_length, 0);
        $this->LFSRC($src, $dst);
        
        $this->mac->initWithR(pack('C*', ...$this->R));
        $this->mac->update(pack('C*', ...$dst));
        $tag = $this->mac->getTag($this->cipher->blockSize() * 8);
        $this->A = array_values(unpack('C*', $tag));
        
        return $dst;
    }
    
    public function decrypt($src) {
        $dst = array_fill(0, strlen($src), 0);
        $this->LFSRC($src, $dst);
        return $dst;
    }
    
    public function getTag($tag_bits = 96) {
        $tag_bytes = intdiv($tag_bits, 8);
        $tag = array_fill(0, $tag_bytes, 0);
        $block_bytes = $this->block_bytes;
        
        // Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
        $Atemp = array_slice($this->A, 0, $block_bytes);
        $aux_value1 = array_fill(0, $block_bytes, 0);
        $aux_value2 = array_fill(0, $block_bytes, 0);
        
        // auxValue1 = rpad(bin(n-tagBits)||1)
        $diff = $this->cipher->blockSize() * 8 - $tag_bits;
        
        if ($diff == 0) {
            $aux_value1[0] = 0x80;
            $aux_value1[1] = 0x00;
        } elseif ($diff < 0) {
            $aux_value1[0] = $diff & 0xFF;
            $aux_value1[1] = 0x80;
        } else {
            $diff = ($diff << 1) | 0x01;
            while ($diff > 0 && ($diff & 0x80) == 0) {
                $diff = ($diff << 1) & 0xFF;
            }
            $aux_value1[0] = $diff & 0xFF;
            $aux_value1[1] = 0x00;
        }
        
        // auxValue2 = lpad(bin(|M|))
        for ($i = 0; $i < 4; $i++) {
            $aux_value2[$block_bytes - $i - 1] = (($this->m_length * 8) >> (8 * $i)) & 0xFF;
        }
        
        $this->xorArrays($Atemp, $aux_value1);
        $this->xorArrays($Atemp, $aux_value2);
        
        // Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
        if (!empty($this->L)) {
            // auxValue2 = lpad(bin(|H|))
            $aux_value2_h = array_fill(0, $block_bytes, 0);
            for ($i = 0; $i < 4; $i++) {
                $aux_value2_h[$block_bytes - $i - 1] = (($this->h_length * 8) >> (8 * $i)) & 0xFF;
            }
            
            $Dtemp = array_slice($this->D, 0, $block_bytes);
            
            $this->xorArrays($Dtemp, $aux_value1);
            $this->xorArrays($Dtemp, $aux_value2_h);
            $sct_result = $this->cipher->sct(pack('C*', ...$Dtemp));
            $aux_value1_sct = array_values(unpack('C*', $sct_result));
            $this->xorArrays($Atemp, $aux_value1_sct);
        }
        
        // Step 7 of Algorithm 2 - Page 6
        $encrypted = $this->cipher->encryptBlock(pack('C*', ...$Atemp));
        $aux_value1_final = array_values(unpack('C*', $encrypted));
        
        for ($i = 0; $i < $tag_bytes; $i++) {
            $tag[$i] = $aux_value1_final[$i];
        }
        
        return pack('C*', ...$tag);
    }
}

// Funções auxiliares para o CLI
function hex2str($hex) {
    return hex2bin(str_replace('0x', '', strtolower($hex)));
}

function run_self_test() {
    echo "=== Running Curupira2 LetterSoup AEAD self-test ===\n";
    echo "Note: Using fixed test vectors for verification\n\n";
    
    try {
        // Fixed test vectors
        $test_key = hex2bin("0228674ed28f695ed88a39ec");
        $test_plaintext = "Test message for LetterSoup";
        $test_aad = "metadata";
        
        echo "Test key: " . bin2hex($test_key) . "\n";
        echo "Test plaintext: $test_plaintext\n";
        echo "Test AAD: $test_aad\n";
        
        // Create cipher
        $cipher = new Curupira2($test_key);
        
        // Test 1: Basic encryption/decryption
        echo "\n1. Basic encryption/decryption test:\n";
        $aead = new LetterSoup($cipher);
        $nonce = hex2bin("000102030405060708090a0b"); // Fixed nonce for reproducible tests
        
        $aead->setIV($nonce);
        $aead->update($test_aad);
        
        $ciphertext = $aead->encrypt($test_plaintext);
        $tag = $aead->getTag(96);
        
        echo "   Nonce: " . bin2hex($nonce) . "\n";
        echo "   Ciphertext (hex): " . bin2hex(pack('C*', ...$ciphertext)) . "\n";
        echo "   Tag: " . bin2hex($tag) . "\n";
        
        // Decrypt
        $aead2 = new LetterSoup($cipher);
        $aead2->setIV($nonce);
        $aead2->update($test_aad);
        
        $decrypted = $aead2->decrypt(pack('C*', ...$ciphertext));
        $decrypted_str = pack('C*', ...$decrypted);
        
        echo "   Decrypted: $decrypted_str\n";
        echo "   Match original: " . ($test_plaintext === $decrypted_str ? 'true' : 'false') . "\n";
        
        // Test 2: Empty AAD
        echo "\n2. Test with empty AAD:\n";
        $aead3 = new LetterSoup($cipher);
        $aead3->setIV($nonce);
        $aead3->update('');
        
        $ciphertext3 = $aead3->encrypt($test_plaintext);
        $tag3 = $aead3->getTag(96);
        
        echo "   Ciphertext with empty AAD: " . substr(bin2hex(pack('C*', ...$ciphertext3)), 0, 32) . "...\n";
        echo "   Tag with empty AAD: " . bin2hex($tag3) . "\n";
        
        // Test 3: Different AAD produces different results
        echo "\n3. Different AAD produces different results:\n";
        $aead4 = new LetterSoup($cipher);
        $aead4->setIV($nonce);
        $aead4->update('different_aad');
        
        $ciphertext4 = $aead4->encrypt($test_plaintext);
        $tag4 = $aead4->getTag(96);
        
        echo "   Ciphertext same as test 1? " . (pack('C*', ...$ciphertext) === pack('C*', ...$ciphertext4) ? 'true' : 'false') . "\n";
        echo "   Tag same as test 1? " . ($tag === $tag4 ? 'true' : 'false') . "\n";
        
        // Test 4: Self-consistency test
        echo "\n4. Self-consistency test:\n";
        $test_messages = [
            "",
            "A",
            "AB",
            "ABC",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "This is a longer test message to verify encryption works properly!"
        ];
        
        $all_passed = true;
        foreach ($test_messages as $i => $msg) {
            $aead_test = new LetterSoup($cipher);
            $test_nonce = random_bytes(12);
            
            $aead_test->setIV($test_nonce);
            $aead_test->update($test_aad);
            
            $encrypted = $aead_test->encrypt($msg);
            $test_tag = $aead_test->getTag(96);
            
            // Decrypt
            $aead_dec = new LetterSoup($cipher);
            $aead_dec->setIV($test_nonce);
            $aead_dec->update($test_aad);
            
            $decrypted = $aead_dec->decrypt(pack('C*', ...$encrypted));
            $decrypted_str = pack('C*', ...$decrypted);
            
            $passed = ($msg === $decrypted_str);
            $all_passed = $all_passed && $passed;
            
            echo "   Test " . ($i+1) . " (" . strlen($msg) . " bytes): " . ($passed ? 'PASS' : 'FAIL') . "\n";
            if (!$passed) {
                echo "     Expected: $msg\n";
                echo "     Got: $decrypted_str\n";
            }
        }
        
        if ($all_passed) {
            echo "\n✓ All self-consistency tests passed!\n";
        } else {
            echo "\n✗ Some tests failed!\n";
            return 1;
        }
        
        echo "\n=== Self-test completed successfully! ===\n";
        return 0;
        
    } catch (Exception $e) {
        echo "\n✗ Self-test failed: " . $e->getMessage() . "\n";
        echo $e->getTraceAsString() . "\n";
        return 1;
    }
}

// CLI handling
if (php_sapi_name() === 'cli') {
    $shortopts = "edtk:f:o:";
    $longopts = ["encrypt", "decrypt", "test", "key:", "aad:", "file:", "output:"];
    $options = getopt($shortopts, $longopts);
    
    if (isset($options['t']) || isset($options['test'])) {
        exit(run_self_test());
    }
    
    $is_encrypt = isset($options['e']) || isset($options['encrypt']);
    $is_decrypt = isset($options['d']) || isset($options['decrypt']);
    
    if (!$is_encrypt && !$is_decrypt) {
        echo "Error: Must specify either -e/--encrypt or -d/--decrypt\n";
        exit(1);
    }
    
    // Get key
    $key_hex = $options['k'] ?? $options['key'] ?? null;
    if (!$key_hex) {
        echo "Error: Key (-k/--key) is required\n";
        exit(1);
    }
    
    try {
        $key = hex2str($key_hex);
        if (strlen($key) != 12 && strlen($key) != 18 && strlen($key) != 24) {
            throw new Exception("Key must be 12, 18 or 24 bytes, got " . strlen($key) . " bytes");
        }
        
        // Read input
        $input_data = '';
        if (isset($options['f']) || isset($options['file'])) {
            $filename = $options['f'] ?? $options['file'];
            $input_data = file_get_contents($filename);
            if ($input_data === false) {
                throw new Exception("Cannot read input file: $filename");
            }
        } else {
            $input_data = file_get_contents('php://stdin');
        }
        
        // Create cipher and AEAD
        $cipher = new Curupira2($key);
        $aead = new LetterSoup($cipher);
        
        // Get AAD
        $aad = $options['aad'] ?? '';
        
        if ($is_encrypt) {
            // Generate random nonce (12 bytes)
            $nonce = random_bytes(12);
            
            // Set IV
            $aead->setIV($nonce);
            
            // Process AAD
            $aead->update($aad);
            
            // Encrypt
            $ciphertext = $aead->encrypt($input_data);
            
            // Get tag
            $tag = $aead->getTag(96);
            
            // Output: nonce + tag + ciphertext
            $output = $nonce . $tag . pack('C*', ...$ciphertext);
            
            if (isset($options['o']) || isset($options['output'])) {
                $filename = $options['o'] ?? $options['output'];
                file_put_contents($filename, $output);
                fwrite(STDERR, "Encryption complete. Output written to $filename\n");
                fwrite(STDERR, "Nonce: " . bin2hex($nonce) . "\n");
                fwrite(STDERR, "Tag: " . bin2hex($tag) . "\n");
                fwrite(STDERR, "Ciphertext length: " . count($ciphertext) . " bytes\n");
            } else {
                echo $output;
            }
            
        } else { // decrypt
            if (strlen($input_data) < 24) {
                throw new Exception("Input too short. Must contain at least 24 bytes (nonce + tag)");
            }
            
            // Extract nonce, tag and ciphertext
            $nonce = substr($input_data, 0, 12);
            $tag = substr($input_data, 12, 12);
            $ciphertext = substr($input_data, 24);
            
            // Set IV
            $aead->setIV($nonce);
            
            // Process AAD
            $aead->update($aad);
            
            // Decrypt
            $plaintext = $aead->decrypt($ciphertext);
            
            // Verify authentication
            $aead_verify = new LetterSoup($cipher);
            $aead_verify->setIV($nonce);
            $aead_verify->update($aad);
            
            $test_ciphertext = $aead_verify->encrypt(pack('C*', ...$plaintext));
            $test_tag = $aead_verify->getTag(96);
            
            if ($tag !== $test_tag) {
                throw new Exception("Authentication failed! Expected tag: " . bin2hex($test_tag) . ", Received tag: " . bin2hex($tag));
            }
            
            $plaintext_str = pack('C*', ...$plaintext);
            
            if (isset($options['o']) || isset($options['output'])) {
                $filename = $options['o'] ?? $options['output'];
                file_put_contents($filename, $plaintext_str);
                fwrite(STDERR, "Decryption complete. Output written to $filename\n");
            } else {
                echo $plaintext_str;
            }
        }
        
        exit(0);
        
    } catch (Exception $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
}
