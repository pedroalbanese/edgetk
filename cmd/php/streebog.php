<?php

/**
 * Streebog - GOST R 34.11-2012 Hash Function
 * RFC 6986 - Big-endian hash output
 * PHP implementation
 */

class Streebog {
    const BLOCK_SIZE = 64;
    
    private $size;
    private $buf = '';
    private $n = 0;
    private $h;
    private $chk;
    private $tmp;
    private $psBuf;
    private $eMsgBuf;
    private $eKBuf;
    private $eXorBuf;
    private $gBuf;
    private $addBuf;
    
    private static $pi;
    private static $tau;
    private static $C;
    private static $A;
    private static $cache;
    
    public function __construct($size = 64) {
        if ($size !== 32 && $size !== 64) {
            throw new Exception("size must be either 32 or 64");
        }
        $this->size = $size;
        self::initConstants();
        $this->reset();
    }
    
    private static function initConstants() {
        if (self::$pi !== null) return;
        
        // S-box
        self::$pi = [
            0xfc,0xee,0xdd,0x11,0xcf,0x6e,0x31,0x16,0xfb,0xc4,0xfa,0xda,0x23,0xc5,0x04,0x4d,
            0xe9,0x77,0xf0,0xdb,0x93,0x2e,0x99,0xba,0x17,0x36,0xf1,0xbb,0x14,0xcd,0x5f,0xc1,
            0xf9,0x18,0x65,0x5a,0xe2,0x5c,0xef,0x21,0x81,0x1c,0x3c,0x42,0x8b,0x01,0x8e,0x4f,
            0x05,0x84,0x02,0xae,0xe3,0x6a,0x8f,0xa0,0x06,0x0b,0xed,0x98,0x7f,0xd4,0xd3,0x1f,
            0xeb,0x34,0x2c,0x51,0xea,0xc8,0x48,0xab,0xf2,0x2a,0x68,0xa2,0xfd,0x3a,0xce,0xcc,
            0xb5,0x70,0x0e,0x56,0x08,0x0c,0x76,0x12,0xbf,0x72,0x13,0x47,0x9c,0xb7,0x5d,0x87,
            0x15,0xa1,0x96,0x29,0x10,0x7b,0x9a,0xc7,0xf3,0x91,0x78,0x6f,0x9d,0x9e,0xb2,0xb1,
            0x32,0x75,0x19,0x3d,0xff,0x35,0x8a,0x7e,0x6d,0x54,0xc6,0x80,0xc3,0xbd,0x0d,0x57,
            0xdf,0xf5,0x24,0xa9,0x3e,0xa8,0x43,0xc9,0xd7,0x79,0xd6,0xf6,0x7c,0x22,0xb9,0x03,
            0xe0,0x0f,0xec,0xde,0x7a,0x94,0xb0,0xbc,0xdc,0xe8,0x28,0x50,0x4e,0x33,0x0a,0x4a,
            0xa7,0x97,0x60,0x73,0x1e,0x00,0x62,0x44,0x1a,0xb8,0x38,0x82,0x64,0x9f,0x26,0x41,
            0xad,0x45,0x46,0x92,0x27,0x5e,0x55,0x2f,0x8c,0xa3,0xa5,0x7d,0x69,0xd5,0x95,0x3b,
            0x07,0x58,0xb3,0x40,0x86,0xac,0x1d,0xf7,0x30,0x37,0x6b,0xe4,0x88,0xd9,0xe7,0x89,
            0xe1,0x1b,0x83,0x49,0x4c,0x3f,0xf8,0xfe,0x8d,0x53,0xaa,0x90,0xca,0xd8,0x85,0x61,
            0x20,0x71,0x67,0xa4,0x2d,0x2b,0x09,0x5b,0xcb,0x9b,0x25,0xd0,0xbe,0xe5,0x6c,0x52,
            0x59,0xa6,0x74,0xd2,0xe6,0xf4,0xb4,0xc0,0xd1,0x66,0xaf,0xc2,0x39,0x4b,0x63,0xb6
        ];
        
        // Tau permutation
        self::$tau = [
            0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38,
            0x01,0x09,0x11,0x19,0x21,0x29,0x31,0x39,
            0x02,0x0a,0x12,0x1a,0x22,0x2a,0x32,0x3a,
            0x03,0x0b,0x13,0x1b,0x23,0x2b,0x33,0x3b,
            0x04,0x0c,0x14,0x1c,0x24,0x2c,0x34,0x3c,
            0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d,
            0x06,0x0e,0x16,0x1e,0x26,0x2e,0x36,0x3e,
            0x07,0x0f,0x17,0x1f,0x27,0x2f,0x37,0x3f
        ];
        
         // Constants C (12 x 64 bytes)
        self::$C = [
            // C[0]
            "\x07\x45\xa6\xf2\x59\x65\x80\xdd\x23\x4d\x74\xcc\x36\x74\x76\x05" .
            "\x15\xd3\x60\xa4\x08\x2a\x42\xa2\x01\x69\x67\x92\x91\xe0\x7c\x4b" .
            "\xfc\xc4\x85\x75\x8d\xb8\x4e\x71\x16\xd0\x45\x2e\x43\x76\x6a\x2f" .
            "\x1f\x7c\x65\xc0\x81\x2f\xcb\xeb\xe9\xda\xca\x1e\xda\x5b\x08\xb1",
            
            // C[1]
            "\xb7\x9b\xb1\x21\x70\x04\x79\xe6\x56\xcd\xcb\xd7\x1b\xa2\xdd\x55" .
            "\xca\xa7\x0a\xdb\xc2\x61\xb5\x5c\x58\x99\xd6\x12\x6b\x17\xb5\x9a" .
            "\x31\x01\xb5\x16\x0f\x5e\xd5\x61\x98\x2b\x23\x0a\x72\xea\xfe\xf3" .
            "\xd7\xb5\x70\x0f\x46\x9d\xe3\x4f\x1a\x2f\x9d\xa9\x8a\xb5\xa3\x6f",
            
            // C[2]
            "\xb2\x0a\xba\x0a\xf5\x96\x1e\x99\x31\xdb\x7a\x86\x43\xf4\xb6\xc2" .
            "\x09\xdb\x62\x60\x37\x3a\xc9\xc1\xb1\x9e\x35\x90\xe4\x0f\xe2\xd3" .
            "\x7b\x7b\x29\xb1\x14\x75\xea\xf2\x8b\x1f\x9c\x52\x5f\x5e\xf1\x06" .
            "\x35\x84\x3d\x6a\x28\xfc\x39\x0a\xc7\x2f\xce\x2b\xac\xdc\x74\xf5",
            
            // C[3]
            "\x2e\xd1\xe3\x84\xbc\xbe\x0c\x22\xf1\x37\xe8\x93\xa1\xea\x53\x34" .
            "\xbe\x03\x52\x93\x33\x13\xb7\xd8\x75\xd6\x03\xed\x82\x2c\xd7\xa9" .
            "\x3f\x35\x5e\x68\xad\x1c\x72\x9d\x7d\x3c\x5c\x33\x7e\x85\x8e\x48" .
            "\xdd\xe4\x71\x5d\xa0\xe1\x48\xf9\xd2\x66\x15\xe8\xb3\xdf\x1f\xef",
            
            // C[4]
            "\x57\xfe\x6c\x7c\xfd\x58\x17\x60\xf5\x63\xea\xa9\x7e\xa2\x56\x7a" .
            "\x16\x1a\x27\x23\xb7\x00\xff\xdf\xa3\xf5\x3a\x25\x47\x17\xcd\xbf" .
            "\xbd\xff\x0f\x80\xd7\x35\x9e\x35\x4a\x10\x86\x16\x1f\x1c\x15\x7f" .
            "\x63\x23\xa9\x6c\x0c\x41\x3f\x9a\x99\x47\x47\xad\xac\x6b\xea\x4b",
            
            // C[5]
            "\x6e\x7d\x64\x46\x7a\x40\x68\xfa\x35\x4f\x90\x36\x72\xc5\x71\xbf" .
            "\xb6\xc6\xbe\xc2\x66\x1f\xf2\x0a\xb4\xb7\x9a\x1c\xb7\xa6\xfa\xcf" .
            "\xc6\x8e\xf0\x9a\xb4\x9a\x7f\x18\x6c\xa4\x42\x51\xf9\xc4\x66\x2d" .
            "\xc0\x39\x30\x7a\x3b\xc3\xa4\x6f\xd9\xd3\x3a\x1d\xae\xae\x4f\xae",
            
            // C[6]
            "\x93\xd4\x14\x3a\x4d\x56\x86\x88\xf3\x4a\x3c\xa2\x4c\x45\x17\x35" .
            "\x04\x05\x4a\x28\x83\x69\x47\x06\x37\x2c\x82\x2d\xc5\xab\x92\x09" .
            "\xc9\x93\x7a\x19\x33\x3e\x47\xd3\xc9\x87\xbf\xe6\xc7\xc6\x9e\x39" .
            "\x54\x09\x24\xbf\xfe\x86\xac\x51\xec\xc5\xaa\xee\x16\x0e\xc7\xf4",
            
            // C[7]
            "\x1e\xe7\x02\xbf\xd4\x0d\x7f\xa4\xd9\xa8\x51\x59\x35\xc2\xac\x36" .
            "\x2f\xc4\xa5\xd1\x2b\x8d\xd1\x69\x90\x06\x9b\x92\xcb\x2b\x89\xf4" .
            "\x9a\xc4\xdb\x4d\x3b\x44\xb4\x89\x1e\xde\x36\x9c\x71\xf8\xb7\x4e" .
            "\x41\x41\x6e\x0c\x02\xaa\xe7\x03\xa7\xc9\x93\x4d\x42\x5b\x1f\x9b",
            
            // C[8]
            "\xdb\x5a\x23\x83\x51\x44\x61\x72\x60\x2a\x1f\xcb\x92\xdc\x38\x0e" .
            "\x54\x9c\x07\xa6\x9a\x8a\x2b\x7b\xb1\xce\xb2\xdb\x0b\x44\x0a\x80" .
            "\x84\x09\x0d\xe0\xb7\x55\xd9\x3c\x24\x42\x89\x25\x1b\x3a\x7d\x3a" .
            "\xde\x5f\x16\xec\xd8\x9a\x4c\x94\x9b\x22\x31\x16\x54\x5a\x8f\x37",
            
            // C[9]
            "\xed\x9c\x45\x98\xfb\xc7\xb4\x74\xc3\xb6\x3b\x15\xd1\xfa\x98\x36" .
            "\xf4\x52\x76\x3b\x30\x6c\x1e\x7a\x4b\x33\x69\xaf\x02\x67\xe7\x9f" .
            "\x03\x61\x33\x1b\x8a\xe1\xff\x1f\xdb\x78\x8a\xff\x1c\xe7\x41\x89" .
            "\xf3\xf3\xe4\xb2\x48\xe5\x2a\x38\x52\x6f\x05\x80\xa6\xde\xbe\xab",
            
            // C[10]
            "\x1b\x2d\xf3\x81\xcd\xa4\xca\x6b\x5d\xd8\x6f\xc0\x4a\x59\xa2\xde" .
            "\x98\x6e\x47\x7d\x1d\xcd\xba\xef\xca\xb9\x48\xea\xef\x71\x1d\x8a" .
            "\x79\x66\x84\x14\x21\x80\x01\x20\x61\x07\xab\xeb\xbb\x6b\xfa\xd8" .
            "\x94\xfe\x5a\x63\xcd\xc6\x02\x30\xfb\x89\xc8\xef\xd0\x9e\xcd\x7b",
            
            // C[11]
            "\x20\xd7\x1b\xf1\x4a\x92\xbc\x48\x99\x1b\xb2\xd9\xd5\x17\xf4\xfa" .
            "\x52\x28\xe1\x88\xaa\xa4\x1d\xe7\x86\xcc\x91\x18\x9d\xef\x80\x5d" .
            "\x9b\x9f\x21\x30\xd4\x12\x20\xf8\x77\x1d\xdf\xbc\x32\x3c\xa4\xcd" .
            "\x7a\xb1\x49\x04\xb0\x80\x13\xd2\xba\x31\x16\xf1\x67\xe7\x8e\x37",
        ];
        
        // A constants for L transformation
        $as = [
            [0x8e,0x20,0xfa,0xa7,0x2b,0xa0,0xb4,0x70],[0x47,0x10,0x7d,0xdd,0x9b,0x50,0x5a,0x38],
            [0xad,0x08,0xb0,0xe0,0xc3,0x28,0x2d,0x1c],[0xd8,0x04,0x58,0x70,0xef,0x14,0x98,0x0e],
            [0x6c,0x02,0x2c,0x38,0xf9,0x0a,0x4c,0x07],[0x36,0x01,0x16,0x1c,0xf2,0x05,0x26,0x8d],
            [0x1b,0x8e,0x0b,0x0e,0x79,0x8c,0x13,0xc8],[0x83,0x47,0x8b,0x07,0xb2,0x46,0x87,0x64],
            [0xa0,0x11,0xd3,0x80,0x81,0x8e,0x8f,0x40],[0x50,0x86,0xe7,0x40,0xce,0x47,0xc9,0x20],
            [0x28,0x43,0xfd,0x20,0x67,0xad,0xea,0x10],[0x14,0xaf,0xf0,0x10,0xbd,0xd8,0x75,0x08],
            [0x0a,0xd9,0x78,0x08,0xd0,0x6c,0xb4,0x04],[0x05,0xe2,0x3c,0x04,0x68,0x36,0x5a,0x02],
            [0x8c,0x71,0x1e,0x02,0x34,0x1b,0x2d,0x01],[0x46,0xb6,0x0f,0x01,0x1a,0x83,0x98,0x8e],
            [0x90,0xda,0xb5,0x2a,0x38,0x7a,0xe7,0x6f],[0x48,0x6d,0xd4,0x15,0x1c,0x3d,0xfd,0xb9],
            [0x24,0xb8,0x6a,0x84,0x0e,0x90,0xf0,0xd2],[0x12,0x5c,0x35,0x42,0x07,0x48,0x78,0x69],
            [0x09,0x2e,0x94,0x21,0x8d,0x24,0x3c,0xba],[0x8a,0x17,0x4a,0x9e,0xc8,0x12,0x1e,0x5d],
            [0x45,0x85,0x25,0x4f,0x64,0x09,0x0f,0xa0],[0xac,0xcc,0x9c,0xa9,0x32,0x8a,0x89,0x50],
            [0x9d,0x4d,0xf0,0x5d,0x5f,0x66,0x14,0x51],[0xc0,0xa8,0x78,0xa0,0xa1,0x33,0x0a,0xa6],
            [0x60,0x54,0x3c,0x50,0xde,0x97,0x05,0x53],[0x30,0x2a,0x1e,0x28,0x6f,0xc5,0x8c,0xa7],
            [0x18,0x15,0x0f,0x14,0xb9,0xec,0x46,0xdd],[0x0c,0x84,0x89,0x0a,0xd2,0x76,0x23,0xe0],
            [0x06,0x42,0xca,0x05,0x69,0x3b,0x9f,0x70],[0x03,0x21,0x65,0x8c,0xba,0x93,0xc1,0x38],
            [0x86,0x27,0x5d,0xf0,0x9c,0xe8,0xaa,0xa8],[0x43,0x9d,0xa0,0x78,0x4e,0x74,0x55,0x54],
            [0xaf,0xc0,0x50,0x3c,0x27,0x3a,0xa4,0x2a],[0xd9,0x60,0x28,0x1e,0x9d,0x1d,0x52,0x15],
            [0xe2,0x30,0x14,0x0f,0xc0,0x80,0x29,0x84],[0x71,0x18,0x0a,0x89,0x60,0x40,0x9a,0x42],
            [0xb6,0x0c,0x05,0xca,0x30,0x20,0x4d,0x21],[0x5b,0x06,0x8c,0x65,0x18,0x10,0xa8,0x9e],
            [0x45,0x6c,0x34,0x88,0x7a,0x38,0x05,0xb9],[0xac,0x36,0x1a,0x44,0x3d,0x1c,0x8c,0xd2],
            [0x56,0x1b,0x0d,0x22,0x90,0x0e,0x46,0x69],[0x2b,0x83,0x88,0x11,0x48,0x07,0x23,0xba],
            [0x9b,0xcf,0x44,0x86,0x24,0x8d,0x9f,0x5d],[0xc3,0xe9,0x22,0x43,0x12,0xc8,0xc1,0xa0],
            [0xef,0xfa,0x11,0xaf,0x09,0x64,0xee,0x50],[0xf9,0x7d,0x86,0xd9,0x8a,0x32,0x77,0x28],
            [0xe4,0xfa,0x20,0x54,0xa8,0x0b,0x32,0x9c],[0x72,0x7d,0x10,0x2a,0x54,0x8b,0x19,0x4e],
            [0x39,0xb0,0x08,0x15,0x2a,0xcb,0x82,0x27],[0x92,0x58,0x04,0x84,0x15,0xeb,0x41,0x9d],
            [0x49,0x2c,0x02,0x42,0x84,0xfb,0xae,0xc0],[0xaa,0x16,0x01,0x21,0x42,0xf3,0x57,0x60],
            [0x55,0x0b,0x8e,0x9e,0x21,0xf7,0xa5,0x30],[0xa4,0x8b,0x47,0x4f,0x9e,0xf5,0xdc,0x18],
            [0x70,0xa6,0xa5,0x6e,0x24,0x40,0x59,0x8e],[0x38,0x53,0xdc,0x37,0x12,0x20,0xa2,0x47],
            [0x1c,0xa7,0x6e,0x95,0x09,0x10,0x51,0xad],[0x0e,0xdd,0x37,0xc4,0x8a,0x08,0xa6,0xd8],
            [0x07,0xe0,0x95,0x62,0x45,0x04,0x53,0x6c],[0x8d,0x70,0xc4,0x31,0xac,0x02,0xa7,0x36],
            [0xc8,0x38,0x62,0x96,0x56,0x01,0xdd,0x1b],[0x64,0x1c,0x31,0x4b,0x2b,0x8e,0xe0,0x83]
        ];
        
        self::$A = [];
        for ($i = 0; $i < 64; $i++) {
            self::$A[$i] = 0;
            for ($j = 0; $j < 8; $j++) {
                self::$A[$i] = (self::$A[$i] << 8) | $as[$i][$j];
            }
        }
        
        // Cache for L transformation
        self::$cache = [];
        for ($byteN = 0; $byteN < 8; $byteN++) {
            for ($byteValN = 0; $byteValN < 256; $byteValN++) {
                $val = $byteValN;
                $res64 = 0;
                for ($bitN = 0; $bitN < 8; $bitN++) {
                    if ($val & 0x80) {
                        $res64 ^= self::$A[(7 - $byteN) * 8 + $bitN];
                    }
                    $val <<= 1;
                }
                self::$cache[$byteN][$byteValN] = $res64;
            }
        }
    }
    
    public function reset() {
        $this->buf = '';
        $this->n = 0;
        $this->h = str_repeat("\x00", self::BLOCK_SIZE);
        $this->chk = str_repeat("\x00", self::BLOCK_SIZE);
        $this->tmp = str_repeat("\x00", self::BLOCK_SIZE);
        $this->psBuf = str_repeat("\x00", self::BLOCK_SIZE);
        $this->eMsgBuf = str_repeat("\x00", self::BLOCK_SIZE);
        $this->eKBuf = str_repeat("\x00", self::BLOCK_SIZE);
        $this->eXorBuf = str_repeat("\x00", self::BLOCK_SIZE);
        $this->gBuf = str_repeat("\x00", self::BLOCK_SIZE);
        $this->addBuf = str_repeat("\x00", self::BLOCK_SIZE);
        
        if ($this->size == 32) {
            for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
                $this->h[$i] = "\x01";
            }
        }
    }
    
    public function write($data) {
        $this->buf .= $data;
        while (strlen($this->buf) >= self::BLOCK_SIZE) {
            $this->tmp = substr($this->buf, 0, self::BLOCK_SIZE);
            $this->h = $this->g($this->n, $this->h, $this->tmp);
            $this->chk = $this->add512bit($this->chk, $this->tmp);
            $this->n += self::BLOCK_SIZE * 8;
            $this->buf = substr($this->buf, self::BLOCK_SIZE);
        }
        return strlen($data);
    }
    
    public function sum($in = '') {
        $buf = str_repeat("\x00", self::BLOCK_SIZE);
        $hsh = str_repeat("\x00", self::BLOCK_SIZE);
        
        // Copiar o buffer restante
        $buf = str_pad(substr($this->buf, 0, strlen($this->buf)), self::BLOCK_SIZE, "\x00");
        $buf[strlen($this->buf)] = "\x01";
        
        // Calcular hash final
        $hsh = $this->g($this->n, $this->h, $buf);
        
        // Adicionar comprimento
        $lenBits = $this->n + strlen($this->buf) * 8;
        $lenBytes = str_repeat("\x00", self::BLOCK_SIZE);
        for ($i = 0; $i < 8; $i++) {
            $lenBytes[$i] = chr(($lenBits >> ($i * 8)) & 0xFF);
        }
        $hsh = $this->g(0, $hsh, $lenBytes);
        
        // Finalizar com checksum
        $hsh = $this->g(0, $hsh, $this->add512bit($this->chk, $buf));
        
        if ($this->size == 32) {
            return $in . substr($hsh, self::BLOCK_SIZE / 2);
        }
        return $in . $hsh;
    }
    
    private function add512bit($chk, $data) {
        $ss = 0;
        for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
            $ss = ord($chk[$i]) + ord($data[$i]) + ($ss >> 8);
            $this->addBuf[$i] = chr($ss & 0xFF);
        }
        return $this->addBuf;
    }
    
    private function g($n, $hsh, $data) {
        // Copiar hsh para out
        for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
            $this->gBuf[$i] = $hsh[$i];
        }
        
        // XOR com n (primeiros 8 bytes)
        $this->gBuf[0] = chr(ord($this->gBuf[0]) ^ ($n & 0xFF));
        $this->gBuf[1] = chr(ord($this->gBuf[1]) ^ (($n >> 8) & 0xFF));
        $this->gBuf[2] = chr(ord($this->gBuf[2]) ^ (($n >> 16) & 0xFF));
        $this->gBuf[3] = chr(ord($this->gBuf[3]) ^ (($n >> 24) & 0xFF));
        $this->gBuf[4] = chr(ord($this->gBuf[4]) ^ (($n >> 32) & 0xFF));
        $this->gBuf[5] = chr(ord($this->gBuf[5]) ^ (($n >> 40) & 0xFF));
        $this->gBuf[6] = chr(ord($this->gBuf[6]) ^ (($n >> 48) & 0xFF));
        $this->gBuf[7] = chr(ord($this->gBuf[7]) ^ (($n >> 56) & 0xFF));
        
        // E(K, M)
        $out = $this->e($this->l($this->ps($this->gBuf)), $data);
        
        // XOR com hsh e data
        for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
            $out[$i] = chr(ord($out[$i]) ^ ord($hsh[$i]) ^ ord($data[$i]));
        }
        
        return $out;
    }
    
    private function e($K, $msg) {
        for ($i = 0; $i < 12; $i++) {
            // msg = L(PS(K XOR msg))
            for ($j = 0; $j < self::BLOCK_SIZE; $j++) {
                $this->eXorBuf[$j] = chr(ord($K[$j]) ^ ord($msg[$j]));
            }
            $msg = $this->l($this->ps($this->eXorBuf));
            
            // K = L(PS(K XOR C[i]))
            for ($j = 0; $j < self::BLOCK_SIZE; $j++) {
                $this->eXorBuf[$j] = chr(ord($K[$j]) ^ ord(self::$C[$i][$j]));
            }
            $K = $this->l($this->ps($this->eXorBuf));
        }
        
        // return K XOR msg
        for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
            $this->eXorBuf[$i] = chr(ord($K[$i]) ^ ord($msg[$i]));
        }
        return $this->eXorBuf;
    }
    
    private function ps($data) {
        for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
            $this->psBuf[self::$tau[$i]] = chr(self::$pi[ord($data[$i])]);
        }
        return $this->psBuf;
    }
    
    private function l($data) {
        $result = str_repeat("\x00", self::BLOCK_SIZE);
        for ($i = 0; $i < 8; $i++) {
            $res64 = 0;
            $res64 ^= self::$cache[0][ord($data[$i * 8 + 0])];
            $res64 ^= self::$cache[1][ord($data[$i * 8 + 1])];
            $res64 ^= self::$cache[2][ord($data[$i * 8 + 2])];
            $res64 ^= self::$cache[3][ord($data[$i * 8 + 3])];
            $res64 ^= self::$cache[4][ord($data[$i * 8 + 4])];
            $res64 ^= self::$cache[5][ord($data[$i * 8 + 5])];
            $res64 ^= self::$cache[6][ord($data[$i * 8 + 6])];
            $res64 ^= self::$cache[7][ord($data[$i * 8 + 7])];
            
            $result[$i * 8 + 0] = chr($res64 & 0xFF);
            $result[$i * 8 + 1] = chr(($res64 >> 8) & 0xFF);
            $result[$i * 8 + 2] = chr(($res64 >> 16) & 0xFF);
            $result[$i * 8 + 3] = chr(($res64 >> 24) & 0xFF);
            $result[$i * 8 + 4] = chr(($res64 >> 32) & 0xFF);
            $result[$i * 8 + 5] = chr(($res64 >> 40) & 0xFF);
            $result[$i * 8 + 6] = chr(($res64 >> 48) & 0xFF);
            $result[$i * 8 + 7] = chr(($res64 >> 56) & 0xFF);
        }
        return $result;
    }
    
    public static function hash256($data) {
        $h = new self(32);
        $h->write($data);
        return $h->sum();
    }
    
    public static function hash512($data) {
        $h = new self(64);
        $h->write($data);
        return $h->sum();
    }
}

// Test
if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    $test = "The quick brown fox jumps over the lazy dog";
    
    echo "Streebog (GOST R 34.11-2012) Test\n";
    echo "=================================\n\n";
    echo "Test string: $test\n\n";
    
    $hash256 = Streebog::hash256($test);
    echo "Streebog-256: " . bin2hex($hash256) . "\n";
    
    $hash512 = Streebog::hash512($test);
    echo "Streebog-512: " . bin2hex($hash512) . "\n";
}
?>
