#!/usr/bin/env php
<?php
/**
 * VKO GOST R 34.10-2012 512-bit - Key Agreement Tool
 * 100% Compatible with EdgeTK (GoGOST)
 * 
 * Features:
 * - Curve A (paramSetA)
 * - Streebog-512 as KDF
 * - Kuznechik-CBC for key encryption (RFC 1423)
 */

require_once 'streebog.php';
require_once 'kuznechik.php';

bcscale(0);

// ===============================
// Helpers
// ===============================

function bcmodp($x, $p) {
    $r = bcmod($x, $p);
    if (bccomp($r, "0") < 0) $r = bcadd($r, $p);
    return $r;
}

function bcinv($a, $p) {
    $lm = "1"; $hm = "0";
    $low = bcmodp($a, $p); 
    $high = $p;

    while (bccomp($low, "1") > 0) {
        $r = bcdiv($high, $low);
        $nm = bcsub($hm, bcmul($lm, $r));
        $new = bcsub($high, bcmul($low, $r));
        $hm = $lm; $high = $low;
        $lm = $nm; $low = $new;
    }
    return bcmodp($lm, $p);
}

function bcpowmod_simple($a, $e, $m) {
    $result = "1";
    $a = bcmod($a, $m);

    while (bccomp($e, "0") > 0) {
        if (bcmod($e, "2") === "1") {
            $result = bcmod(bcmul($result, $a), $m);
        }
        $a = bcmod(bcmul($a, $a), $m);
        $e = bcdiv($e, "2");
    }
    return $result;
}

function hex2dec($hex) {
    $dec = "0";
    $hex = ltrim($hex, '0');
    if ($hex === '') $hex = '0';
    for ($i = 0; $i < strlen($hex); $i++) {
        $dec = bcmul($dec, "16");
        $dec = bcadd($dec, hexdec($hex[$i]));
    }
    return $dec;
}

function dec2hex($dec) {
    if ($dec === "0") return "0";
    $hex = "";
    while (bccomp($dec, "0") > 0) {
        $hex = dechex((int)bcmod($dec, "16")) . $hex;
        $dec = bcdiv($dec, "16", 0);
    }
    return $hex;
}

function le($hex) {
    return implode('', array_reverse(str_split($hex, 2)));
}

function be($hex) {
    return implode('', array_reverse(str_split($hex, 2)));
}

// ===============================
// Structures
// ===============================

class Curve {
    public $p, $a, $b, $Gx, $Gy, $n;

    public function __construct($p, $a, $b, $Gx, $Gy, $n) {
        $this->p  = hex2dec($p);
        $this->a  = hex2dec($a);
        $this->b  = hex2dec($b);
        $this->Gx = hex2dec($Gx);
        $this->Gy = hex2dec($Gy);
        $this->n  = hex2dec($n);
    }
}

class Point {
    public $x, $y, $inf = false;

    public function __construct($x = null, $y = null) {
        if ($x === null) {
            $this->inf = true;
        } else {
            $this->x = $x;
            $this->y = $y;
        }
    }
}

// ===============================
// ECC Operations
// ===============================

function point_add($curve, $P, $Q) {
    if ($P->inf) return $Q;
    if ($Q->inf) return $P;

    $p = $curve->p;

    if (bccomp($P->x, $Q->x) == 0) {
        if (bccomp(bcmodp(bcadd($P->y, $Q->y), $p), "0") == 0) {
            return new Point();
        }
        return point_double($curve, $P);
    }

    $lambda = bcmul(
        bcsub($Q->y, $P->y),
        bcinv(bcsub($Q->x, $P->x), $p)
    );
    $lambda = bcmodp($lambda, $p);

    $x = bcsub(bcsub(bcpowmod_simple($lambda, "2", $p), $P->x), $Q->x);
    $x = bcmodp($x, $p);

    $y = bcsub(bcmul($lambda, bcsub($P->x, $x)), $P->y);
    $y = bcmodp($y, $p);

    return new Point($x, $y);
}

function point_double($curve, $P) {
    if ($P->inf) return $P;

    $p = $curve->p;

    $lambda = bcmul(
        bcadd(bcmul("3", bcpowmod_simple($P->x, "2", $p)), $curve->a),
        bcinv(bcmul("2", $P->y), $p)
    );
    $lambda = bcmodp($lambda, $p);

    $x = bcsub(bcpowmod_simple($lambda, "2", $p), bcmul("2", $P->x));
    $x = bcmodp($x, $p);

    $y = bcsub(bcmul($lambda, bcsub($P->x, $x)), $P->y);
    $y = bcmodp($y, $p);

    return new Point($x, $y);
}

function scalar_mul($curve, $k, $P) {
    $result = new Point();
    $addend = $P;

    while (bccomp($k, "0") > 0) {
        if (bcmod($k, "2") == "1") {
            $result = point_add($curve, $result, $addend);
        }
        $addend = point_double($curve, $addend);
        $k = bcdiv($k, "2");
    }

    return $result;
}

// ===============================
// GOST 512-bit Curve A (paramSetA)
// ===============================

function curveA() {
    return new Curve(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
        "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
        "3",
        "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"
    );
}

// ===============================
// VKO Functions
// ===============================

function random_scalar($n) {
    $bytes = random_bytes(64);
    $hex = bin2hex($bytes);
    return bcmod(hex2dec($hex), $n);
}

function pubkey($curve, $priv) {
    return scalar_mul($curve, $priv, new Point($curve->Gx, $curve->Gy));
}

// ===============================
// RFC 1423 Key Derivation (MD5-based)
// ===============================

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

// ===============================
// PKCS#8 PEM with Kuznechik-CBC support
// ===============================

class GostPEM
{
    private static $oid_algorithm = "\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x02";
    private static $oid_paramset = "\x06\x09\x2a\x85\x03\x07\x01\x02\x01\x02\x01";
    
    /**
     * Convert private key to PKCS#8 PEM (with or without encryption)
     */
    public static function privateToPEM($privateKeyHex, $password = null) {
        $privateKeyLe = le($privateKeyHex);
        $privateKeyBin = hex2bin($privateKeyLe);
        
        $inner = "\x04\x40" . $privateKeyBin;
        $privateKey = "\x04" . chr(strlen($inner)) . $inner;
        $paramSet = "\x30" . chr(strlen(self::$oid_paramset)) . self::$oid_paramset;
        $algorithm = self::$oid_algorithm . $paramSet;
        $algId = "\x30" . chr(strlen($algorithm)) . $algorithm;
        $version = "\x02\x01\x00";
        $total = $version . $algId . $privateKey;
        $pkcs8 = "\x30" . chr(strlen($total)) . $total;
        
        if ($password) {
            // Encrypt with Kuznechik-CBC (RFC 1423)
            return self::encryptPrivateKey($pkcs8, $password);
        } else {
            $b64 = base64_encode($pkcs8);
            $lines = str_split($b64, 64);
            return "-----BEGIN GOST PRIVATE KEY-----\n" .
                   implode("\n", $lines) . "\n" .
                   "-----END GOST PRIVATE KEY-----\n";
        }
    }
    
    /**
     * Encrypt private key using Kuznechik-CBC
     */
    private static function encryptPrivateKey($derData, $password) {
        // Generate random IV (16 bytes for Kuznechik)
        $iv = random_bytes(16);
        
        // Derive 32-byte key (Kuznechik) using RFC 1423
        $key = rfc1423_derive_key_md5($password, $iv, 32);
        
        // Encrypt with Kuznechik-CBC
        $cipher = new Kuznechik($key);
        $ciphertext = self::cbcEncrypt($cipher, $derData, $iv);
        
        // Format as PEM with RFC 1423 headers
        $b64 = base64_encode($ciphertext);
        $lines = str_split($b64, 64);
        
        $pem = "-----BEGIN GOST PRIVATE KEY-----\n";
        $pem .= "Proc-Type: 4,ENCRYPTED\n";
        $pem .= "DEK-Info: KUZNECHIK-CBC," . strtoupper(bin2hex($iv)) . "\n";
        $pem .= "\n";
        $pem .= implode("\n", $lines) . "\n";
        $pem .= "-----END GOST PRIVATE KEY-----\n";
        
        return $pem;
    }
    
    /**
     * CBC encryption for Kuznechik
     */
    private static function cbcEncrypt($cipher, $data, $iv) {
        $blockSize = Kuznechik::BLOCK_SIZE;
        
        // PKCS#7 padding
        $padding = $blockSize - (strlen($data) % $blockSize);
        $data .= str_repeat(chr($padding), $padding);
        
        $result = '';
        $prevBlock = $iv;
        
        for ($i = 0; $i < strlen($data); $i += $blockSize) {
            $block = substr($data, $i, $blockSize);
            
            // XOR with previous block
            $xored = '';
            for ($j = 0; $j < $blockSize; $j++) {
                $xored .= chr(ord($block[$j]) ^ ord($prevBlock[$j]));
            }
            
            // Encrypt
            $encrypted = $cipher->encryptBlock($xored);
            $result .= $encrypted;
            $prevBlock = $encrypted;
        }
        
        return $result;
    }
    
    /**
     * CBC decryption for Kuznechik
     */
    private static function cbcDecrypt($cipher, $data, $iv) {
        $blockSize = Kuznechik::BLOCK_SIZE;
        
        if (strlen($data) % $blockSize !== 0) {
            throw new Exception("Invalid ciphertext length");
        }
        
        $result = '';
        $prevBlock = $iv;
        
        for ($i = 0; $i < strlen($data); $i += $blockSize) {
            $block = substr($data, $i, $blockSize);
            
            // Decrypt
            $decrypted = $cipher->decryptBlock($block);
            
            // XOR with previous block
            $plain = '';
            for ($j = 0; $j < $blockSize; $j++) {
                $plain .= chr(ord($decrypted[$j]) ^ ord($prevBlock[$j]));
            }
            
            $result .= $plain;
            $prevBlock = $block;
        }
        
        // Remove PKCS#7 padding
        $padding = ord($result[strlen($result) - 1]);
        if ($padding > 0 && $padding <= $blockSize) {
            $result = substr($result, 0, -$padding);
        }
        
        return $result;
    }
    
    /**
     * Generate public key PEM
     */
    public static function publicToPEM($publicKeyHex) {
        $xBe = substr($publicKeyHex, 0, 128);
        $yBe = substr($publicKeyHex, 128, 128);
        
        $xLe = le($xBe);
        $yLe = le($yBe);
        
        $publicKeyLe = $xLe . $yLe;
        $publicKeyBin = hex2bin($publicKeyLe);
        
        $paramSet = "\x30" . chr(strlen(self::$oid_paramset)) . self::$oid_paramset;
        $algorithm = self::$oid_algorithm . $paramSet;
        $algId = "\x30" . chr(strlen($algorithm)) . $algorithm;
        
        $octet = "\x04\x81\x80" . $publicKeyBin;
        $bitString = "\x03\x81\x84\x00" . $octet;
        $content = $algId . $bitString;
        $der = "\x30\x81\xa0" . $content;
        
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        
        return "-----BEGIN PUBLIC KEY-----\n" .
               implode("\n", $lines) . "\n" .
               "-----END PUBLIC KEY-----\n";
    }
    
    /**
     * Parse private key PEM (supports encrypted and unencrypted)
     */
    public static function parsePrivatePEM($pemData, $password = null) {
        $lines = explode("\n", trim($pemData));
        $b64 = '';
        $inData = false;
        $isEncrypted = false;
        $iv = null;
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            if (strpos($line, "-----BEGIN GOST PRIVATE KEY-----") === 0) {
                $inData = true;
                continue;
            }
            if (strpos($line, "-----END GOST PRIVATE KEY-----") === 0) {
                break;
            }
            
            if ($inData) {
                // Check RFC 1423 headers
                if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                    $isEncrypted = true;
                    continue;
                }
                if (strpos($line, "DEK-Info:") === 0) {
                    $parts = explode(",", $line);
                    if (count($parts) >= 2) {
                        $iv = hex2bin(trim($parts[1]));
                    }
                    continue;
                }
                if (empty($line)) {
                    continue;
                }
                if (!str_contains($line, ":")) {
                    $b64 .= $line;
                }
            }
        }
        
        $der = base64_decode($b64);
        if ($der === false) {
            throw new Exception("Invalid base64 data");
        }
        
        if ($isEncrypted) {
            if (!$password) {
                throw new Exception("Password required for encrypted private key");
            }
            if (!$iv || strlen($iv) !== 16) {
                throw new Exception("Invalid IV for Kuznechik-CBC");
            }
            
            // Derive 32-byte key
            $key = rfc1423_derive_key_md5($password, $iv, 32);
            
            // Decrypt
            $cipher = new Kuznechik($key);
            $der = self::cbcDecrypt($cipher, $der, $iv);
        }
        
        // Parse DER
        $pos = strpos($der, "\x04\x40");
        if ($pos === false) {
            throw new Exception("Cannot find private key in DER");
        }
        
        $privateBytes = substr($der, $pos + 2, 64);
        $privateHexLe = bin2hex($privateBytes);
        
        return be($privateHexLe);
    }
    
    /**
     * Parse public key PEM
     */
    public static function parsePublicPEM($pemData) {
        $lines = explode("\n", trim($pemData));
        $b64 = '';
        $inData = false;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (strpos($line, "-----BEGIN PUBLIC KEY-----") === 0) {
                $inData = true;
                continue;
            }
            if (strpos($line, "-----END PUBLIC KEY-----") === 0) {
                break;
            }
            if ($inData && $line) {
                $b64 .= $line;
            }
        }
        
        $der = base64_decode($b64);
        if ($der === false) {
            throw new Exception("Invalid base64 data");
        }
        
        $pos = strpos($der, "\x04\x81\x80");
        if ($pos === false) {
            throw new Exception("Cannot find public key in DER");
        }
        
        $publicBytes = substr($der, $pos + 3, 128);
        $publicHexLe = bin2hex($publicBytes);
        
        $xLe = substr($publicHexLe, 0, 128);
        $yLe = substr($publicHexLe, 128, 128);
        
        $xBe = be($xLe);
        $yBe = be($yLe);
        
        return $xBe . $yBe;
    }
}

// ===============================
// EdgeTK VKO (uses LE(XY) for KDF)
// ===============================

function vko_edgetk($curve, $priv, $pub) {
    $shared = scalar_mul($curve, $priv, $pub);
    
    $xBe = str_pad(dec2hex($shared->x), 128, "0", STR_PAD_LEFT);
    $yBe = str_pad(dec2hex($shared->y), 128, "0", STR_PAD_LEFT);
    
    $xLe = le($xBe);
    $yLe = le($yBe);
    
    $keyMaterial = hex2bin($xLe . $yLe);
    
    return Streebog::hash512($keyMaterial);
}

// ===============================
// CLI
// ===============================

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($argv[0])) {
    $options = [
        'keygen' => false,
        'derive' => false,
        'priv' => null,
        'pub' => null,
        'password' => null,
        'help' => false
    ];
    
    for ($i = 1; $i < $argc; $i++) {
        switch ($argv[$i]) {
            case 'keygen': $options['keygen'] = true; break;
            case 'derive': $options['derive'] = true; break;
            case '--priv': if (isset($argv[$i+1])) $options['priv'] = $argv[++$i]; break;
            case '--pub': if (isset($argv[$i+1])) $options['pub'] = $argv[++$i]; break;
            case '--password': if (isset($argv[$i+1])) $options['password'] = $argv[++$i]; break;
            case '--help': case '-h': $options['help'] = true; break;
        }
    }
    
    if ($options['help']) {
        echo "VKO GOST R 34.10-2012 512-bit - Key Agreement Tool\n";
        echo "100% Compatible with EdgeTK (GoGOST)\n";
        echo "Uses Streebog-512 as KDF\n";
        echo "Supports Kuznechik-CBC for encrypted keys\n\n";
        echo "Usage:\n";
        echo "  php " . basename($argv[0]) . " keygen --priv <file> --pub <file> [--password <pwd>]\n";
        echo "  php " . basename($argv[0]) . " derive --priv <file> --pub <file> [--password <pwd>]\n\n";
        exit(0);
    }
    
    try {
        $curve = curveA();
        
        if ($options['keygen']) {
            if (!$options['priv'] || !$options['pub']) {
                fwrite(STDERR, "Error: --priv and --pub are required\n");
                exit(1);
            }
            
            $priv = random_scalar($curve->n);
            $privHex = str_pad(dec2hex($priv), 128, "0", STR_PAD_LEFT);
            $pubPoint = pubkey($curve, $priv);
            $pubHex = str_pad(dec2hex($pubPoint->x), 128, "0", STR_PAD_LEFT) . 
                      str_pad(dec2hex($pubPoint->y), 128, "0", STR_PAD_LEFT);
            
            $pemPriv = GostPEM::privateToPEM($privHex, $options['password']);
            $pemPub = GostPEM::publicToPEM($pubHex);
            
            file_put_contents($options['priv'], $pemPriv);
            file_put_contents($options['pub'], $pemPub);
            
            fwrite(STDERR, "Keys saved:\n");
            fwrite(STDERR, "  Private: " . $options['priv'] . "\n");
            fwrite(STDERR, "  Public:  " . $options['pub'] . "\n");
            if ($options['password']) {
                fwrite(STDERR, "  Encrypted with password\n");
            }
            exit(0);
        }
        
        if ($options['derive']) {
            if (!$options['priv'] || !$options['pub']) {
                fwrite(STDERR, "Error: --priv and --pub are required\n");
                exit(1);
            }
            
            $privPem = file_get_contents($options['priv']);
            $pubPem = file_get_contents($options['pub']);
            
            $privHex = GostPEM::parsePrivatePEM($privPem, $options['password']);
            $pubHex = GostPEM::parsePublicPEM($pubPem);
            
            $priv = hex2dec($privHex);
            $pub = new Point(
                hex2dec(substr($pubHex, 0, 128)),
                hex2dec(substr($pubHex, 128, 128))
            );
            
            $result = vko_edgetk($curve, $priv, $pub);
            
            echo bin2hex($result) . "\n";
            exit(0);
        }
        
        fwrite(STDERR, "Error: No command specified. Use --help\n");
        exit(1);
        
    } catch (Exception $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
}
