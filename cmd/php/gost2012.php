#!/usr/bin/env php
<?php
/**
 * GOST R 34.10-2012 256-bit - Key Agreement (VKO) and Digital Signature Tool
 * 100% Compatible with EdgeTK (GoGOST)
 * Curve: id-tc26-gost-3410-12-256-paramSetA (TwistedEdwards)
 * Supports Kuznechik-CBC for encrypted private keys (RFC 1423)
 */

require_once 'streebog.php';
require_once 'kuznechik.php';

bcscale(0);

// ===============================
// Helpers
// ===============================

function bytes2big($bytes) {
    return hex2dec(bin2hex($bytes));
}

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
// Password handling
// ===============================

function get_password($prompt = "Enter password: ", $confirm = false) {
    if (defined('STDIN')) {
        echo $prompt;
        system('stty -echo');
        $password = trim(fgets(STDIN));
        system('stty echo');
        echo "\n";
        
        if ($confirm) {
            echo "Confirm password: ";
            system('stty -echo');
            $confirm_password = trim(fgets(STDIN));
            system('stty echo');
            echo "\n";
            
            if ($password !== $confirm_password) {
                throw new Exception("Passwords do not match");
            }
        }
        
        return $password;
    } else {
        return readline($prompt);
    }
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
// Curva Weierstrass (paramSetA 256-bit)
// Parâmetros do GoGOST: id-tc26-gost-3410-12-256-paramSetA
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
    
    public function add(&$x1, &$y1, $x2, $y2) {
        $p = $this->p;
        
        if (bccomp($x1, $x2) == 0 && bccomp($y1, $y2) == 0) {
            $t = bcadd(bcmul("3", bcpowmod_simple($x1, "2", $p)), $this->a);
            $t = bcmod($t, $p);
            $tx = bcmul("2", $y1);
            $tx = bcmod($tx, $p);
            $tx = bcinv($tx, $p);
            $t = bcmod(bcmul($t, $tx), $p);
        } else {
            $tx = bcsub($x2, $x1);
            $tx = bcmod($tx, $p);
            if (bccomp($tx, "0") < 0) $tx = bcadd($tx, $p);
            
            $ty = bcsub($y2, $y1);
            $ty = bcmod($ty, $p);
            if (bccomp($ty, "0") < 0) $ty = bcadd($ty, $p);
            
            $tx = bcinv($tx, $p);
            $t = bcmod(bcmul($ty, $tx), $p);
        }
        
        $tx = bcsub(bcsub(bcpowmod_simple($t, "2", $p), $x1), $x2);
        $tx = bcmod($tx, $p);
        if (bccomp($tx, "0") < 0) $tx = bcadd($tx, $p);
        
        $ty = bcsub(bcmul($t, bcsub($x1, $tx)), $y1);
        $ty = bcmod($ty, $p);
        if (bccomp($ty, "0") < 0) $ty = bcadd($ty, $p);
        
        $x1 = $tx;
        $y1 = $ty;
    }
    
    public function exp($degree, $xS, $yS) {
        if (bccomp($degree, "0") == 0) {
            return null;
        }
        $dg = bcsub($degree, "1");
        $tx = $xS;
        $ty = $yS;
        $cx = $xS;
        $cy = $yS;
        
        while (bccomp($dg, "0") != 0) {
            if (bcmod($dg, "2") == "1") {
                $this->add($tx, $ty, $cx, $cy);
            }
            $dg = bcdiv($dg, "2");
            $this->add($cx, $cy, $cx, $cy);
        }
        return [$tx, $ty];
    }
}

// ===============================
// Curva A 256-bit (paramSetA) - Weierstrass
// Parâmetros do GoGOST: id-tc26-gost-3410-12-256-paramSetA
// ===============================

function curveA() {
    return new Curve(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
        "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
        "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
        "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
        "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
    );
}

function random_scalar($n) {
    $bytes = random_bytes(32);
    $hex = bin2hex($bytes);
    return bcmod(hex2dec($hex), $n);
}

function hash_digest($data) {
    return Streebog::hash256($data);
}

// ===============================
// VKO Functions
// ===============================

function vko_derive($curve, $priv, $pubX, $pubY) {
    // Calcula o ponto compartilhado: dA * QB
    list($sharedX, $sharedY) = $curve->exp($priv, $pubX, $pubY);
    
    // Aplica o cofactor (4 para paramSetA)
    $cofactor = "4";
    list($sharedX, $sharedY) = $curve->exp($cofactor, $sharedX, $sharedY);
    
    // Serializa como LE(X) || LE(Y) (EdgeTK para paramSetA)
    $xBe = str_pad(dec2hex($sharedX), 64, "0", STR_PAD_LEFT);
    $yBe = str_pad(dec2hex($sharedY), 64, "0", STR_PAD_LEFT);
    
    $xLe = le($xBe);
    $yLe = le($yBe);
    
    // EdgeTK: LE(X) || LE(Y)
    $keyMaterial = hex2bin($xLe . $yLe);
    
    // Streebog-256
    return Streebog::hash256($keyMaterial);
}

// ===============================
// Digital Signature Functions
// ===============================

function sign_digest($curve, $priv, $digest) {
    $e = bytes2big($digest);
    $e = bcmod($e, $curve->n);
    if (bccomp($e, "0") == 0) $e = "1";
    
    $pointSize = 32;
    
    do {
        do {
            $kRaw = random_bytes($pointSize);
            $k = bytes2big($kRaw);
            $k = bcmod($k, $curve->n);
        } while (bccomp($k, "0") == 0);
        
        list($rx, $ry) = $curve->exp($k, $curve->Gx, $curve->Gy);
        $r = bcmod($rx, $curve->n);
        
        if (bccomp($r, "0") == 0) continue;
        
        $d = bcmul($priv, $r);
        $k_mul_e = bcmul($k, $e);
        $s = bcadd($d, $k_mul_e);
        $s = bcmod($s, $curve->n);
        
    } while (bccomp($s, "0") == 0);
    
    $s_bytes = hex2bin(str_pad(dec2hex($s), $pointSize * 2, "0", STR_PAD_LEFT));
    $r_bytes = hex2bin(str_pad(dec2hex($r), $pointSize * 2, "0", STR_PAD_LEFT));
    
    return $s_bytes . $r_bytes;
}

function sign($curve, $priv, $data) {
    $digest = hash_digest($data);
    return bin2hex(sign_digest($curve, $priv, $digest));
}

function verify_digest($curve, $pubX, $pubY, $digest, $signature) {
    $pointSize = 32;
    
    $s_bytes = substr($signature, 0, $pointSize);
    $r_bytes = substr($signature, $pointSize, $pointSize);
    
    $s = bytes2big($s_bytes);
    $r = bytes2big($r_bytes);
    
    if (bccomp($r, "0") <= 0 || bccomp($r, $curve->n) >= 0) return false;
    if (bccomp($s, "0") <= 0 || bccomp($s, $curve->n) >= 0) return false;
    
    $e = bytes2big($digest);
    $e = bcmod($e, $curve->n);
    if (bccomp($e, "0") == 0) $e = "1";
    
    $v = bcinv($e, $curve->n);
    
    $z1 = bcmod(bcmul($s, $v), $curve->n);
    $z2 = bcmod(bcmul($r, $v), $curve->n);
    $z2 = bcsub($curve->n, $z2);
    
    list($p1x, $p1y) = $curve->exp($z1, $curve->Gx, $curve->Gy);
    list($p2x, $p2y) = $curve->exp($z2, $pubX, $pubY);
    
    $curve->add($p1x, $p1y, $p2x, $p2y);
    $R = bcmod($p1x, $curve->n);
    
    return bccomp($R, $r) == 0;
}

function verify($curve, $pubX, $pubY, $data, $signature_hex) {
    $digest = hash_digest($data);
    $signature = hex2bin($signature_hex);
    return verify_digest($curve, $pubX, $pubY, $digest, $signature);
}

// ===============================
// PKCS#8 PEM with Kuznechik-CBC support
// OID correto para paramSetA: 1.2.643.7.1.2.1.1.1
// ===============================

class GostPEM
{
    private static $oid_algorithm = "\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x02";
    private static $oid_paramset = "\x06\x09\x2a\x85\x03\x07\x01\x02\x01\x01\x01";
    
    public static function privateToPEM($privateKeyHex, $password = null) {
        $privateKeyLe = le($privateKeyHex);
        $privateKeyBin = hex2bin($privateKeyLe);
        
        $inner = "\x04\x20" . $privateKeyBin;
        $privateKey = "\x04" . chr(strlen($inner)) . $inner;
        $paramSet = "\x30" . chr(strlen(self::$oid_paramset)) . self::$oid_paramset;
        $algorithm = self::$oid_algorithm . $paramSet;
        $algId = "\x30" . chr(strlen($algorithm)) . $algorithm;
        $version = "\x02\x01\x00";
        $total = $version . $algId . $privateKey;
        $pkcs8 = "\x30" . chr(strlen($total)) . $total;
        
        if ($password) {
            return self::encryptPrivateKey($pkcs8, $password);
        } else {
            $b64 = base64_encode($pkcs8);
            $lines = str_split($b64, 64);
            return "-----BEGIN GOST PRIVATE KEY-----\n" .
                   implode("\n", $lines) . "\n" .
                   "-----END GOST PRIVATE KEY-----\n";
        }
    }
    
    private static function encryptPrivateKey($derData, $password) {
        $iv = random_bytes(16);
        $key = rfc1423_derive_key_md5($password, $iv, 32);
        
        $cipher = new Kuznechik($key);
        $ciphertext = self::cbcEncrypt($cipher, $derData, $iv);
        
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
    
    private static function cbcEncrypt($cipher, $data, $iv) {
        $blockSize = Kuznechik::BLOCK_SIZE;
        $padding = $blockSize - (strlen($data) % $blockSize);
        $data .= str_repeat(chr($padding), $padding);
        
        $result = '';
        $prevBlock = $iv;
        
        for ($i = 0; $i < strlen($data); $i += $blockSize) {
            $block = substr($data, $i, $blockSize);
            $xored = '';
            for ($j = 0; $j < $blockSize; $j++) {
                $xored .= chr(ord($block[$j]) ^ ord($prevBlock[$j]));
            }
            $encrypted = $cipher->encryptBlock($xored);
            $result .= $encrypted;
            $prevBlock = $encrypted;
        }
        
        return $result;
    }
    
    private static function cbcDecrypt($cipher, $data, $iv) {
        $blockSize = Kuznechik::BLOCK_SIZE;
        
        if (strlen($data) % $blockSize !== 0) {
            throw new Exception("Invalid ciphertext length");
        }
        
        $result = '';
        $prevBlock = $iv;
        
        for ($i = 0; $i < strlen($data); $i += $blockSize) {
            $block = substr($data, $i, $blockSize);
            $decrypted = $cipher->decryptBlock($block);
            $plain = '';
            for ($j = 0; $j < $blockSize; $j++) {
                $plain .= chr(ord($decrypted[$j]) ^ ord($prevBlock[$j]));
            }
            $result .= $plain;
            $prevBlock = $block;
        }
        
        $padding = ord($result[strlen($result) - 1]);
        if ($padding > 0 && $padding <= $blockSize) {
            $result = substr($result, 0, -$padding);
        }
        
        return $result;
    }
    
    public static function publicToPEM($publicKeyHex) {
        $xBe = substr($publicKeyHex, 0, 64);
        $yBe = substr($publicKeyHex, 64, 64);
        
        $xLe = le($xBe);
        $yLe = le($yBe);
        
        $publicKeyBin = hex2bin($xLe . $yLe);
        
        $der = "\x30\x5e" .
               "\x30\x17" .
               "\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x02" .
               "\x30\x0b" .
               "\x06\x09\x2a\x85\x03\x07\x01\x02\x01\x01\x01" .
               "\x03\x43\x00" .
               "\x04\x40" . $publicKeyBin;
        
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        
        return "-----BEGIN PUBLIC KEY-----\n" .
               implode("\n", $lines) . "\n" .
               "-----END PUBLIC KEY-----\n";
    }
    
    public static function isEncryptedPEM($pemData) {
        return (strpos($pemData, "Proc-Type: 4,ENCRYPTED") !== false);
    }
    
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
            if (strpos($line, "-----END GOST PRIVATE KEY-----") === 0) break;
            
            if ($inData) {
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
                if (empty($line)) continue;
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
            
            $key = rfc1423_derive_key_md5($password, $iv, 32);
            $cipher = new Kuznechik($key);
            $der = self::cbcDecrypt($cipher, $der, $iv);
        }
        
        $pos = strpos($der, "\x04\x20");
        if ($pos === false) {
            throw new Exception("Cannot find private key in DER");
        }
        
        $privateBytes = substr($der, $pos + 2, 32);
        $privateHexLe = bin2hex($privateBytes);
        
        return be($privateHexLe);
    }
    
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
            if (strpos($line, "-----END PUBLIC KEY-----") === 0) break;
            if ($inData && $line) {
                $b64 .= $line;
            }
        }
        
        $der = base64_decode($b64);
        if ($der === false) {
            throw new Exception("Invalid base64 data");
        }
        
        $pos = strpos($der, "\x04\x40");
        if ($pos === false) {
            throw new Exception("Cannot find public key in DER");
        }
        
        $publicBytes = substr($der, $pos + 2, 64);
        $publicHexLe = bin2hex($publicBytes);
        
        $xLe = substr($publicHexLe, 0, 64);
        $yLe = substr($publicHexLe, 64, 64);
        
        $xBe = be($xLe);
        $yBe = be($yLe);
        
        return $xBe . $yBe;
    }
}

// ===============================
// Parse command (edgetk style)
// ===============================

function cmd_parse($args) {
    $key_file = null;
    $password = null;
    
    for ($i = 0; $i < count($args); $i++) {
        $arg = $args[$i];
        
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif ($arg === '--key' && isset($args[$i+1])) {
            $key_file = $args[++$i];
        } elseif (strpos($arg, '--password') === 0) {
            if (strpos($arg, '--password=') === 0) {
                $password = substr($arg, 11);
            } else {
                $password = get_password("Enter password to decrypt private key: ");
            }
        }
    }
    
    if (!$key_file) {
        echo "ERROR: Key not specified (use --key FILE or --key=FILE)\n";
        return 1;
    }
    
    if (!file_exists($key_file)) {
        echo "ERROR: Key file not found: $key_file\n";
        return 1;
    }
    
    $pem_data = file_get_contents($key_file);
    if ($pem_data === false) {
        echo "ERROR: Cannot read key file: $key_file\n";
        return 1;
    }
    
    $is_private = (strpos($pem_data, "PRIVATE KEY") !== false);
    $is_public = (strpos($pem_data, "PUBLIC KEY") !== false);
    
    if (!$is_private && !$is_public) {
        echo "ERROR: Unknown key format\n";
        return 1;
    }
    
    $is_encrypted = GostPEM::isEncryptedPEM($pem_data);
    
    if ($is_encrypted && $is_private && !$password) {
        $password = get_password("Enter password to decrypt private key: ");
    }
    
    try {
        if ($is_private) {
            $keyHexBe = GostPEM::parsePrivatePEM($pem_data, $password);
            $keyHexLe = le($keyHexBe);
            $decryptedPEM = GostPEM::privateToPEM($keyHexBe, null);
            echo $decryptedPEM;
        } else {
            $keyHexBe = GostPEM::parsePublicPEM($pem_data);
            $keyHexLe = le($keyHexBe);
            echo $pem_data;
        }
    } catch (Exception $e) {
        echo "ERROR: Failed to parse key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    $curve = curveA();
    
    if ($is_private) {
        $priv = hex2dec($keyHexBe);
        list($pubX, $pubY) = $curve->exp($priv, $curve->Gx, $curve->Gy);
        $xBe = str_pad(dec2hex($pubX), 64, "0", STR_PAD_LEFT);
        $yBe = str_pad(dec2hex($pubY), 64, "0", STR_PAD_LEFT);
        
        echo "Private key: " . strtoupper($keyHexLe) . "\n";
        echo "Public key: \n";
        echo "   X:" . strtoupper($xBe) . "\n";
        echo "   Y:" . strtoupper($yBe) . "\n";
    } else {
        $xBe = substr($keyHexBe, 0, 64);
        $yBe = substr($keyHexBe, 64, 64);
        echo "Public key:\n";
        echo "   X:" . strtoupper($xBe) . "\n";
        echo "   Y:" . strtoupper($yBe) . "\n";
    }
    
    echo "Curve: id-tc26-gost-3410-12-256-paramSetA\n";
    
    if ($is_private) {
        list($pubX, $pubY) = $curve->exp(hex2dec($keyHexBe), $curve->Gx, $curve->Gy);
        $xLe = le(str_pad(dec2hex($pubX), 64, "0", STR_PAD_LEFT));
        $yLe = le(str_pad(dec2hex($pubY), 64, "0", STR_PAD_LEFT));
        $rawPublic = hex2bin($xLe . $yLe);
    } else {
        $xLe = le($xBe);
        $yLe = le($yBe);
        $rawPublic = hex2bin($xLe . $yLe);
    }
    
    $keyIdFull = Streebog::hash256($rawPublic);
    $keyId = substr(bin2hex($keyIdFull), 0, 40);
    echo "\nKeyID: " . $keyId . "\n";
    
    return 0;
}

// ===============================
// CLI
// ===============================

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($argv[0])) {
    $options = [
        'keygen' => false,
        'derive' => false,
        'sign' => false,
        'verify' => false,
        'parse' => false,
        'priv' => null,
        'pub' => null,
        'data' => null,
        'sig' => null,
        'password' => null,
        'help' => false
    ];
    
    // Check for parse command
    if ($argc >= 2 && $argv[1] === 'parse') {
        $parse_args = array_slice($argv, 2);
        exit(cmd_parse($parse_args));
    }
    
    for ($i = 1; $i < $argc; $i++) {
        switch ($argv[$i]) {
            case 'keygen': $options['keygen'] = true; break;
            case 'derive': $options['derive'] = true; break;
            case 'sign': $options['sign'] = true; break;
            case 'verify': $options['verify'] = true; break;
            case '--priv': if (isset($argv[$i+1])) $options['priv'] = $argv[++$i]; break;
            case '--pub': if (isset($argv[$i+1])) $options['pub'] = $argv[++$i]; break;
            case '--data': if (isset($argv[$i+1])) $options['data'] = $argv[++$i]; break;
            case '--sig': if (isset($argv[$i+1])) $options['sig'] = $argv[++$i]; break;
            case '--password': 
                if (isset($argv[$i+1]) && $argv[$i+1][0] !== '-') {
                    $options['password'] = $argv[++$i];
                } else {
                    $options['password'] = get_password("Enter password: ");
                }
                break;
            case '--help': case '-h': $options['help'] = true; break;
        }
    }
    
    if ($options['help']) {
        echo "GOST R 34.10-2012 256-bit - Key Agreement and Digital Signature Tool\n";
        echo "100% Compatible with EdgeTK (GoGOST)\n";
        echo "Curve: id-tc26-gost-3410-12-256-paramSetA\n";
        echo "Hash: Streebog-256\n";
        echo "Supports Kuznechik-CBC for encrypted keys\n\n";
        echo "Usage:\n";
        echo "  php gost.php keygen --priv <file> --pub <file> [--password <pwd>]\n";
        echo "  php gost.php derive --priv <file> --pub <file> [--password <pwd>]\n";
        echo "  php gost.php sign --priv <file> --data <file> [--password <pwd>]\n";
        echo "  php gost.php verify --pub <file> --data <file> --sig <hex>\n";
        echo "  php gost.php parse --key <file> [--password]\n\n";
        exit(0);
    }
    
    try {
        $curve = curveA();
        
        if ($options['keygen']) {
            if (!$options['priv'] || !$options['pub']) die("Error: --priv and --pub required\n");
            
            $priv = random_scalar($curve->n);
            $privHex = str_pad(dec2hex($priv), 64, "0", STR_PAD_LEFT);
            list($pubX, $pubY) = $curve->exp($priv, $curve->Gx, $curve->Gy);
            $pubHex = str_pad(dec2hex($pubX), 64, "0", STR_PAD_LEFT) . 
                      str_pad(dec2hex($pubY), 64, "0", STR_PAD_LEFT);
            
            $pemPriv = GostPEM::privateToPEM($privHex, $options['password']);
            $pemPub = GostPEM::publicToPEM($pubHex);
            
            file_put_contents($options['priv'], $pemPriv);
            file_put_contents($options['pub'], $pemPub);
            
            fwrite(STDERR, "Private key saved to: " . $options['priv'] . "\n");
            fwrite(STDERR, "Public key saved to: " . $options['pub'] . "\n");
            if ($options['password']) {
                fwrite(STDERR, "Encrypted with password\n");
            }
            exit(0);
        }
        elseif ($options['derive']) {
            if (!$options['priv'] || !$options['pub']) die("Error: --priv and --pub required\n");
            
            $privPem = file_get_contents($options['priv']);
            $pubPem = file_get_contents($options['pub']);
            
            $isEncrypted = GostPEM::isEncryptedPEM($privPem);
            $password = $options['password'];
            
            if ($isEncrypted && !$password) {
                $password = get_password("Enter password to decrypt private key: ");
            }
            
            $privHex = GostPEM::parsePrivatePEM($privPem, $password);
            $pubHex = GostPEM::parsePublicPEM($pubPem);
            
            $priv = hex2dec($privHex);
            $pubX = hex2dec(substr($pubHex, 0, 64));
            $pubY = hex2dec(substr($pubHex, 64, 64));
            
            $shared = vko_derive($curve, $priv, $pubX, $pubY);
            echo bin2hex($shared) . "\n";
        }
        elseif ($options['sign']) {
            if (!$options['priv'] || !$options['data']) die("Error: --priv and --data required\n");
            
            $privPem = file_get_contents($options['priv']);
            
            $isEncrypted = GostPEM::isEncryptedPEM($privPem);
            $password = $options['password'];
            
            if ($isEncrypted && !$password) {
                $password = get_password("Enter password to decrypt private key: ");
            }
            
            $privHex = GostPEM::parsePrivatePEM($privPem, $password);
            $priv = hex2dec($privHex);
            $data = file_get_contents($options['data']);
            
            $signature = sign($curve, $priv, $data);
            echo $signature . "\n";
        }
        elseif ($options['verify']) {
            if (!$options['pub'] || !$options['data'] || !$options['sig']) die("Error: --pub, --data and --sig required\n");
            
            $pubPem = file_get_contents($options['pub']);
            $pubHex = GostPEM::parsePublicPEM($pubPem);
            $pubX = hex2dec(substr($pubHex, 0, 64));
            $pubY = hex2dec(substr($pubHex, 64, 64));
            $data = file_get_contents($options['data']);
            
            $valid = verify($curve, $pubX, $pubY, $data, $options['sig']);
            echo $valid ? "Signature valid\n" : "Signature invalid\n";
            exit($valid ? 0 : 1);
        }
        else {
            die("No command specified. Use --help\n");
        }
        
    } catch (Exception $e) {
        die("Error: " . $e->getMessage() . "\n");
    }
}
