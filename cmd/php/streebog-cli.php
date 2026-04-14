#!/usr/bin/env php
<?php
/**
 * gost12sum - Streebog (GOST R 34.11-2012) Hash Utility
 * Compatível com edgetk: -key para HMAC e HKDF
 */

require_once __DIR__ . '/streebog.php';

class GOST12SumCLI {
    private $algorithm = 64;
    private $recursive = false;
    private $checkFile = null;
    private $binary = true;
    private $key = null;           // Chave para HMAC/HKDF (compatível com edgetk)
    private $keyIsHex = false;
    private $salt = null;          // Salt para HKDF
    private $info = '';            // Info para HKDF
    private $length = 32;          // Length para HKDF
    private $hexInput = false;
    private $files = [];
    private $algorithmBits = 512;
    private $isHmacMode = false;
    private $isHkdfMode = false;
    
    public function __construct() {
        $this->parseArgs();
    }
    
    private function parseArgs() {
        $argv = $_SERVER['argv'];
        $argc = count($argv);
        
        for ($i = 1; $i < $argc; $i++) {
            $arg = $argv[$i];
            
            switch ($arg) {
                case '-a':
                case '--algorithm':
                    $i++;
                    if ($i >= $argc) $this->error("Missing argument for $arg");
                    $this->algorithmBits = (int)$argv[$i];
                    $this->algorithm = ($this->algorithmBits === 256) ? 32 : 64;
                    break;
                    
                case '-r':
                case '--recursive':
                    $this->recursive = true;
                    break;
                    
                case '-c':
                case '--check':
                    $i++;
                    if ($i < $argc && $argv[$i][0] !== '-') {
                        $this->checkFile = $argv[$i];
                    } else {
                        $this->checkFile = '-';
                        $i--;
                    }
                    break;
                    
                case '-b':
                case '--binary':
                    $this->binary = true;
                    break;
                    
                case '-t':
                case '--text':
                    $this->binary = false;
                    break;
                    
                case '-hmac':
                    $this->isHmacMode = true;
                    break;
                    
                case '-hkdf':
                    $this->isHkdfMode = true;
                    break;
                    
                case '-key':
                    $i++;
                    if ($i >= $argc) $this->error("Missing argument for $arg");
                    $this->key = $argv[$i];
                    break;
                    
                case '-salt':
                    $i++;
                    if ($i >= $argc) $this->error("Missing argument for $arg");
                    $this->salt = $argv[$i];
                    break;
                    
                case '-info':
                    $i++;
                    if ($i >= $argc) $this->error("Missing argument for $arg");
                    $this->info = $argv[$i];
                    break;
                    
                case '-l':
                    $i++;
                    if ($i >= $argc) $this->error("Missing argument for $arg");
                    $this->length = (int)$argv[$i];
                    break;
                    
                case '--hex':
                    $this->hexInput = true;
                    $this->keyIsHex = true;
                    break;
                    
                case '--version':
                    echo "gost12sum version 1.0.0 (Streebog GOST R 34.11-2012)\n";
                    exit(0);
                    
                case '-h':
                case '--help':
                    $this->showHelp();
                    exit(0);
                    
                default:
                    if (strpos($arg, '-') === 0 && $arg !== '-') {
                        $this->error("Unknown option: $arg");
                    }
                    $this->files[] = $arg;
            }
        }
    }
    
    private function isPiped() {
        return !function_exists('posix_isatty') || !posix_isatty(STDIN);
    }
    
    private function showHelp() {
        echo <<<HELP
gost12sum - Streebog (GOST R 34.11-2012) Hash Utility
Compatível com edgetk

Usage:
  gost12sum [options] [files...]                    Compute hash
  gost12sum -hmac -key <key> [files...]             Compute HMAC
  gost12sum -hkdf -key <ikm> [-salt <salt>] [-info <info>] [-l <len>]
  gost12sum -c [file]                               Check hashes

Options:
  -a, --algorithm <256|512>   Hash algorithm [default: 512]
  -r, --recursive             Process directories recursively
  -b, --binary                Binary mode (* prefix) [default]
  -t, --text                  Text mode (no * prefix)
  -hmac                       HMAC mode
  -hkdf                       HKDF mode
  -key <key>                  Key for HMAC or IKM for HKDF
  -salt <salt>                Salt for HKDF (optional)
  -info <info>                Context info for HKDF (optional)
  -l <bytes>                  Output length for HKDF [default: 32]
  --hex                       Input key/salt as hex string
  --version                   Show version
  -h, --help                  Show help

Examples:
  gost12sum file.txt
  gost12sum -a 256 file.txt
  gost12sum -c checksums.txt
  cat checksums.txt | gost12sum -c
  gost12sum -hmac -key "123" file.txt
  gost12sum -hkdf -key "ikm" -salt "salt" -info "info" -l 32

HELP;
    }
    
    private function error($msg) {
        fwrite(STDERR, "Error: $msg\n");
        exit(1);
    }
    
    private function decodeInput($input) {
        if ($this->hexInput || $this->keyIsHex) {
            $decoded = hex2bin($input);
            if ($decoded === false) {
                $this->error("Invalid hex string: $input");
            }
            return $decoded;
        }
        return $input;
    }
    
    public function run() {
        // HKDF mode
        if ($this->isHkdfMode) {
            $this->runHKDF();
            return;
        }
        
        // HMAC mode
        if ($this->isHmacMode) {
            $this->runHMAC();
            return;
        }
        
        // Check mode
        if ($this->checkFile !== null) {
            $this->runCheck();
            return;
        }
        
        // Hash mode
        if ($this->isPiped() && empty($this->files)) {
            $this->hashStdin();
        } else if (!empty($this->files)) {
            $this->hashFiles();
        } else {
            $this->showHelp();
            exit(1);
        }
    }
    
    private function hashStdin() {
        $input = file_get_contents('php://stdin');
        if ($input === false) {
            $this->error("Failed to read from stdin");
        }
        
        $streebog = new Streebog($this->algorithm);
        $streebog->write($input);
        $hash = $streebog->sum();
        echo bin2hex($hash) . "\n";
    }
    
    private function hashFiles() {
        foreach ($this->files as $file) {
            $this->processFile($file);
        }
    }
    
    private function processFile($path) {
        if (!file_exists($path)) {
            fwrite(STDERR, "Warning: File '$path' not found\n");
            return;
        }
        
        if (is_dir($path)) {
            if ($this->recursive) {
                $files = $this->getFilesRecursive($path);
                foreach ($files as $file) {
                    $this->hashSingleFile($file);
                }
            } else {
                fwrite(STDERR, "Warning: $path is a directory (use -r)\n");
            }
        } else {
            $this->hashSingleFile($path);
        }
    }
    
    private function getFilesRecursive($dir) {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = $file->getPathname();
            }
        }
        sort($files);
        return $files;
    }
    
    private function hashSingleFile($file) {
        if (!is_readable($file)) {
            fwrite(STDERR, "Warning: Cannot read '$file'\n");
            return;
        }
        
        $fh = fopen($file, 'rb');
        if (!$fh) {
            fwrite(STDERR, "Warning: Failed to open '$file'\n");
            return;
        }
        
        $streebog = new Streebog($this->algorithm);
        while (!feof($fh)) {
            $data = fread($fh, 8192);
            if ($data !== false && $data !== '') {
                $streebog->write($data);
            }
        }
        fclose($fh);
        
        $hash = bin2hex($streebog->sum());
        echo $hash . " *" . $file . "\n";
    }
    
    private function runHMAC() {
        if ($this->key === null) {
            $this->error("HMAC requires -key parameter");
        }
        
        $key = $this->decodeInput($this->key);
        
        if ($this->isPiped() && empty($this->files)) {
            $data = file_get_contents('php://stdin');
            if ($data === false) {
                $this->error("Failed to read from stdin");
            }
            $hmac = $this->computeHMAC($data, $key);
            echo bin2hex($hmac) . "\n";
        } else {
            foreach ($this->files as $file) {
                if (is_dir($file) && $this->recursive) {
                    $files = $this->getFilesRecursive($file);
                    foreach ($files as $f) {
                        $data = file_get_contents($f);
                        if ($data !== false) {
                            $hmac = $this->computeHMAC($data, $key);
                            echo bin2hex($hmac) . " *" . $f . "\n";
                        }
                    }
                } else {
                    $data = file_get_contents($file);
                    if ($data === false) {
                        fwrite(STDERR, "Warning: Failed to read '$file'\n");
                        continue;
                    }
                    $hmac = $this->computeHMAC($data, $key);
                    echo bin2hex($hmac) . " *" . $file . "\n";
                }
            }
        }
    }
    
    private function computeHMAC($data, $key) {
        $blockSize = 64;
        
        if (strlen($key) > $blockSize) {
            $streebog = new Streebog($this->algorithm);
            $streebog->write($key);
            $key = $streebog->sum();
        }
        
        if (strlen($key) < $blockSize) {
            $key = str_pad($key, $blockSize, "\x00");
        }
        
        $ipad = '';
        $opad = '';
        for ($i = 0; $i < $blockSize; $i++) {
            $ipad .= chr(ord($key[$i]) ^ 0x36);
            $opad .= chr(ord($key[$i]) ^ 0x5C);
        }
        
        $inner = new Streebog($this->algorithm);
        $inner->write($ipad);
        $inner->write($data);
        $innerHash = $inner->sum();
        
        $outer = new Streebog($this->algorithm);
        $outer->write($opad);
        $outer->write($innerHash);
        
        return $outer->sum();
    }
    
    private function runHKDF() {
        if ($this->key === null) {
            $this->error("HKDF requires -key parameter");
        }
        
        $ikm = $this->decodeInput($this->key);
        $salt = $this->salt !== null ? $this->decodeInput($this->salt) : '';
        $info = $this->info;
        $length = $this->length;
        
        $okm = $this->hkdf($ikm, $length, $salt, $info);
        echo bin2hex($okm) . "\n";
    }
    
    private function hkdf($ikm, $length, $salt = '', $info = '') {
        $hashLen = $this->algorithm;
        
        if (empty($salt)) {
            $salt = str_repeat("\x00", $hashLen);
        }
        
        $prk = $this->computeHMAC($ikm, $salt);
        
        $okm = '';
        $t = '';
        $counter = 1;
        
        while (strlen($okm) < $length) {
            $t = $this->computeHMAC($t . $info . chr($counter), $prk);
            $okm .= $t;
            $counter++;
        }
        
        return substr($okm, 0, $length);
    }
    
    private function runCheck() {
        if ($this->checkFile === '-') {
            $content = file_get_contents('php://stdin');
            if ($content === false) {
                $this->error("Failed to read from stdin");
            }
            $lines = explode("\n", $content);
        } else {
            if (!is_readable($this->checkFile)) {
                $this->error("Cannot read: {$this->checkFile}");
            }
            $lines = file($this->checkFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }
        
        $failed = 0;
        $passed = 0;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            if (preg_match('/^([a-f0-9]+)\s+\*?(.+)$/', $line, $matches)) {
                $expectedHash = $matches[1];
                $filename = trim($matches[2]);
                
                if (!file_exists($filename)) {
                    echo "$filename: FAILED (not found)\n";
                    $failed++;
                    continue;
                }
                
                if (is_dir($filename)) {
                    echo "$filename: FAILED (is a directory)\n";
                    $failed++;
                    continue;
                }
                
                $actualHash = $this->hashFileForCheck($filename);
                
                if ($expectedHash === $actualHash) {
                    echo "$filename: OK\n";
                    $passed++;
                } else {
                    echo "$filename: FAILED\n";
                    $failed++;
                }
            }
        }
        
        echo "\n$passed passed, $failed failed\n";
        exit($failed > 0 ? 1 : 0);
    }
    
    private function hashFileForCheck($file) {
        $fh = fopen($file, 'rb');
        if (!$fh) {
            return '';
        }
        
        $streebog = new Streebog($this->algorithm);
        while (!feof($fh)) {
            $data = fread($fh, 8192);
            if ($data !== false && $data !== '') {
                $streebog->write($data);
            }
        }
        fclose($fh);
        
        return bin2hex($streebog->sum());
    }
}

if (PHP_SAPI === 'cli') {
    $app = new GOST12SumCLI();
    $app->run();
}
?>
