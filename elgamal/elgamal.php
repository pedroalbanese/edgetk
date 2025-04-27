<?php

/**
 * Biblioteca Criptográfica ElGamal
 * Combina funções de assinatura digital e criptografia
 */
class ElGamalCrypto {
    // =============================================
    // Funções Matemáticas Básicas
    // =============================================

    /**
     * Exponenciação modular (base^exp % mod)
     */
    public static function modexp($base, $exp, $mod) {
        $result = "1";
        $base = bcmod($base, $mod);
        while (bccomp($exp, "0") > 0) {
            if (bcmod($exp, "2") === "1") {
                $result = bcmod(bcmul($result, $base), $mod);
            }
            $exp = bcdiv($exp, "2", 0);
            $base = bcmod(bcmul($base, $base), $mod);
        }
        return $result;
    }

    /**
     * Algoritmo de Euclides Estendido para inverso modular
     */
    public static function modinv($a, $m) {
        $m0 = $m;
        $x0 = "0";
        $x1 = "1";

        while (bccomp($a, "1") > 0) {
            $q = bcdiv($a, $m, 0);
            $t = $m;

            $m = bcmod($a, $m);
            $a = $t;
            $t = $x0;

            $x0 = bcsub($x1, bcmul($q, $x0));
            $x1 = $t;
        }

        if (bccomp($x1, "0") < 0) {
            $x1 = bcadd($x1, $m0);
        }

        return $x1;
    }

    /**
     * Converte hexadecimal para decimal (big int)
     */
    public static function hexToDec($hex) {
        $hex = strtolower($hex);
        $dec = '0';
        $len = strlen($hex);
        for ($i = 0; $i < $len; $i++) {
            $digit = strpos('0123456789abcdef', $hex[$i]);
            $dec = bcmul($dec, '16');
            $dec = bcadd($dec, (string)$digit);
        }
        return $dec;
    }

    /**
     * Converte decimal para hexadecimal (big int)
     */
    public static function bcdechex($dec) {
        $hex = '';
        do {
            $last = bcmod($dec, '16');
            $hex = dechex($last) . $hex;
            $dec = bcdiv($dec, '16', 0);
        } while (bccomp($dec, '0') > 0);
        return $hex;
    }

    /**
     * Calcula o MDC (Máximo Divisor Comum)
     */
    public static function gcd($a, $b) {
        while (bccomp($b, "0") != 0) {
            $temp = $b;
            $b = bcmod($a, $b);
            $a = $temp;
        }
        return $a;
    }

    // =============================================
    // Funções de Geração de Números Aleatórios
    // =============================================

    /**
     * Gera um número aleatório grande usando /dev/urandom
     */
    public static function generate_random_number($min, $max) {
        $range = bcsub($max, $min);
        $bits = self::bc_bit_length($range) + 64;
        
        $bytes = (int)ceil($bits / 8);
        $random_data = file_get_contents('/dev/urandom', false, null, 0, $bytes);
        $random_hex = bin2hex($random_data);
        $random_num = self::bchexdec($random_hex);
        
        $random_num = bcmod($random_num, bcadd($range, "1"));
        return bcadd($random_num, $min);
    }

    /**
     * Gera um k coprimo com p-1
     */
    public static function generate_coprime_k($p) {
        $p_minus_1 = bcsub($p, "1");
        $min = "2";
        $max = bcsub($p_minus_1, "1");
        
        do {
            $k = self::generate_random_number($min, $max);
        } while (self::gcd($k, $p_minus_1) !== "1");
        
        return $k;
    }

    // =============================================
    // Funções de Conversão de Dados
    // =============================================

    /**
     * Converte string para inteiro grande
     */
    public static function bytesToInt($str) {
        $result = '0';
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $result = bcadd(bcmul($result, '256'), (string)ord($str[$i]));
        }
        return $result;
    }

    /**
     * Converte inteiro grande de volta para string
     */
    public static function intToBytes($intVal) {
        $bytes = '';
        while (bccomp($intVal, '0') > 0) {
            $byte = bcmod($intVal, '256');
            $bytes = chr((int)$byte) . $bytes;
            $intVal = bcdiv($intVal, '256');
        }
        return $bytes;
    }

    /**
     * Função de hash compatível com Whirlpool
     */
    public static function hash_message($message, $mod) {
        $hash = hash('whirlpool', $message, true);
        $hashInt = '0';
        for ($i = 0; $i < strlen($hash); $i++) {
            $hashInt = bcadd(bcmul($hashInt, '256'), strval(ord($hash[$i])));
        }
        return bcmod($hashInt, $mod);
    }

    // =============================================
    // Funções de Assinatura Digital
    // =============================================

    /**
     * Gera assinatura ElGamal
     */
    public static function elgamal_sign($message, $p, $g, $x, $k = null) {
        $p1 = bcsub($p, "1");
        
        if ($k === null) {
            $k = self::generate_coprime_k($p);
        } elseif (bccomp(bcmod($k, $p1), "0") === 0) {
            throw new Exception("k deve ser primo relativo a p-1");
        }

        $r = self::modexp($g, $k, $p);
        $h = self::hash_message($message, $p1);
        $xr = bcmod(bcmul($x, $r), $p1);
        $s1 = bcsub($h, $xr);
        if (bccomp($s1, "0") < 0) {
            $s1 = bcadd($s1, $p1);
        }

        $k_inv = self::modinv($k, $p1);
        $s = bcmod(bcmul($k_inv, $s1), $p1);

        return ['r' => $r, 's' => $s];
    }

    /**
     * Verifica assinatura ElGamal
     */
    public static function elgamal_verify($message, $r, $s, $p, $g, $y) {
        if (bccomp($r, '0') <= 0 || bccomp($r, bcsub($p, '1')) >= 0) {
            return false;
        }

        $h = self::hash_message($message, $p);

        $v1 = self::modexp($g, $h, $p);
        $yr = self::modexp($y, $r, $p);
        $rs = self::modexp($r, $s, $p);
        $v2 = bcmod(bcmul($yr, $rs), $p);

        return bccomp($v1, $v2) === 0;
    }

    // =============================================
    // Funções de Criptografia/Descriptografia
    // =============================================

    /**
     * Criptografa uma mensagem usando ElGamal
     */
    public static function elgamal_encrypt($message, $p, $g, $y, $k = null) {
        $m = self::bytesToInt($message);
        $pMinus2 = bcsub($p, '2');
        
        if ($k === null) {
            $k = self::generate_random_number('1', $pMinus2);
        }
        
        $c1 = self::modexp($g, $k, $p);
        $s = self::modexp($y, $k, $p);
        $c2 = bcmod(bcmul($m, $s), $p);
        
        return ['c1' => $c1, 'c2' => $c2];
    }

    /**
     * Descriptografa uma mensagem usando ElGamal
     */
    public static function elgamal_decrypt($c1, $c2, $p, $x) {
        $s = self::modexp($c1, $x, $p);
        $s_inv = self::modexp($s, bcsub($p, '2'), $p); // Inverso multiplicativo
        $m = bcmod(bcmul($c2, $s_inv), $p);
        
        return self::intToBytes($m);
    }

    // =============================================
    // Funções Auxiliares
    // =============================================

    /**
     * Estima o número de bits de um número BC
     */
    private static function bc_bit_length($number) {
        $length = 0;
        $temp = $number;
        while (bccomp($temp, "0") > 0) {
            $temp = bcdiv($temp, "2", 0);
            $length++;
        }
        return $length;
    }

    /**
     * Converte hexadecimal para decimal (alternativa)
     */
    private static function bchexdec($hex) {
        $dec = "0";
        $len = strlen($hex);
        for ($i = 0; $i < $len; $i++) {
            $current = hexdec($hex[$i]);
            $dec = bcmul($dec, "16");
            $dec = bcadd($dec, $current);
        }
        return $dec;
    }
}

/**
 * Funções para manipulação de arquivos de cifra
 */
class ElGamalFile {
    /**
     * Salva o texto cifrado em arquivo
     */
    public static function save_ciphertext($filename, $cipher) {
        $content = "c1 = " . ElGamalCrypto::bcdechex($cipher['c1']) . "\n";
        $content .= "c2 = " . ElGamalCrypto::bcdechex($cipher['c2']);
        file_put_contents($filename, $content);
    }

    /**
     * Lê o texto cifrado de arquivo
     */
    public static function read_ciphertext($filename) {
        $contents = file_get_contents($filename);
        if (!$contents) {
            throw new Exception("Erro ao ler o arquivo: $filename");
        }

        preg_match('/c1 = ([0-9a-fA-F]+)/', $contents, $match_c1);
        preg_match('/c2 = ([0-9a-fA-F]+)/', $contents, $match_c2);

        if (count($match_c1) === 0 || count($match_c2) === 0) {
            throw new Exception("Não foi possível extrair c1 ou c2 do arquivo.");
        }

        return [
            'c1' => ElGamalCrypto::hexToDec($match_c1[1]),
            'c2' => ElGamalCrypto::hexToDec($match_c2[1]),
        ];
    }

    /**
     * Salva assinatura em arquivo
     */
    public static function save_signature($filename, $signature) {
        $content = "r = " . ElGamalCrypto::bcdechex($signature['r']) . "\n";
        $content .= "s = " . ElGamalCrypto::bcdechex($signature['s']);
        file_put_contents($filename, $content);
    }

    /**
     * Lê assinatura de arquivo
     */
    public static function read_signature($filename) {
        $contents = file_get_contents($filename);
        if (!$contents) {
            throw new Exception("Erro ao ler o arquivo: $filename");
        }

        preg_match('/r = ([0-9a-fA-F]+)/', $contents, $match_r);
        preg_match('/s = ([0-9a-fA-F]+)/', $contents, $match_s);

        if (count($match_r) === 0 || count($match_s) === 0) {
            throw new Exception("Não foi possível extrair r ou s do arquivo.");
        }

        return [
            'r' => ElGamalCrypto::hexToDec($match_r[1]),
            's' => ElGamalCrypto::hexToDec($match_s[1]),
        ];
    }
}

// Parâmetros públicos do sistema (3072 bits)
define('ELGAMAL_P', ElGamalCrypto::hexToDec('b3361eb41e256582262a39a8bd0e093a434fe64ab005da3cd65880ea1d8ddd2568ff508e05f3a3fe5358eeb06a32329cf211cd6db30f61bfea323e2ca06fd3fdedcb79045a9b6506090d3dd2cd31148ccaa92cf95273490cdbcf285ec6ccb6ae4607a0654a518ecf21897a0e92e2caade5a66d90dd8c6775717f126413fee527a7ecfdc870cc74438a71cfddb486aadb9b74a4c09f1d2d20c5ca7a5a73526782ccc51d868f97485a8eec21ed20ad20590d3999a472dcfddb3f77f3c3315e7aea64372092f0e93161a82397e3592e275697efced77683584ccb7a01fdc83117d5f28cb818fafaa2abb2284562f92e45902c50cef61c2547eb31d7afaa50485b0229b9a7ad803d473ddc66218ebf1c284dc2fdc251caa7a77299081f12d8ca91f63200e29812b7a09a229f3c05a0037df4478f9146a334a89bf49a716cee243f7f7cfc08ba485d2a420a7361a21aa115773f555cedd7b39ed48e70ae8c7887903a1f9fd386ce0648e34c7e6054943fceadf0efdcec6b7f9d5f6f4473e7d8ab5c6f'));
define('ELGAMAL_G', ElGamalCrypto::hexToDec('7f9833fffa3139db133421f7eaae6b7dbc35827162d7c48bbb38d3b05ca288fd4c91cf8a57e07fe51dbcb02c2bfc3df3c2c95328d3428caf0d47040319f28c26061b1e928006d2b6c5eda9889ba6ef8a711b8c0c0d2ab34e1b3ea7ba77582c6b738d48878ffd3900961c772693dce7518c59b7db5b17660928b8583a2a92247c5f56306cd1f948e784741c5ac962f2dbcf411eab33d42bbb6a25dd50d0e75aeb170f7a95b26803132c13da1c11e2a0045987374e8226bf1f9ff53616fd686c29926216b6f6e0a5719cb541a34b3171b354ac9725f9351c2885f613e761119b28733ad627cc22c7e09b4d2455e5b8bdef46f7966c06a6116d87bc162afe6763664a3f91b554494412e4e48afef92e68d68caf4b5e5e229fda4adf9a8812ff4aeebc4eb7aff4b3d3cff9f4384fd98c845497fa6ade3b013691788dd15a2a7fa129aa11542cf6452a03a9fe50ad7af926fd6601552c52f7e2f17dc17eb8bd0aaf03ed30ca651c755a708ca10483ed254e2dc714c91b7d0e9bcfe34918908f69f0b2'));
?>
