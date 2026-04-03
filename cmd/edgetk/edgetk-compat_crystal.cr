# crypto.cr
# Unified tool with X448, ED521, Curupira192-CBC and Anubis-GCM

require "big"
require "random/secure"
require "base64"
require "option_parser"

# ====================================================================
# Global helper functions (defined outside any module)
# ====================================================================

def constant_time_compare(a : Bytes, b : Bytes) : Bool
  return false if a.size != b.size
  result = 0
  a.size.times { |i| result |= a[i] ^ b[i] }
  result == 0
end

def xor_bytes(a : Bytes, b : Bytes) : Bytes
  len = Math.min(a.size, b.size)
  Bytes.new(len).tap do |result|
    len.times { |i| result[i] = (a[i] ^ b[i]).to_u8 }
  end
end

def hex_to_bytes(hex : String) : Bytes
  hex = hex.gsub(/\s+/, "")
  hex = "0" + hex if hex.size.odd?
  bytes = Bytes.new(hex.size // 2)
  hex.size.times do |i|
    next if i.even?
    byte = hex[i-1, 2].to_u8(16)
    bytes[(i-1)//2] = byte
  end
  bytes
end

def bytes_to_hex(bytes : Bytes) : String
  String.build { |str| bytes.each { |b| str << b.to_s(16).rjust(2, '0') } }
end

# ====================================================================
# MD5 Implementation in Pure Crystal (version with safe operations)
# ====================================================================

module MD5
  # Per-round shift amounts
  S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]

  # Constants K[i]
  K = [
    0xd76aa478_u32, 0xe8c7b756_u32, 0x242070db_u32, 0xc1bdceee_u32,
    0xf57c0faf_u32, 0x4787c62a_u32, 0xa8304613_u32, 0xfd469501_u32,
    0x698098d8_u32, 0x8b44f7af_u32, 0xffff5bb1_u32, 0x895cd7be_u32,
    0x6b901122_u32, 0xfd987193_u32, 0xa679438e_u32, 0x49b40821_u32,
    0xf61e2562_u32, 0xc040b340_u32, 0x265e5a51_u32, 0xe9b6c7aa_u32,
    0xd62f105d_u32, 0x02441453_u32, 0xd8a1e681_u32, 0xe7d3fbc8_u32,
    0x21e1cde6_u32, 0xc33707d6_u32, 0xf4d50d87_u32, 0x455a14ed_u32,
    0xa9e3e905_u32, 0xfcefa3f8_u32, 0x676f02d9_u32, 0x8d2a4c8a_u32,
    0xfffa3942_u32, 0x8771f681_u32, 0x6d9d6122_u32, 0xfde5380c_u32,
    0xa4beea44_u32, 0x4bdecfa9_u32, 0xf6bb4b60_u32, 0xbebfbc70_u32,
    0x289b7ec6_u32, 0xeaa127fa_u32, 0xd4ef3085_u32, 0x04881d05_u32,
    0xd9d4d039_u32, 0xe6db99e5_u32, 0x1fa27cf8_u32, 0xc4ac5665_u32,
    0xf4292244_u32, 0x432aff97_u32, 0xab9423a7_u32, 0xfc93a039_u32,
    0x655b59c3_u32, 0x8f0ccc92_u32, 0xffeff47d_u32, 0x85845dd1_u32,
    0x6fa87e4f_u32, 0xfe2ce6e0_u32, 0xa3014314_u32, 0x4e0811a1_u32,
    0xf7537e82_u32, 0xbd3af235_u32, 0x2ad7d2bb_u32, 0xeb86d391_u32
  ]

  # Initial hash values
  H0 = 0x67452301_u32
  H1 = 0xefcdab89_u32
  H2 = 0x98badcfe_u32
  H3 = 0x10325476_u32

  def self.rotate_left(x : UInt32, n : Int32) : UInt32
    (x << n) | (x >> (32 - n))
  end

  def self.pad(message : Bytes) : Bytes
    orig_size_in_bits = message.size.to_u64 * 8
    result = Bytes.new(0)
    
    # Append bit '1'
    result += Bytes[0x80]
    
    # Append 0 bits until length in bits ≡ 448 (mod 512)
    while ((message.size + result.size).to_u64 * 8) % 512 != 448
      result += Bytes[0x00]
    end
    
    # Append original length in bits as 64-bit little-endian
    8.times do |i|
      result += Bytes[((orig_size_in_bits >> (8 * i)) & 0xFF).to_u8]
    end
    
    message + result
  end

  def self.digest(data : Bytes) : Bytes
    # Pad the message
    padded = pad(data)
    
    # Initialize hash values
    a0 = H0
    b0 = H1
    c0 = H2
    d0 = H3
    
    # Process each 512-bit block
    (0...padded.size).step(64) do |i|
      # Create 16-word array of 32-bit words (little-endian)
      m = Array(UInt32).new(16, 0_u32)
      16.times do |j|
        word = 0_u32
        4.times do |k|
          byte = padded[i + j*4 + k].to_u32
          word |= byte << (8 * k)
        end
        m[j] = word
      end
      
      # Initialize hash for this block
      a = a0
      b = b0
      c = c0
      d = d0
      
      # Main loop
      64.times do |j|
        f = 0_u32
        g = 0
        if j < 16
          f = (b & c) | ((~b) & d)
          g = j
        elsif j < 32
          f = (d & b) | ((~d) & c)
          g = (5*j + 1) % 16
        elsif j < 48
          f = b ^ c ^ d
          g = (3*j + 5) % 16
        else
          f = c ^ (b | (~d))
          g = (7*j) % 16
        end
        
        # Using Crystal's wrapping addition
        temp = a &+ f &+ K[j] &+ m[g]
        a = d
        d = c
        c = b
        b = b &+ rotate_left(temp, S[j])
      end
      
      # Add this block's hash to result (wrapping addition)
      a0 = a0 &+ a
      b0 = b0 &+ b
      c0 = c0 &+ c
      d0 = d0 &+ d
    end
    
    # Produce final hash (16 bytes, little-endian)
    result = Bytes.new(16)
    4.times do |i|
      result[i] = ((a0 >> (8 * i)) & 0xFF).to_u8
      result[i + 4] = ((b0 >> (8 * i)) & 0xFF).to_u8
      result[i + 8] = ((c0 >> (8 * i)) & 0xFF).to_u8
      result[i + 12] = ((d0 >> (8 * i)) & 0xFF).to_u8
    end
    
    result
  end

  def self.hexdigest(data : Bytes) : String
    bytes_to_hex(digest(data))
  end

  def self.hexdigest(data : String) : String
    hexdigest(data.to_slice)
  end
end

# ====================================================================
# RFC 1423 KEY DERIVATION (MD5-based)
# ====================================================================

def rfc1423_derive_key_md5(password : String, salt : Bytes, key_size : Int32) : Bytes
  # Use first 8 bytes of salt for key derivation (as per RFC 1423)
  iv_salt = salt[0, 8]
  
  # RFC 1423 uses MD5 iteratively: D_i = MD5(D_{i-1} || P || S)
  d = Bytes.new(0)
  result = Bytes.new(0)
  
  while result.size < key_size
    # D_i = MD5(D_{i-1} || P || S)
    md5_input = d + password.to_slice + iv_salt
    d = MD5.digest(md5_input)
    result = result + d
  end
  
  result[0, key_size]
end

# ====================================================================
# RFC 1423 ENCRYPTION FOR PRIVATE KEYS
# ====================================================================

def encrypt_private_key_pem(data : Bytes, password : String, cipher_name : String = "CURUPIRA-192-CBC") : String
  raise "Unsupported cipher: #{cipher_name}" if cipher_name != "CURUPIRA-192-CBC"
  
  # Generate random IV (12 bytes for Curupira)
  iv = Random::Secure.random_bytes(12)
  
  # Derive key using RFC 1423 method (192-bit = 24 bytes)
  key = rfc1423_derive_key_md5(password, iv, 24)
  
  # Create Curupira cipher with derived key
  cipher = Curupira1::Cipher.new(key)
  
  # Create CBC mode with IV
  cbc = Curupira1::CBC.new(cipher, iv)
  
  # Encrypt data
  encrypted_data = cbc.encrypt(data)
  
  # Note: IV is NOT included in encrypted data (only in header)
  # Format as PEM with RFC 1423 headers
  b64_data = Base64.strict_encode(encrypted_data)
  lines = b64_data.scan(/.{1,64}/).map(&.[0])
  
  String.build do |io|
    io << "Proc-Type: 4,ENCRYPTED\n"
    io << "DEK-Info: #{cipher_name},#{bytes_to_hex(iv)}\n"
    io << "\n"
    lines.each { |line| io << line << "\n" }
  end
end

def decrypt_private_key_pem(pem_content : String, password : String) : Bytes
  lines = pem_content.lines
  
  # Remove BEGIN/END lines
  lines = lines.reject { |l| l.starts_with?("-----") }
  
  # Parse headers
  proc_type = nil
  dek_info = nil
  b64_lines = [] of String
  in_headers = true
  
  lines.each do |line|
    line = line.strip
    
    if line.empty? && in_headers
      in_headers = false
      next
    end
    
    if in_headers
      if line.starts_with?("Proc-Type:")
        proc_type = line[10..-1].strip
        raise "Not an encrypted PEM block" if proc_type != "4,ENCRYPTED"
      elsif line.starts_with?("DEK-Info:")
        dek_info = line[10..-1].strip
      end
    else
      b64_lines << line
    end
  end
  
  raise "Missing DEK-Info header" if dek_info.nil?
  
  # Parse DEK-Info
  dek_parts = dek_info.split(",", 2)
  raise "Invalid DEK-Info format: #{dek_info}" if dek_parts.size != 2
  
  cipher_name = dek_parts[0].strip
  iv_hex = dek_parts[1].strip
  
  raise "Unsupported cipher: #{cipher_name}" if cipher_name != "CURUPIRA-192-CBC"
  
  iv = hex_to_bytes(iv_hex)
  raise "Invalid IV length" if iv.size != 12
  
  # Decode base64 data
  b64_data = b64_lines.join
  encrypted_data = Base64.decode(b64_data)
  
  # Derive key using the IV from header
  key = rfc1423_derive_key_md5(password, iv, 24)
  
  # Create Curupira cipher with derived key
  cipher = Curupira1::Cipher.new(key)
  
  # Create CBC mode with IV from header
  cbc = Curupira1::CBC.new(cipher, iv)
  
  # Decrypt
  cbc.decrypt(encrypted_data)
rescue e
  raise "Decryption failed (wrong password?): #{e.message}"
end

# ====================================================================
# ED521 PEM FUNCTIONS WITH RFC 1423 ENCRYPTION
# ====================================================================

def ed521_private_to_pem_pkcs8(private_key : BigInt, password : String? = nil) : String
  priv_bytes = little_int_to_bytes(private_key, ED521::BYTE_LEN)
  
  # ED521 OID: 1.3.6.1.4.1.44588.2.1
  encoded_oid = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  oid_der = Bytes[0x06, 0x0a] + encoded_oid
  algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]
  
  version = Bytes[0x02, 0x01, 0x00]
  
  # Private key as OCTET STRING (tag 0x04, length 66)
  priv_field = Bytes[0x04, 0x42] + priv_bytes
  
  content = version + algorithm_id + priv_field
  content_len = content.size
  
  # SEQUENCE
  pkcs8 = if content_len <= 0x7F
            Bytes[0x30, content_len.to_u8] + content
          else
            Bytes[0x30, 0x81, content_len.to_u8] + content
          end
  
  if password
    # Encrypt using RFC 1423 with Curupira-192-CBC
    encrypted_content = encrypt_private_key_pem(pkcs8, password)
    "-----BEGIN E-521 PRIVATE KEY-----\n#{encrypted_content}-----END E-521 PRIVATE KEY-----\n"
  else
    b64 = Base64.strict_encode(pkcs8)
    lines = b64.scan(/.{1,64}/).map(&.[0])
    
    String.build do |io|
      io << "-----BEGIN E-521 PRIVATE KEY-----\n"
      lines.each { |line| io << line << "\n" }
      io << "-----END E-521 PRIVATE KEY-----\n"
    end
  end
end

def ed521_public_to_pem(public_x : BigInt, public_y : BigInt) : String
  compressed = compress_point(public_x, public_y)
  
  # ED521 OID: 1.3.6.1.4.1.44588.2.1
  encoded_oid = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  oid_der = Bytes[0x06, 0x0a] + encoded_oid
  algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]
  
  # BIT STRING with compressed point
  bit_string_data = Bytes[0x00] + compressed
  bit_string_len = bit_string_data.size
  
  bit_string = if bit_string_len <= 0x7F
                 Bytes[0x03, bit_string_len.to_u8] + bit_string_data
               else
                 Bytes[0x03, 0x81, bit_string_len.to_u8] + bit_string_data
               end
  
  content = algorithm_id + bit_string
  content_len = content.size
  
  spki = if content_len <= 0x7F
           Bytes[0x30, content_len.to_u8] + content
         else
           Bytes[0x30, 0x81, content_len.to_u8] + content
         end
  
  b64 = Base64.strict_encode(spki)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  
  String.build do |io|
    io << "-----BEGIN E-521 PUBLIC KEY-----\n"
    lines.each { |line| io << line << "\n" }
    io << "-----END E-521 PUBLIC KEY-----\n"
  end
end

def parse_ed521_private_key_pem(pem_content : String, password : String? = nil) : BigInt
  lines = pem_content.lines
  b64_lines = lines.reject { |l| l.starts_with?("-----") }
  
  # Check if encrypted
  is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
  
  if is_encrypted
    raise "Private key is encrypted but no password provided" if password.nil?
    
    # Extract only the encrypted part (without BEGIN/END lines)
    encrypted_pem = lines.reject { |l| l.starts_with?("-----") }.join("\n")
    
    # Decrypt
    decrypted_der = decrypt_private_key_pem(encrypted_pem, password)
    
    # Parse decrypted DER
    parse_pkcs8_der(decrypted_der)
  else
    # Not encrypted, just parse
    b64 = b64_lines.join
    der = Base64.decode(b64)
    parse_pkcs8_der(der)
  end
end

def parse_pkcs8_der(der : Bytes) : BigInt
  idx = 0
  
  # SEQUENCE
  raise "Invalid PEM" if der[idx] != 0x30
  idx += 1
  
  # Skip length
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    idx += 1
  end
  
  # Version (INTEGER 0)
  raise "Invalid version" if der[idx] != 0x02
  idx += 1
  raise "Invalid version length" if der[idx] != 0x01
  idx += 1
  raise "Version not 0" if der[idx] != 0x00
  idx += 1
  
  # AlgorithmIdentifier (SEQUENCE)
  raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  
  # Skip AlgorithmIdentifier length and content
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    alg_len = der[idx]
    idx += 1 + alg_len
  end
  
  # PrivateKey (OCTET STRING - tag 0x04)
  raise "Expected OCTET STRING" if der[idx] != 0x04
  idx += 1
  
  priv_len = der[idx].to_i
  idx += 1
  
  if priv_len == 0x81
    priv_len = der[idx].to_i
    idx += 1
  elsif priv_len == 0x82
    priv_len = (der[idx].to_i << 8) | der[idx+1].to_i
    idx += 2
  end
  
  key_bytes = der[idx, priv_len]
  
  bytes_to_little_int(key_bytes)
end

def parse_ed521_public_key_pem(pem_content : String) : Tuple(BigInt, BigInt)
  lines = pem_content.lines
  b64_lines = lines.reject { |l| l.starts_with?("-----") }
  b64 = b64_lines.join
  der = Base64.decode(b64)
  
  idx = 0
  
  # SEQUENCE
  raise "Invalid PEM" if der[idx] != 0x30
  idx += 1
  
  # Skip SEQUENCE length
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    idx += 1
  end
  
  # AlgorithmIdentifier (SEQUENCE)
  raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  
  # Skip AlgorithmIdentifier length and content
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    alg_len = der[idx]
    idx += 1 + alg_len
  end
  
  # BIT STRING
  raise "Expected BIT STRING" if der[idx] != 0x03
  idx += 1
  
  # Skip BIT STRING length
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    idx += 1
  end
  
  unused = der[idx]
  idx += 1
  
  key_bytes = der[idx, ED521::BYTE_LEN]
  
  x, y = decompress_point(key_bytes)
  raise "Invalid public key" if x.nil? || y.nil?
  
  {x, y}
end

# ====================================================================
# X448 PEM FUNCTIONS WITH ENCRYPTION (based on Python code)
# ====================================================================

def x448_private_to_pem_pkcs8(private_key_bytes : Bytes, password : String? = nil) : String
  if private_key_bytes.size != 56
    raise ArgumentError.new("X448 private key must be 56 bytes")
  end
  
  # X448 OID: 1.3.101.111
  x448_oid = Bytes[0x06, 0x03, 0x2b, 0x65, 0x6f]  # 1.3.101.111 (X448)
  
  # PrivateKey as OCTET STRING
  inner = Bytes[0x04, 0x38] + private_key_bytes
  private_key = Bytes[0x04, inner.size.to_u8] + inner
  
  # AlgorithmIdentifier
  alg_id = Bytes[0x30, x448_oid.size.to_u8] + x448_oid
  
  # Version
  version = Bytes[0x02, 0x01, 0x00]
  
  # Total PKCS8 structure
  total_len = version.size + alg_id.size + private_key.size
  pkcs8 = Bytes[0x30, total_len.to_u8] + version + alg_id + private_key
  
  if password
    # Encrypt using RFC 1423 with Curupira-192-CBC
    encrypted_content = encrypt_private_key_pem(pkcs8, password)
    "-----BEGIN X448 PRIVATE KEY-----\n#{encrypted_content}-----END X448 PRIVATE KEY-----\n"
  else
    # Convert to PEM without encryption
    b64 = Base64.strict_encode(pkcs8)
    lines = b64.scan(/.{1,64}/).map(&.[0])
    
    String.build do |io|
      io << "-----BEGIN X448 PRIVATE KEY-----\n"
      lines.each { |line| io << line << "\n" }
      io << "-----END X448 PRIVATE KEY-----\n"
    end
  end
end

def x448_public_to_pem(public_key_bytes : Bytes) : String
  if public_key_bytes.size != 56
    raise ArgumentError.new("X448 public key must be 56 bytes")
  end
  
  # X448 OID: 1.3.101.111
  x448_oid = Bytes[0x06, 0x03, 0x2b, 0x65, 0x6f]  # 1.3.101.111 (X448)
  
  # AlgorithmIdentifier
  alg_id = Bytes[0x30, x448_oid.size.to_u8] + x448_oid
  
  # BIT STRING with public key
  bit_string = Bytes[0x03, (public_key_bytes.size + 1).to_u8, 0x00] + public_key_bytes
  
  # SubjectPublicKeyInfo
  spki = Bytes[0x30, (alg_id.size + bit_string.size).to_u8] + alg_id + bit_string
  
  # Convert to PEM
  b64 = Base64.strict_encode(spki)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  
  String.build do |io|
    io << "-----BEGIN X448 PUBLIC KEY-----\n"
    lines.each { |line| io << line << "\n" }
    io << "-----END X448 PUBLIC KEY-----\n"
  end
end

def parse_x448_private_key_pem(pem_content : String, password : String? = nil) : Bytes
  # Check if encrypted
  is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
  
  if is_encrypted
    raise "Private key is encrypted but no password provided" if password.nil?
    
    # Decrypt
    decrypted_der = decrypt_private_key_pem(pem_content, password)
    
    # Extract the last 56 bytes (the actual private key)
    if decrypted_der.size >= 56
      decrypted_der[decrypted_der.size - 56, 56]
    else
      raise ArgumentError.new("Invalid private key data")
    end
  else
    # Not encrypted, parse directly
    lines = pem_content.lines
    b64_lines = lines.reject { |l| l.starts_with?("-----") }
    b64 = b64_lines.join
    der = Base64.decode(b64)
    
    # Extract the last 56 bytes
    if der.size >= 56
      der[der.size - 56, 56]
    else
      raise ArgumentError.new("Invalid private key data")
    end
  end
end

def parse_x448_public_key_pem(pem_content : String) : Bytes
  lines = pem_content.lines
  b64_lines = lines.reject { |l| l.starts_with?("-----") }
  b64 = b64_lines.join
  der = Base64.decode(b64)
  
  # Extract the last 56 bytes
  if der.size >= 56
    der[der.size - 56, 56]
  else
    raise ArgumentError.new("Invalid public key data")
  end
end

# ====================================================================
# ORIGINAL CODE: ed521.cr (operational part)
# ====================================================================

# Extended Euclidean algorithm for modular inverse
def mod_inverse(a : BigInt, m : BigInt) : BigInt
  m0 = m
  x0 = BigInt.new(0)
  x1 = BigInt.new(1)
  
  return BigInt.new(0) if m == 1
  
  a = a % m
  while a > 1
    q = a // m
    t = m
    
    m = a % m
    a = t
    t = x0
    
    x0 = x1 - q * x0
    x1 = t
  end
  
  if x1 < 0
    x1 = x1 + m0
  end
  x1
end

# Modular exponentiation: (base ** exp) % mod
def mod_pow(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
  result = BigInt.new(1)
  b = base % mod
  e = exp
  while e > 0
    if e.odd?
      result = (result * b) % mod
    end
    b = (b * b) % mod
    e >>= 1
  end
  result
end

# ====================================================================
# E-521 Curve Parameters (Edwards)
# ====================================================================

module ED521
  P = BigInt.new("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
  N = BigInt.new("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
  D = BigInt.new(-376014)
  
  Gx = BigInt.new("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
  Gy = BigInt.new(12)
  
  H = 4
  BIT_SIZE = 521
  BYTE_LEN = 66
  
  OID_DER = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
end

# ====================================================================
# Byte conversion functions
# ====================================================================

def bytes_to_little_int(bytes : Bytes) : BigInt
  result = BigInt.new(0)
  bytes.size.times do |i|
    result |= BigInt.new(bytes[i]) << (i * 8)
  end
  result
end

def little_int_to_bytes(n : BigInt, length : Int32) : Bytes
  hex = n.to_s(16)
  hex = hex.rjust(hex.size + (hex.size.odd? ? 1 : 0), '0')
  bytes_be = Bytes.new(hex.size // 2) { |i| hex[2*i, 2].to_u8(16) }
  
  if bytes_be.size < length
    padding = Bytes.new(length - bytes_be.size, 0_u8)
    bytes_be = padding + bytes_be
  end
  
  bytes_le = Bytes.new(length, 0_u8)
  length.times { |i| bytes_le[i] = bytes_be[length - 1 - i] }
  bytes_le
end

def constant_time_eq(a : BigInt, b : BigInt) : Bool
  a_bytes = a.to_s(16).rjust(ED521::BYTE_LEN*2, '0').to_slice
  b_bytes = b.to_s(16).rjust(ED521::BYTE_LEN*2, '0').to_slice
  result = 0
  ED521::BYTE_LEN.times do |i|
    result |= a_bytes[i] ^ b_bytes[i]
  end
  result == 0
end

# ====================================================================
# SHAKE256 Implementation
# ====================================================================

module SHAKE256
  RATE = 136
  DSBYTE = 0x1F_u8
  ROUNDS = 24

  RC = [
    0x0000000000000001_u64, 0x0000000000008082_u64,
    0x800000000000808A_u64, 0x8000000080008000_u64,
    0x000000000000808B_u64, 0x0000000080000001_u64,
    0x8000000080008081_u64, 0x8000000000008009_u64,
    0x000000000000008A_u64, 0x0000000000000088_u64,
    0x0000000080008009_u64, 0x000000008000000A_u64,
    0x000000008000808B_u64, 0x800000000000008B_u64,
    0x8000000000008089_u64, 0x8000000000008003_u64,
    0x8000000000008002_u64, 0x8000000000000080_u64,
    0x000000000000800A_u64, 0x800000008000000A_u64,
    0x8000000080008081_u64, 0x8000000000008080_u64,
    0x0000000080000001_u64, 0x8000000080008008_u64,
  ]

  ROT = [
    [  0, 36,  3, 41, 18 ],
    [  1, 44, 10, 45,  2 ],
    [ 62,  6, 43, 15, 61 ],
    [ 28, 55, 25, 21, 56 ],
    [ 27, 20, 39,  8, 14 ],
  ]

  private def self.rotl(x : UInt64, n : Int32) : UInt64
    ((x << n) | (x >> (64 - n)))
  end

  private def self.keccak_f(state : Array(UInt64))
    24.times do |round|
      c = Array(UInt64).new(5) { |i|
        state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
      }
      d = Array(UInt64).new(5) { |i|
        c[(i+4)%5] ^ rotl(c[(i+1)%5], 1)
      }
      5.times do |i|
        5.times do |j|
          state[i + 5*j] ^= d[i]
        end
      end

      b = Array(UInt64).new(25, 0_u64)
      5.times do |x|
        5.times do |y|
          b[y + 5*((2*x + 3*y) % 5)] = rotl(state[x + 5*y], ROT[x][y])
        end
      end

      5.times do |x|
        5.times do |y|
          state[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
        end
      end

      state[0] ^= RC[round]
    end
  end

  def self.shake256(data : Bytes, output_len : Int32) : Bytes
    state = Array(UInt64).new(25, 0_u64)

    offset = 0
    data_size = data.size
    
    while offset + RATE <= data_size
      block = data[offset, RATE]
      RATE.times do |i|
        state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
      end
      keccak_f(state)
      offset += RATE
    end

    block = Bytes.new(RATE, 0_u8)
    remaining = data_size - offset
    remaining.times { |i| block[i] = data[offset + i] }
    block[remaining] ^= DSBYTE
    block[RATE - 1] ^= 0x80

    RATE.times do |i|
      state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
    end
    keccak_f(state)

    output = Bytes.new(output_len, 0_u8)
    extracted = 0
    
    while extracted < output_len
      i = 0
      while i < RATE && extracted < output_len
        lane = i // 8
        shift = 8 * (i % 8)
        output[extracted] = ((state[lane] >> shift) & 0xFF).to_u8
        extracted += 1
        i += 1
      end
      
      if extracted < output_len
        keccak_f(state)
      end
    end

    output
  end
end

# ====================================================================
# E-521 Elliptic Curve Functions
# ====================================================================

module ED521Curve
  def self.on_curve?(x : BigInt, y : BigInt) : Bool
    x2 = (x * x) % ED521::P
    y2 = (y * y) % ED521::P
    left = (x2 + y2) % ED521::P
    
    d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
    right = (1 + (d_pos * x2 * y2) % ED521::P) % ED521::P
    
    left == right
  end
  
  def self.add(x1 : BigInt, y1 : BigInt, x2 : BigInt, y2 : BigInt) : Tuple(BigInt, BigInt)
    if x1 == 0 && y1 == 1
      return {x2, y2}
    end
    if x2 == 0 && y2 == 1
      return {x1, y1}
    end
    
    x1y2 = (x1 * y2) % ED521::P
    y1x2 = (y1 * x2) % ED521::P
    numerator_x = (x1y2 + y1x2) % ED521::P
    
    y1y2 = (y1 * y2) % ED521::P
    x1x2 = (x1 * x2) % ED521::P
    numerator_y = (y1y2 - x1x2) % ED521::P
    numerator_y = (numerator_y + ED521::P) % ED521::P if numerator_y < 0
    
    d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
    dx1x2y1y2 = (d_pos * ((x1x2 * y1y2) % ED521::P)) % ED521::P
    
    denominator_x = (1 + dx1x2y1y2) % ED521::P
    denominator_y = (1 - dx1x2y1y2) % ED521::P
    denominator_y = (denominator_y + ED521::P) % ED521::P if denominator_y < 0
    
    inv_den_x = mod_inverse(denominator_x, ED521::P)
    inv_den_y = mod_inverse(denominator_y, ED521::P)
    
    x3 = (numerator_x * inv_den_x) % ED521::P
    y3 = (numerator_y * inv_den_y) % ED521::P
    
    {x3, y3}
  end
  
  def self.double(x : BigInt, y : BigInt) : Tuple(BigInt, BigInt)
    add(x, y, x, y)
  end
  
  def self.scalar_mult(x : BigInt, y : BigInt, k_bytes : Bytes) : Tuple(BigInt, BigInt)
    scalar = bytes_to_little_int(k_bytes) % ED521::N
    
    result_x = BigInt.new(0)
    result_y = BigInt.new(1)
    temp_x = x
    temp_y = y
    
    while scalar > 0
      if scalar.odd?
        result_x, result_y = add(result_x, result_y, temp_x, temp_y)
      end
      temp_x, temp_y = double(temp_x, temp_y)
      scalar >>= 1
    end
    
    {result_x, result_y}
  end
  
  def self.scalar_base_mult(k_bytes : Bytes) : Tuple(BigInt, BigInt)
    scalar_mult(ED521::Gx, ED521::Gy, k_bytes)
  end
end

# ====================================================================
# Point Compression/Decompression
# ====================================================================

def compress_point(x : BigInt, y : BigInt) : Bytes
  y_bytes = little_int_to_bytes(y, ED521::BYTE_LEN)
  x_lsb = (x & 1).to_u8
  y_bytes[ED521::BYTE_LEN - 1] |= (x_lsb << 7)
  y_bytes
end

def decompress_point(data : Bytes) : Tuple(BigInt?, BigInt?)
  return {nil, nil} if data.size != ED521::BYTE_LEN
  
  last_byte = data[ED521::BYTE_LEN - 1]
  sign_bit = (last_byte >> 7) & 1
  
  y_bytes = data.dup
  y_bytes[ED521::BYTE_LEN - 1] = last_byte & 0x7F
  y = bytes_to_little_int(y_bytes)
  
  return {nil, nil} if y >= ED521::P
  
  y2 = (y * y) % ED521::P
  
  numerator = (1 - y2) % ED521::P
  numerator = (numerator + ED521::P) % ED521::P if numerator < 0
  
  d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
  denominator = (1 - (d_pos * y2) % ED521::P) % ED521::P
  denominator = (denominator + ED521::P) % ED521::P if denominator < 0
  
  inv_den = mod_inverse(denominator, ED521::P)
  return {nil, nil} if inv_den == 0
  
  x2 = (numerator * inv_den) % ED521::P
  
  exp = (ED521::P + 1) // 4
  x = mod_pow(x2, exp, ED521::P)
  
  x2_check = (x * x) % ED521::P
  if x2_check != x2
    x = (-x) % ED521::P
    x2_check = (x * x) % ED521::P
    return {nil, nil} if x2_check != x2
  end
  
  x_lsb = (x & 1).to_u8
  if x_lsb != sign_bit
    x = (-x) % ED521::P
  end
  
  return {nil, nil} unless ED521Curve.on_curve?(x, y)
  
  {x, y}
end

# ====================================================================
# Hash Functions
# ====================================================================

def dom5(phflag : UInt8, context : Bytes) : Bytes
  raise "context too long for dom5" if context.size > 255
  
  prefix = "SigEd521".to_slice
  len_byte = Bytes[context.size.to_u8]
  
  prefix + Bytes[phflag] + len_byte + context
end

def hash_e521(phflag : UInt8, context : Bytes, x : Bytes) : Bytes
  dom = dom5(phflag, context)
  input = dom + x
  SHAKE256.shake256(input, 132)
end

# ====================================================================
# ED521 Key Generation
# ====================================================================

def generate_private_key : BigInt
  loop do
    priv_bytes = Random::Secure.random_bytes(ED521::BYTE_LEN)
    a = bytes_to_little_int(priv_bytes)
    return a if a < ED521::N
  end
end

def get_public_key(private_key : BigInt) : Tuple(BigInt, BigInt)
  priv_bytes = little_int_to_bytes(private_key, ED521::BYTE_LEN)
  ED521Curve.scalar_base_mult(priv_bytes)
end

# ====================================================================
# EdDSA Signature
# ====================================================================

def sign(private_key : BigInt, message : Bytes) : Bytes
  byte_len = ED521::BYTE_LEN
  
  prefix = hash_e521(0x00_u8, Bytes.empty, little_int_to_bytes(private_key, byte_len))
  
  r_bytes = hash_e521(0x00_u8, Bytes.empty, prefix + message)
  r = bytes_to_little_int(r_bytes[0, byte_len]) % ED521::N
  
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_compressed = compress_point(rx, ry)
  
  pub_x, pub_y = get_public_key(private_key)
  a_compressed = compress_point(pub_x, pub_y)
  
  hram_input = r_compressed + a_compressed + message
  hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
  h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521::N
  
  s = (r + (h * private_key) % ED521::N) % ED521::N
  
  s_bytes = little_int_to_bytes(s, byte_len)
  r_compressed + s_bytes
end

def verify(public_x : BigInt, public_y : BigInt, message : Bytes, signature : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  
  return false if signature.size != 2 * byte_len
  
  r_compressed = signature[0, byte_len]
  s_bytes = signature[byte_len, byte_len]
  
  rx, ry = decompress_point(r_compressed)
  return false if rx.nil? || ry.nil?
  
  s = bytes_to_little_int(s_bytes)
  return false if s >= ED521::N
  
  a_compressed = compress_point(public_x, public_y)
  
  hram_input = r_compressed + a_compressed + message
  hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
  h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521::N
  
  sg_x, sg_y = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  
  ha_x, ha_y = ED521Curve.scalar_mult(public_x, public_y, little_int_to_bytes(h, byte_len))
  
  rha_x, rha_y = ED521Curve.add(rx, ry, ha_x, ha_y)
  
  constant_time_eq(sg_x, rha_x) && constant_time_eq(sg_y, rha_y)
end

# ====================================================================
# Knowledge Proof (ZKP) - Add after signature functions
# ====================================================================

# Generates ZKP proof of private key knowledge
def prove_knowledge(private_key : BigInt) : Bytes
  byte_len = ED521::BYTE_LEN
  
  # Generate random r
  r = loop do
    r_bytes = Random::Secure.random_bytes(byte_len)
    r_val = bytes_to_little_int(r_bytes)
    break r_val if r_val < ED521::N
  end
  
  # Commitment R = r*G
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_comp = compress_point(rx, ry)
  
  # Public key A
  pub_x, pub_y = get_public_key(private_key)
  a_comp = compress_point(pub_x, pub_y)
  
  # Challenge c = H(R || A) (Fiat-Shamir)
  input_data = r_comp + a_comp
  c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N
  
  # Response s = r + c*a (mod N)
  s = (r + (c * private_key) % ED521::N) % ED521::N
  
  # Proof = R || s
  s_bytes = little_int_to_bytes(s, byte_len)
  r_comp + s_bytes
end

# Verifies ZKP proof
def verify_knowledge(public_x : BigInt, public_y : BigInt, proof : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  
  return false if proof.size != 2 * byte_len
  
  r_comp = proof[0, byte_len]
  s_bytes = proof[byte_len, byte_len]
  
  # Decompress R
  rx, ry = decompress_point(r_comp)
  return false if rx.nil? || ry.nil?
  
  s = bytes_to_little_int(s_bytes)
  
  # Recalculate c = H(R || A)
  a_comp = compress_point(public_x, public_y)
  input_data = r_comp + a_comp
  c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N
  
  # Verify s*G == R + c*A
  sg_x, sg_y = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  ca_x, ca_y = ED521Curve.scalar_mult(public_x, public_y, little_int_to_bytes(c, byte_len))
  rca_x, rca_y = ED521Curve.add(rx, ry, ca_x, ca_y)
  
  constant_time_eq(sg_x, rca_x) && constant_time_eq(sg_y, rca_y)
end

# ====================================================================
# X448 Implementation
# ====================================================================

P_X448 = (BigInt.new(1) << 448) - (BigInt.new(1) << 224) - 1
A_X448 = BigInt.new(156326)
A24_X448 = BigInt.new(39081)

X448_BASE_POINT = Bytes[
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0
]

def modp_add(a : BigInt, b : BigInt) : BigInt
  (a + b) % P_X448
end

def modp_sub(a : BigInt, b : BigInt) : BigInt
  (a - b) % P_X448
end

def modp_mul(a : BigInt, b : BigInt) : BigInt
  (a * b) % P_X448
end

def modp_sqr(a : BigInt) : BigInt
  (a * a) % P_X448
end

def modp_inv(a : BigInt) : BigInt
  exp = P_X448 - 2
  result = BigInt.new(1)
  base = a % P_X448
  
  while exp > 0
    if exp.odd?
      result = (result * base) % P_X448
    end
    base = (base * base) % P_X448
    exp >>= 1
  end
  
  result
end

def clamp_scalar_go(scalar : Bytes) : Bytes
  raise ArgumentError.new("Scalar must be 56 bytes") if scalar.size != 56
  
  clamped = scalar.dup
  clamped[0] &= 0xFC_u8
  clamped[55] |= 0x80_u8
  clamped
end

def x448_scalar_mult(scalar : Bytes, point : Bytes) : Bytes
  raise ArgumentError.new("Inputs must be 56 bytes") if scalar.size != 56 || point.size != 56
  
  k = clamp_scalar_go(scalar)
  
  k_int = BigInt.new(0)
  56.times do |i|
    k_int |= BigInt.new(k[i]) << (i * 8)
  end
  
  u_int = BigInt.new(0)
  56.times do |i|
    u_int |= BigInt.new(point[i]) << (i * 8)
  end
  
  x1 = u_int % P_X448
  x2 = BigInt.new(1)
  z2 = BigInt.new(0)
  x3 = u_int % P_X448
  z3 = BigInt.new(1)
  swap = 0
  
  448.times do |i|
    t = 447 - i
    k_t = ((k_int >> t) & 1).to_i
    swap ^= k_t
    
    if swap == 1
      x2, x3 = x3, x2
      z2, z3 = z3, z2
    end
    swap = k_t
    
    a = modp_add(x2, z2)
    aa = modp_sqr(a)
    b = modp_sub(x2, z2)
    bb = modp_sqr(b)
    e = modp_sub(aa, bb)
    c = modp_add(x3, z3)
    d = modp_sub(x3, z3)
    da = modp_mul(d, a)
    cb = modp_mul(c, b)
    
    x3 = modp_sqr(modp_add(da, cb))
    z3 = modp_mul(modp_sqr(modp_sub(da, cb)), x1)
    x2 = modp_mul(aa, bb)
    z2 = modp_mul(modp_add(modp_mul(e, A24_X448), aa), e)
  end
  
  if swap == 1
    x2, x3 = x3, x2
    z2, z3 = z3, z2
  end
  
  raise ArgumentError.new("x448 bad input point") if z2 == 0
  
  result = modp_mul(x2, modp_inv(z2))
  
  bytes = Bytes.new(56, 0)
  56.times do |i|
    bytes[i] = ((result >> (i * 8)) & 0xFF).to_u8
  end
  
  bytes
end

def x448_base_point_mult(scalar : Bytes) : Bytes
  x448_scalar_mult(scalar, X448_BASE_POINT)
end

def x448_generate_private_key : Bytes
  private_bytes = Bytes.new(56)
  Random::Secure.random_bytes(private_bytes)
  clamp_scalar_go(private_bytes)
end

def x448_get_public_key(private_key : Bytes) : Bytes
  x448_base_point_mult(private_key)
end

def x448_shared_secret(private_key : Bytes, peer_public_key : Bytes) : Bytes
  x448_scalar_mult(private_key, peer_public_key)
end

# ====================================================================
# Curupira1 Implementation
# ====================================================================

module Curupira1
  BLOCK_SIZE = 12

  class InvalidKeyError < Exception
    def initialize
      super("curupira1: invalid key length (must be 12, 18, or 24 bytes)")
    end
  end

  S_BOX_TABLE = [
    0xba, 0x54, 0x2f, 0x74, 0x53, 0xd3, 0xd2, 0x4d,
    0x50, 0xac, 0x8d, 0xbf, 0x70, 0x52, 0x9a, 0x4c,
    0xea, 0xd5, 0x97, 0xd1, 0x33, 0x51, 0x5b, 0xa6,
    0xde, 0x48, 0xa8, 0x99, 0xdb, 0x32, 0xb7, 0xfc,
    0xe3, 0x9e, 0x91, 0x9b, 0xe2, 0xbb, 0x41, 0x6e,
    0xa5, 0xcb, 0x6b, 0x95, 0xa1, 0xf3, 0xb1, 0x02,
    0xcc, 0xc4, 0x1d, 0x14, 0xc3, 0x63, 0xda, 0x5d,
    0x5f, 0xdc, 0x7d, 0xcd, 0x7f, 0x5a, 0x6c, 0x5c,
    0xf7, 0x26, 0xff, 0xed, 0xe8, 0x9d, 0x6f, 0x8e,
    0x19, 0xa0, 0xf0, 0x89, 0x0f, 0x07, 0xaf, 0xfb,
    0x08, 0x15, 0x0d, 0x04, 0x01, 0x64, 0xdf, 0x76,
    0x79, 0xdd, 0x3d, 0x16, 0x3f, 0x37, 0x6d, 0x38,
    0xb9, 0x73, 0xe9, 0x35, 0x55, 0x71, 0x7b, 0x8c,
    0x72, 0x88, 0xf6, 0x2a, 0x3e, 0x5e, 0x27, 0x46,
    0x0c, 0x65, 0x68, 0x61, 0x03, 0xc1, 0x57, 0xd6,
    0xd9, 0x58, 0xd8, 0x66, 0xd7, 0x3a, 0xc8, 0x3c,
    0xfa, 0x96, 0xa7, 0x98, 0xec, 0xb8, 0xc7, 0xae,
    0x69, 0x4b, 0xab, 0xa9, 0x67, 0x0a, 0x47, 0xf2,
    0xb5, 0x22, 0xe5, 0xee, 0xbe, 0x2b, 0x81, 0x12,
    0x83, 0x1b, 0x0e, 0x23, 0xf5, 0x45, 0x21, 0xce,
    0x49, 0x2c, 0xf9, 0xe6, 0xb6, 0x28, 0x17, 0x82,
    0x1a, 0x8b, 0xfe, 0x8a, 0x09, 0xc9, 0x87, 0x4e,
    0xe1, 0x2e, 0xe4, 0xe0, 0xeb, 0x90, 0xa4, 0x1e,
    0x85, 0x60, 0x00, 0x25, 0xf4, 0xf1, 0x94, 0x0b,
    0xe7, 0x75, 0xef, 0x34, 0x31, 0xd4, 0xd0, 0x86,
    0x7e, 0xad, 0xfd, 0x29, 0x30, 0x3b, 0x9f, 0xf8,
    0xc6, 0x13, 0x06, 0x05, 0xc5, 0x11, 0x77, 0x7c,
    0x7a, 0x78, 0x36, 0x1c, 0x39, 0x59, 0x18, 0x56,
    0xb3, 0xb0, 0x24, 0x20, 0xb2, 0x92, 0xa3, 0xc0,
    0x44, 0x62, 0x10, 0xb4, 0x84, 0x43, 0x93, 0xc2,
    0x4a, 0xbd, 0x8f, 0x2d, 0xbc, 0x9c, 0x6a, 0x40,
    0xcf, 0xa2, 0x80, 0x4f, 0x1f, 0xca, 0xaa, 0x42,
  ].map(&.to_u8)

  X_TIMES_TABLE = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
    0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE,
    0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
    0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
    0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
    0x4D, 0x4F, 0x49, 0x4B, 0x45, 0x47, 0x41, 0x43,
    0x5D, 0x5F, 0x59, 0x5B, 0x55, 0x57, 0x51, 0x53,
    0x6D, 0x6F, 0x69, 0x6B, 0x65, 0x67, 0x61, 0x63,
    0x7D, 0x7F, 0x79, 0x7B, 0x75, 0x77, 0x71, 0x73,
    0x0D, 0x0F, 0x09, 0x0B, 0x05, 0x07, 0x01, 0x03,
    0x1D, 0x1F, 0x19, 0x1B, 0x15, 0x17, 0x11, 0x13,
    0x2D, 0x2F, 0x29, 0x2B, 0x25, 0x27, 0x21, 0x23,
    0x3D, 0x3F, 0x39, 0x3B, 0x35, 0x37, 0x31, 0x33,
    0xCD, 0xCF, 0xC9, 0xCB, 0xC5, 0xC7, 0xC1, 0xC3,
    0xDD, 0xDF, 0xD9, 0xDB, 0xD5, 0xD7, 0xD1, 0xD3,
    0xED, 0xEF, 0xE9, 0xEB, 0xE5, 0xE7, 0xE1, 0xE3,
    0xFD, 0xFF, 0xF9, 0xFB, 0xF5, 0xF7, 0xF1, 0xF3,
    0x8D, 0x8F, 0x89, 0x8B, 0x85, 0x87, 0x81, 0x83,
    0x9D, 0x9F, 0x99, 0x9B, 0x95, 0x97, 0x91, 0x93,
    0xAD, 0xAF, 0xA9, 0xAB, 0xA5, 0xA7, 0xA1, 0xA3,
    0xBD, 0xBF, 0xB9, 0xBB, 0xB5, 0xB7, 0xB1, 0xB3,
  ].map(&.to_u8)

  def self.s_box(v : UInt8) : UInt8
    S_BOX_TABLE[v]
  end

  def self.x_times(v : UInt8) : UInt8
    X_TIMES_TABLE[v]
  end

  class Cipher
    getter block_size : Int32
    getter key_bits : Int32
    getter rounds : Int32
    getter t : Int32
    getter encryption_round_keys : Array(Bytes)
    getter decryption_round_keys : Array(Bytes)

    def initialize(key : Bytes)
      @block_size = BLOCK_SIZE
      
      if key.size != 12 && key.size != 18 && key.size != 24
        raise InvalidKeyError.new
      end

      @key_bits = key.size * 8
      
      @rounds = case key.size
                when 12 then 10
                when 18 then 14
                else        18
                end
      
      @t = @key_bits // 48
      
      @encryption_round_keys = Array(Bytes).new(@rounds + 1)
      @decryption_round_keys = Array(Bytes).new(@rounds + 1)
      
      expand_key(key)
    end

    def encrypt(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      process_block(dst, src, @encryption_round_keys)
    end

    def decrypt(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      process_block(dst, src, @decryption_round_keys)
    end

    def sct(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      tmp = perform_unkeyed_round(src)
      3.times do
        tmp = perform_unkeyed_round(tmp)
      end

      tmp.copy_to(dst)
    end

    private def process_block(dst : Bytes, src : Bytes, round_keys : Array(Bytes)) : Nil
      block = src.dup

      block = perform_whitening_round(block, round_keys[0])

      (1...@rounds).each do |r|
        block = perform_round(block, round_keys[r])
      end

      block = perform_last_round(block, round_keys[@rounds])

      block.copy_to(dst)
    end

    private def expand_key(key : Bytes) : Nil
      kr = key.dup
      krk = select_round_key(kr)
      @encryption_round_keys << krk

      (1..@rounds).each do |r|
        kr = calculate_next_subkey(kr, r)
        krk = select_round_key(kr)
        @encryption_round_keys << krk
      end

      (0..@rounds).each do |r|
        @decryption_round_keys << Bytes.new(@block_size, 0)
      end

      @decryption_round_keys[0] = @encryption_round_keys[@rounds].dup
      @decryption_round_keys[@rounds] = @encryption_round_keys[0].dup

      (1...@rounds).each do |r|
        @decryption_round_keys[r] = apply_linear_diffusion_layer(@encryption_round_keys[@rounds - r])
      end
    end

    private def calculate_next_subkey(kr : Bytes, subkey_rank : Int32) : Bytes
      result = apply_linear_diffusion(
        apply_cyclic_shift(
          apply_constant_addition(kr, subkey_rank),
          @t
        ),
        @t
      )
      
      Bytes.new(result.size).tap do |bytes|
        result.each_with_index { |v, i| bytes[i] = v }
      end
    end

    private def apply_constant_addition(kr : Bytes, subkey_rank : Int32) : Array(UInt8)
      q = calculate_schedule_constant(subkey_rank)
      result = Array(UInt8).new(3 * 2 * @t, 0_u8)
      
      (0...3).each do |i|
        (0...(2 * @t)).each do |j|
          result[i + 3*j] = (kr[i + 3*j] ^ q[i + 3*j]).to_u8
        end
      end
      
      result
    end

    private def calculate_schedule_constant(s : Int32) : Array(UInt8)
      size = 3 * 2 * @t
      q = Array(UInt8).new(size, 0_u8)

      if s == 0
        return q
      end

      (0...(2 * @t)).each do |j|
        q[3*j] = Curupira1.s_box((2 * @t * (s - 1) + j).to_u8!)
      end

      q
    end

    private def apply_cyclic_shift(a : Array(UInt8), t : Int32) : Array(UInt8)
      size = 3 * 2 * t
      b = Array(UInt8).new(size, 0_u8)

      (0...(2 * t)).each do |j|
        b[3*j] = a[3*j]
        b[1 + 3*j] = a[1 + 3 * ((j + 1) % (2 * t))]
        
        if j > 0
          b[2 + 3*j] = a[2 + 3 * ((j - 1) % (2 * t))]
        else
          b[2] = a[2 + 3 * (2 * t - 1)]
        end
      end

      b
    end

    private def apply_linear_diffusion(a : Array(UInt8), t : Int32) : Array(UInt8)
      size = 3 * 2 * t
      b = Array(UInt8).new(size, 0_u8)

      (0...(2 * t)).each do |j|
        e_times_a(a, j, b, true)
      end

      b
    end

    private def select_round_key(kr : Bytes) : Bytes
      result = Bytes.new(12, 0_u8)

      (0...4).each do |j|
        result[3*j] = Curupira1.s_box(kr[3*j])
      end

      (1...3).each do |i|
        (0...4).each do |j|
          result[i + 3*j] = kr[i + 3*j]
        end
      end

      result
    end

    private def apply_non_linear_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        12.times { |i| b[i] = Curupira1.s_box(a[i]) }
      end
    end

    private def apply_permutation_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...3).each do |i|
          (0...4).each do |j|
            b[i + 3*j] = a[i + 3*(i ^ j)]
          end
        end
      end
    end

    private def apply_linear_diffusion_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...4).each do |j|
          d_times_a(a, j, b)
        end
      end
    end

    private def apply_key_addition(a : Bytes, kr : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...3).each do |i|
          (0...4).each do |j|
            b[i + 3*j] = (a[i + 3*j] ^ kr[i + 3*j]).to_u8
          end
        end
      end
    end

    private def perform_whitening_round(a : Bytes, k0 : Bytes) : Bytes
      apply_key_addition(a, k0)
    end

    private def perform_last_round(a : Bytes, kr : Bytes) : Bytes
      apply_key_addition(
        apply_permutation_layer(
          apply_non_linear_layer(a)
        ),
        kr
      )
    end

    private def perform_round(a : Bytes, kr : Bytes) : Bytes
      apply_key_addition(
        apply_linear_diffusion_layer(
          apply_permutation_layer(
            apply_non_linear_layer(a)
          )
        ),
        kr
      )
    end

    private def perform_unkeyed_round(a : Bytes) : Bytes
      apply_linear_diffusion_layer(
        apply_permutation_layer(
          apply_non_linear_layer(a)
        )
      )
    end

    private def d_times_a(a : Bytes, j : Int32, b : Bytes) : Nil
      d = 3 * j
      v = Curupira1.x_times((a[0 + d] ^ a[1 + d] ^ a[2 + d]).to_u8)
      w = Curupira1.x_times(v)

      b[0 + d] = (a[0 + d] ^ v).to_u8
      b[1 + d] = (a[1 + d] ^ w).to_u8
      b[2 + d] = (a[2 + d] ^ v ^ w).to_u8
    end

    private def e_times_a(a : Array(UInt8) | Bytes, j : Int32, b : Array(UInt8), e : Bool) : Nil
      d = 3 * j
      v = (a[0 + d] ^ a[1 + d] ^ a[2 + d]).to_u8

      if e
        v = c_times(v)
      else
        v = (c_times(v) ^ v).to_u8
      end

      b[0 + d] = (a[0 + d] ^ v).to_u8
      b[1 + d] = (a[1 + d] ^ v).to_u8
      b[2 + d] = (a[2 + d] ^ v).to_u8
    end

    private def c_times(u : UInt8) : UInt8
      Curupira1.x_times(
        Curupira1.x_times(
          Curupira1.x_times(
            Curupira1.x_times(u) ^ u
          ) ^ u
        )
      )
    end
  end

  C = 0x2A_u8

  class Marvin
    @buffer : Bytes
    @r : Bytes
    @o : Bytes
    @m_length : Int32 = 0
    @letter_soup_mode : Bool

    getter cipher : Cipher
    getter block_bytes : Int32

    def initialize(@cipher, r : Bytes? = nil, @letter_soup_mode = false)
      @block_bytes = @cipher.block_size
      @buffer = Bytes.new(@block_bytes, 0)
      @r = Bytes.new(@block_bytes, 0)
      @o = Bytes.new(@block_bytes, 0)

      if r
        init_with_r(r)
      else
        init
      end
    end

    def init : Nil
      left_padded_c = Bytes.new(@block_bytes, 0)
      left_padded_c[@block_bytes - 1] = C

      encrypted = Bytes.new(@block_bytes)
      @cipher.encrypt(encrypted, left_padded_c)

      @r = encrypted.dup
      xor_in_place(@r, left_padded_c)
      @o = @r.dup
    end

    def init_with_r(r : Bytes) : Nil
      len = Math.min(r.size, @block_bytes)
      @r[0, len].copy_from(r[0, len])
      @o.copy_from(@r)
    end

    def update(a_data : Bytes) : Nil
      a_length = a_data.size
      block_bytes = @block_bytes

      m = Bytes.new(block_bytes, 0)
      a = Bytes.new(block_bytes, 0)

      q = a_length // block_bytes
      r = a_length % block_bytes

      xor_in_place(@buffer, @r)

      q.times do |i|
        m.copy_from(a_data[i * block_bytes, block_bytes])
        update_offset
        xor_in_place(m, @o)
        @cipher.sct(a, m)
        xor_in_place(@buffer, a)
      end

      if r != 0
        m.fill(0)
        m[0, r].copy_from(a_data[q * block_bytes, r])
        update_offset
        xor_in_place(m, @o)
        @cipher.sct(a, m)
        xor_in_place(@buffer, a)
      end

      @m_length = a_length
    end

    def get_tag(tag : Bytes? = nil, tag_bits : Int32 = 96) : Bytes
      tag_bytes = tag_bits // 8
      result = tag || Bytes.new(tag_bytes, 0)
      block_bytes = @block_bytes

      if @letter_soup_mode
        copy_bytes = Math.min(tag_bytes, block_bytes)
        result[0, copy_bytes].copy_from(@buffer[0, copy_bytes])
        return result
      end

      a = Bytes.new(block_bytes, 0)
      encrypted_a = Bytes.new(block_bytes, 0)
      aux_value1 = Bytes.new(block_bytes, 0)
      aux_value2 = Bytes.new(block_bytes, 0)

      diff = @cipher.block_size * 8 - tag_bits

      if diff == 0
        aux_value1[0] = 0x80_u8
        aux_value1[1] = 0x00_u8
      elsif diff < 0
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x80_u8
      else
        diff = (diff << 1) | 0x01
        while diff > 0 && (diff & 0x80) == 0
          diff = (diff << 1) & 0xFF
        end
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x00_u8
      end

      4.times do |i|
        aux_value2[block_bytes - i - 1] = ((@m_length * 8) >> (8 * i)).to_u8! & 0xFF
      end

      a.copy_from(@buffer)
      xor_in_place(a, aux_value1)
      xor_in_place(a, aux_value2)

      @cipher.encrypt(encrypted_a, a)

      result[0, tag_bytes].copy_from(encrypted_a[0, tag_bytes])
      result
    end

    private def update_offset : Nil
      o0 = @o[0]

      (0...11).each do |i|
        @o[i] = @o[i + 1]
      end

      @o[9] = (@o[9] ^ o0 ^ (o0 >> 3) ^ (o0 >> 5)).to_u8!
      @o[10] = (@o[10] ^ ((o0 << 5) & 0xFF) ^ ((o0 << 3) & 0xFF)).to_u8!
      @o[11] = o0
    end

    private def xor_in_place(a : Bytes, b : Bytes) : Nil
      len = Math.min(a.size, b.size)
      len.times do |i|
        a[i] ^= b[i]
      end
    end
  end

  class LetterSoup
    @cipher : Cipher
    @mac : Marvin
    @block_bytes : Int32
    @m_length : Int32 = 0
    @h_length : Int32 = 0
    @iv : Bytes = Bytes.empty
    @a : Bytes = Bytes.empty
    @d : Bytes = Bytes.empty
    @r : Bytes = Bytes.empty
    @l : Bytes = Bytes.empty

    def initialize(@cipher)
      @block_bytes = @cipher.block_size
      @mac = Marvin.new(@cipher, nil, true)
    end

    def set_iv(iv : Bytes) : Nil
      iv_length = iv.size
      block_bytes = @block_bytes

      @iv = iv.dup
      @l = Bytes.empty

      @r = Bytes.new(block_bytes, 0)
      left_padded_n = Bytes.new(block_bytes, 0)

      start_idx = block_bytes - iv_length
      start_idx = 0 if start_idx < 0
      copy_len = Math.min(iv_length, block_bytes)
      
      left_padded_n[start_idx, copy_len].copy_from(iv[0, copy_len])

      encrypted = Bytes.new(block_bytes)
      @cipher.encrypt(encrypted, left_padded_n)

      @r = encrypted.dup
      xor_in_place(@r, left_padded_n)
    end

    def update(a_data : Bytes) : Nil
      a_length = a_data.size
      block_bytes = @block_bytes

      @l = Bytes.new(block_bytes, 0)
      @d = Bytes.new(block_bytes, 0)

      empty = Bytes.new(block_bytes, 0)

      @h_length = a_length
      @cipher.encrypt(@l, empty)

      mac = Marvin.new(@cipher, @l, true)
      mac.update(a_data)
      @d = mac.get_tag(nil, @cipher.block_size * 8)
    end

    def encrypt(dst : Bytes, src : Bytes) : Nil
      m_length = src.size
      block_bytes = @block_bytes

      @a = Bytes.new(block_bytes, 0)
      @m_length = m_length

      lfsrc(src, dst)

      mac = Marvin.new(@cipher, @r, true)
      mac.update(dst[0, m_length])
      @a = mac.get_tag(nil, @cipher.block_size * 8)
    end

    def decrypt(dst : Bytes, src : Bytes) : Nil
      lfsrc(src, dst)
    end

    def get_tag(tag : Bytes? = nil, tag_bits : Int32 = 96) : Bytes
      tag_bytes = tag_bits // 8
      result = tag || Bytes.new(tag_bytes, 0)
      block_bytes = @block_bytes

      atemp = Bytes.new(block_bytes, 0)
      copy_len = Math.min(@a.size, block_bytes)
      atemp[0, copy_len].copy_from(@a[0, copy_len])

      aux_value1 = Bytes.new(block_bytes, 0)
      aux_value2 = Bytes.new(block_bytes, 0)

      diff = @cipher.block_size * 8 - tag_bits

      if diff == 0
        aux_value1[0] = 0x80_u8
        aux_value1[1] = 0x00_u8
      elsif diff < 0
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x80_u8
      else
        diff = (diff << 1) | 0x01
        while diff > 0 && (diff & 0x80) == 0
          diff = (diff << 1) & 0xFF
        end
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x00_u8
      end

      4.times do |i|
        aux_value2[block_bytes - i - 1] = ((@m_length * 8) >> (8 * i)).to_u8! & 0xFF
      end

      xor_in_place(atemp, aux_value1)
      xor_in_place(atemp, aux_value2)

      if !@l.empty?
        aux_value2_h = Bytes.new(block_bytes, 0)
        4.times do |i|
          aux_value2_h[block_bytes - i - 1] = ((@h_length * 8) >> (8 * i)).to_u8! & 0xFF
        end

        dtemp = Bytes.new(block_bytes, 0)
        copy_len = Math.min(@d.size, block_bytes)
        dtemp[0, copy_len].copy_from(@d[0, copy_len])

        xor_in_place(dtemp, aux_value1)
        xor_in_place(dtemp, aux_value2_h)

        sct_result = Bytes.new(block_bytes)
        @cipher.sct(sct_result, dtemp)

        xor_in_place(atemp, sct_result)
      end

      encrypted = Bytes.new(block_bytes)
      @cipher.encrypt(encrypted, atemp)

      result[0, tag_bytes].copy_from(encrypted[0, tag_bytes])
      result
    end

    private def lfsrc(m_data : Bytes, c_data : Bytes) : Nil
      m_length = m_data.size
      block_bytes = @block_bytes

      m = Bytes.new(block_bytes, 0)
      c = Bytes.new(block_bytes, 0)
      o = @r.dup

      q = m_length // block_bytes
      r = m_length % block_bytes

      q.times do |i|
        m.copy_from(m_data[i * block_bytes, block_bytes])
        update_offset(o)
        @cipher.encrypt(c, o)
        xor_in_place(c, m)
        c_data[i * block_bytes, block_bytes].copy_from(c)
      end

      if r != 0
        m.fill(0)
        m[0, r].copy_from(m_data[q * block_bytes, r])
        update_offset(o)
        @cipher.encrypt(c, o)
        xor_in_place(c, m)
        c_data[q * block_bytes, r].copy_from(c[0, r])
      end
    end

    private def update_offset(o : Bytes) : Nil
      o0 = o[0]

      (0...11).each do |i|
        o[i] = o[i + 1]
      end

      o[9] = (o[9] ^ o0 ^ (o0 >> 3) ^ (o0 >> 5)).to_u8!
      o[10] = (o[10] ^ ((o0 << 5) & 0xFF) ^ ((o0 << 3) & 0xFF)).to_u8!
      o[11] = o0
    end

    private def xor_in_place(a : Bytes, b : Bytes) : Nil
      len = Math.min(a.size, b.size)
      len.times do |i|
        a[i] ^= b[i]
      end
    end
  end

  class CBC
    @cipher : Cipher
    @iv : Bytes

    def initialize(@cipher, @iv)
      raise "IV must be #{@cipher.block_size} bytes" if @iv.size != @cipher.block_size
    end

    def encrypt(data : Bytes) : Bytes
      block_size = @cipher.block_size
      
      padding_len = block_size - (data.size % block_size)
      padding_len = block_size if padding_len == 0
      
      padded = Bytes.new(data.size + padding_len)
      data.size.times { |i| padded[i] = data[i] }
      (data.size...padded.size).each { |i| padded[i] = padding_len.to_u8 }
      
      result = Bytes.new(padded.size)
      prev = @iv.dup
      
      (0...padded.size).step(block_size) do |i|
        block = padded[i, block_size]
        
        xored = xor_bytes(block, prev)
        
        encrypted = Bytes.new(block_size)
        @cipher.encrypt(encrypted, xored)
        
        encrypted.size.times { |j| result[i + j] = encrypted[j] }
        
        prev = encrypted
      end
      
      result
    end

    def decrypt(data : Bytes) : Bytes
      block_size = @cipher.block_size
      
      raise "Data size must be multiple of block size" if data.size % block_size != 0
      
      result = Bytes.new(data.size)
      prev = @iv.dup
      
      (0...data.size).step(block_size) do |i|
        block = data[i, block_size]
        
        decrypted = Bytes.new(block_size)
        @cipher.decrypt(decrypted, block)
        
        plain = xor_bytes(decrypted, prev)
        
        plain.size.times { |j| result[i + j] = plain[j] }
        
        prev = block
      end
      
      padding_len = result[-1].to_i
      raise "Invalid padding" if padding_len < 1 || padding_len > block_size
      
      (result.size - padding_len...result.size).each do |i|
        raise "Invalid padding" if result[i] != padding_len
      end
      
      result[0, result.size - padding_len]
    end
  end
end

# ====================================================================
# PKCS8 with Curupira192-CBC
# ====================================================================

def private_key_to_pem_encrypted(private_key : BigInt, password : String) : String
  ed521_private_to_pem_pkcs8(private_key, password)
end

def private_key_to_pem_unencrypted(private_key : BigInt) : String
  ed521_private_to_pem_pkcs8(private_key, nil)
end

def public_key_to_pem(public_x : BigInt, public_y : BigInt) : String
  ed521_public_to_pem(public_x, public_y)
end

def parse_private_key_pem(pem : String, password : String? = nil) : BigInt
  parse_ed521_private_key_pem(pem, password)
end

def parse_public_key_pem(pem : String) : Tuple(BigInt, BigInt)
  parse_ed521_public_key_pem(pem)
end

# ====================================================================
# Anubis-GCM Implementation
# ====================================================================

module Anubis
  # S-boxes and transformation tables
  T0 = [
    0xba69d2bb_u32, 0x54a84de5_u32, 0x2f5ebce2_u32, 0x74e8cd25_u32,
    0x53a651f7_u32, 0xd3bb6bd0_u32, 0xd2b96fd6_u32, 0x4d9a29b3_u32,
    0x50a05dfd_u32, 0xac458acf_u32, 0x8d070e09_u32, 0xbf63c6a5_u32,
    0x70e0dd3d_u32, 0x52a455f1_u32, 0x9a29527b_u32, 0x4c982db5_u32,
    0xeac98f46_u32, 0xd5b773c4_u32, 0x97336655_u32, 0xd1bf63dc_u32,
    0x3366ccaa_u32, 0x51a259fb_u32, 0x5bb671c7_u32, 0xa651a2f3_u32,
    0xdea15ffe_u32, 0x48903dad_u32, 0xa84d9ad7_u32, 0x992f5e71_u32,
    0xdbab4be0_u32, 0x3264c8ac_u32, 0xb773e695_u32, 0xfce5d732_u32,
    0xe3dbab70_u32, 0x9e214263_u32, 0x913f7e41_u32, 0x9b2b567d_u32,
    0xe2d9af76_u32, 0xbb6bd6bd_u32, 0x4182199b_u32, 0x6edca579_u32,
    0xa557aef9_u32, 0xcb8b0b80_u32, 0x6bd6b167_u32, 0x95376e59_u32,
    0xa15fbee1_u32, 0xf3fbeb10_u32, 0xb17ffe81_u32, 0x0204080c_u32,
    0xcc851792_u32, 0xc49537a2_u32, 0x1d3a744e_u32, 0x14285078_u32,
    0xc39b2bb0_u32, 0x63c69157_u32, 0xdaa94fe6_u32, 0x5dba69d3_u32,
    0x5fbe61df_u32, 0xdca557f2_u32, 0x7dfae913_u32, 0xcd871394_u32,
    0x7ffee11f_u32, 0x5ab475c1_u32, 0x6cd8ad75_u32, 0x5cb86dd5_u32,
    0xf7f3fb08_u32, 0x264c98d4_u32, 0xffe3db38_u32, 0xedc79354_u32,
    0xe8cd874a_u32, 0x9d274e69_u32, 0x6fdea17f_u32, 0x8e010203_u32,
    0x19326456_u32, 0xa05dbae7_u32, 0xf0fde71a_u32, 0x890f1e11_u32,
    0x0f1e3c22_u32, 0x070e1c12_u32, 0xaf4386c5_u32, 0xfbebcb20_u32,
    0x08102030_u32, 0x152a547e_u32, 0x0d1a342e_u32, 0x04081018_u32,
    0x01020406_u32, 0x64c88d45_u32, 0xdfa35bf8_u32, 0x76ecc529_u32,
    0x79f2f90b_u32, 0xdda753f4_u32, 0x3d7af48e_u32, 0x162c5874_u32,
    0x3f7efc82_u32, 0x376edcb2_u32, 0x6ddaa973_u32, 0x3870e090_u32,
    0xb96fdeb1_u32, 0x73e6d137_u32, 0xe9cf834c_u32, 0x356ad4be_u32,
    0x55aa49e3_u32, 0x71e2d93b_u32, 0x7bf6f107_u32, 0x8c050a0f_u32,
    0x72e4d531_u32, 0x880d1a17_u32, 0xf6f1ff0e_u32, 0x2a54a8fc_u32,
    0x3e7cf884_u32, 0x5ebc65d9_u32, 0x274e9cd2_u32, 0x468c0589_u32,
    0x0c183028_u32, 0x65ca8943_u32, 0x68d0bd6d_u32, 0x61c2995b_u32,
    0x03060c0a_u32, 0xc19f23bc_u32, 0x57ae41ef_u32, 0xd6b17fce_u32,
    0xd9af43ec_u32, 0x58b07dcd_u32, 0xd8ad47ea_u32, 0x66cc8549_u32,
    0xd7b37bc8_u32, 0x3a74e89c_u32, 0xc88d078a_u32, 0x3c78f088_u32,
    0xfae9cf26_u32, 0x96316253_u32, 0xa753a6f5_u32, 0x982d5a77_u32,
    0xecc59752_u32, 0xb86ddab7_u32, 0xc7933ba8_u32, 0xae4182c3_u32,
    0x69d2b96b_u32, 0x4b9631a7_u32, 0xab4b96dd_u32, 0xa94f9ed1_u32,
    0x67ce814f_u32, 0x0a14283c_u32, 0x478e018f_u32, 0xf2f9ef16_u32,
    0xb577ee99_u32, 0x224488cc_u32, 0xe5d7b364_u32, 0xeec19f5e_u32,
    0xbe61c2a3_u32, 0x2b56acfa_u32, 0x811f3e21_u32, 0x1224486c_u32,
    0x831b362d_u32, 0x1b366c5a_u32, 0x0e1c3824_u32, 0x23468cca_u32,
    0xf5f7f304_u32, 0x458a0983_u32, 0x214284c6_u32, 0xce811f9e_u32,
    0x499239ab_u32, 0x2c58b0e8_u32, 0xf9efc32c_u32, 0xe6d1bf6e_u32,
    0xb671e293_u32, 0x2850a0f0_u32, 0x172e5c72_u32, 0x8219322b_u32,
    0x1a34685c_u32, 0x8b0b161d_u32, 0xfee1df3e_u32, 0x8a09121b_u32,
    0x09122436_u32, 0xc98f038c_u32, 0x87132635_u32, 0x4e9c25b9_u32,
    0xe1dfa37c_u32, 0x2e5cb8e4_u32, 0xe4d5b762_u32, 0xe0dda77a_u32,
    0xebcb8b40_u32, 0x903d7a47_u32, 0xa455aaff_u32, 0x1e3c7844_u32,
    0x85172e39_u32, 0x60c09d5d_u32, 0x00000000_u32, 0x254a94de_u32,
    0xf4f5f702_u32, 0xf1ffe31c_u32, 0x94356a5f_u32, 0x0b162c3a_u32,
    0xe7d3bb68_u32, 0x75eac923_u32, 0xefc39b58_u32, 0x3468d0b8_u32,
    0x3162c4a6_u32, 0xd4b577c2_u32, 0xd0bd67da_u32, 0x86112233_u32,
    0x7efce519_u32, 0xad478ec9_u32, 0xfde7d334_u32, 0x2952a4f6_u32,
    0x3060c0a0_u32, 0x3b76ec9a_u32, 0x9f234665_u32, 0xf8edc72a_u32,
    0xc6913fae_u32, 0x13264c6a_u32, 0x060c1814_u32, 0x050a141e_u32,
    0xc59733a4_u32, 0x11224466_u32, 0x77eec12f_u32, 0x7cf8ed15_u32,
    0x7af4f501_u32, 0x78f0fd0d_u32, 0x366cd8b4_u32, 0x1c387048_u32,
    0x3972e496_u32, 0x59b279cb_u32, 0x18306050_u32, 0x56ac45e9_u32,
    0xb37bf68d_u32, 0xb07dfa87_u32, 0x244890d8_u32, 0x204080c0_u32,
    0xb279f28b_u32, 0x9239724b_u32, 0xa35bb6ed_u32, 0xc09d27ba_u32,
    0x44880d85_u32, 0x62c49551_u32, 0x10204060_u32, 0xb475ea9f_u32,
    0x84152a3f_u32, 0x43861197_u32, 0x933b764d_u32, 0xc2992fb6_u32,
    0x4a9435a1_u32, 0xbd67cea9_u32, 0x8f030605_u32, 0x2d5ab4ee_u32,
    0xbc65caaf_u32, 0x9c254a6f_u32, 0x6ad4b561_u32, 0x40801d9d_u32,
    0xcf831b98_u32, 0xa259b2eb_u32, 0x801d3a27_u32, 0x4f9e21bf_u32,
    0x1f3e7c42_u32, 0xca890f86_u32, 0xaa4992db_u32, 0x42841591_u32
  ]

  T1 = [
    0x69babbd2_u32, 0xa854e54d_u32, 0x5e2fe2bc_u32, 0xe87425cd_u32,
    0xa653f751_u32, 0xbbd3d06b_u32, 0xb9d2d66f_u32, 0x9a4db329_u32,
    0xa050fd5d_u32, 0x45accf8a_u32, 0x078d090e_u32, 0x63bfa5c6_u32,
    0xe0703ddd_u32, 0xa452f155_u32, 0x299a7b52_u32, 0x984cb52d_u32,
    0xc9ea468f_u32, 0xb7d5c473_u32, 0x33975566_u32, 0xbfd1dc63_u32,
    0x6633aacc_u32, 0xa251fb59_u32, 0xb65bc771_u32, 0x51a6f3a2_u32,
    0xa1defe5f_u32, 0x9048ad3d_u32, 0x4da8d79a_u32, 0x2f99715e_u32,
    0xabdbe04b_u32, 0x6432acc8_u32, 0x73b795e6_u32, 0xe5fc32d7_u32,
    0xdbe370ab_u32, 0x219e6342_u32, 0x3f91417e_u32, 0x2b9b7d56_u32,
    0xd9e276af_u32, 0x6bbbbdd6_u32, 0x82419b19_u32, 0xdc6e79a5_u32,
    0x57a5f9ae_u32, 0x8bcb800b_u32, 0xd66b67b1_u32, 0x3795596e_u32,
    0x5fa1e1be_u32, 0xfbf310eb_u32, 0x7fb181fe_u32, 0x04020c08_u32,
    0x85cc9217_u32, 0x95c4a237_u32, 0x3a1d4e74_u32, 0x28147850_u32,
    0x9bc3b02b_u32, 0xc6635791_u32, 0xa9dae64f_u32, 0xba5dd369_u32,
    0xbe5fdf61_u32, 0xa5dcf257_u32, 0xfa7d13e9_u32, 0x87cd9413_u32,
    0xfe7f1fe1_u32, 0xb45ac175_u32, 0xd86c75ad_u32, 0xb85cd56d_u32,
    0xf3f708fb_u32, 0x4c26d498_u32, 0xe3ff38db_u32, 0xc7ed5493_u32,
    0xcde84a87_u32, 0x279d694e_u32, 0xde6f7fa1_u32, 0x018e0302_u32,
    0x32195664_u32, 0x5da0e7ba_u32, 0xfdf01ae7_u32, 0x0f89111e_u32,
    0x1e0f223c_u32, 0x0e07121c_u32, 0x43afc586_u32, 0xebfb20cb_u32,
    0x10083020_u32, 0x2a157e54_u32, 0x1a0d2e34_u32, 0x08041810_u32,
    0x02010604_u32, 0xc864458d_u32, 0xa3dff85b_u32, 0xec7629c5_u32,
    0xf2790bf9_u32, 0xa7ddf453_u32, 0x7a3d8ef4_u32, 0x2c167458_u32,
    0x7e3f82fc_u32, 0x6e37b2dc_u32, 0xda6d73a9_u32, 0x703890e0_u32,
    0x6fb9b1de_u32, 0xe67337d1_u32, 0xcfe94c83_u32, 0x6a35bed4_u32,
    0xaa55e349_u32, 0xe2713bd9_u32, 0xf67b07f1_u32, 0x058c0f0a_u32,
    0xe47231d5_u32, 0x0d88171a_u32, 0xf1f60eff_u32, 0x542afca8_u32,
    0x7c3e84f8_u32, 0xbc5ed965_u32, 0x4e27d29c_u32, 0x8c468905_u32,
    0x180c2830_u32, 0xca654389_u32, 0xd0686dbd_u32, 0xc2615b99_u32,
    0x06030a0c_u32, 0x9fc1bc23_u32, 0xae57ef41_u32, 0xb1d6ce7f_u32,
    0xafd9ec43_u32, 0xb058cd7d_u32, 0xadd8ea47_u32, 0xcc664985_u32,
    0xb3d7c87b_u32, 0x743a9ce8_u32, 0x8dc88a07_u32, 0x783c88f0_u32,
    0xe9fa26cf_u32, 0x31965362_u32, 0x53a7f5a6_u32, 0x2d98775a_u32,
    0xc5ec5297_u32, 0x6db8b7da_u32, 0x93c7a83b_u32, 0x41aec382_u32,
    0xd2696bb9_u32, 0x964ba731_u32, 0x4babdd96_u32, 0x4fa9d19e_u32,
    0xce674f81_u32, 0x140a3c28_u32, 0x8e478f01_u32, 0xf9f216ef_u32,
    0x77b599ee_u32, 0x4422cc88_u32, 0xd7e564b3_u32, 0xc1ee5e9f_u32,
    0x61bea3c2_u32, 0x562bfaac_u32, 0x1f81213e_u32, 0x24126c48_u32,
    0x1b832d36_u32, 0x361b5a6c_u32, 0x1c0e2438_u32, 0x4623ca8c_u32,
    0xf7f504f3_u32, 0x8a458309_u32, 0x4221c684_u32, 0x81ce9e1f_u32,
    0x9249ab39_u32, 0x582ce8b0_u32, 0xeff92cc3_u32, 0xd1e66ebf_u32,
    0x71b693e2_u32, 0x5028f0a0_u32, 0x2e17725c_u32, 0x19822b32_u32,
    0x341a5c68_u32, 0x0b8b1d16_u32, 0xe1fe3edf_u32, 0x098a1b12_u32,
    0x12093624_u32, 0x8fc98c03_u32, 0x13873526_u32, 0x9c4eb925_u32,
    0xdfe17ca3_u32, 0x5c2ee4b8_u32, 0xd5e462b7_u32, 0xdde07aa7_u32,
    0xcbeb408b_u32, 0x3d90477a_u32, 0x55a4ffaa_u32, 0x3c1e4478_u32,
    0x1785392e_u32, 0xc0605d9d_u32, 0x00000000_u32, 0x4a25de94_u32,
    0xf5f402f7_u32, 0xfff11ce3_u32, 0x35945f6a_u32, 0x160b3a2c_u32,
    0xd3e768bb_u32, 0xea7523c9_u32, 0xc3ef589b_u32, 0x6834b8d0_u32,
    0x6231a6c4_u32, 0xb5d4c277_u32, 0xbdd0da67_u32, 0x11863322_u32,
    0xfc7e19e5_u32, 0x47adc98e_u32, 0xe7fd34d3_u32, 0x5229f6a4_u32,
    0x6030a0c0_u32, 0x763b9aec_u32, 0x239f6546_u32, 0xedf82ac7_u32,
    0x91c6ae3f_u32, 0x26136a4c_u32, 0x0c061418_u32, 0x0a051e14_u32,
    0x97c5a433_u32, 0x22116644_u32, 0xee772fc1_u32, 0xf87c15ed_u32,
    0xf47a01f5_u32, 0xf0780dfd_u32, 0x6c36b4d8_u32, 0x381c4870_u32,
    0x723996e4_u32, 0xb259cb79_u32, 0x30185060_u32, 0xac56e945_u32,
    0x7bb38df6_u32, 0x7db087fa_u32, 0x4824d890_u32, 0x4020c080_u32,
    0x79b28bf2_u32, 0x39924b72_u32, 0x5ba3edb6_u32, 0x9dc0ba27_u32,
    0x8844850d_u32, 0xc4625195_u32, 0x20106040_u32, 0x75b49fea_u32,
    0x15843f2a_u32, 0x86439711_u32, 0x3b934d76_u32, 0x99c2b62f_u32,
    0x944aa135_u32, 0x67bda9ce_u32, 0x038f0506_u32, 0x5a2deeb4_u32,
    0x65bcafca_u32, 0x259c6f4a_u32, 0xd46a61b5_u32, 0x80409d1d_u32,
    0x83cf981b_u32, 0x59a2ebb2_u32, 0x1d80273a_u32, 0x9e4fbf21_u32,
    0x3e1f427c_u32, 0x89ca860f_u32, 0x49aadb92_u32, 0x84429115_u32
  ]

  T2 = [
    0xd2bbba69_u32, 0x4de554a8_u32, 0xbce22f5e_u32, 0xcd2574e8_u32,
    0x51f753a6_u32, 0x6bd0d3bb_u32, 0x6fd6d2b9_u32, 0x29b34d9a_u32,
    0x5dfd50a0_u32, 0x8acfac45_u32, 0x0e098d07_u32, 0xc6a5bf63_u32,
    0xdd3d70e0_u32, 0x55f152a4_u32, 0x527b9a29_u32, 0x2db54c98_u32,
    0x8f46eac9_u32, 0x73c4d5b7_u32, 0x66559733_u32, 0x63dcd1bf_u32,
    0xccaa3366_u32, 0x59fb51a2_u32, 0x71c75bb6_u32, 0xa2f3a651_u32,
    0x5ffedea1_u32, 0x3dad4890_u32, 0x9ad7a84d_u32, 0x5e71992f_u32,
    0x4be0dbab_u32, 0xc8ac3264_u32, 0xe695b773_u32, 0xd732fce5_u32,
    0xab70e3db_u32, 0x42639e21_u32, 0x7e41913f_u32, 0x567d9b2b_u32,
    0xaf76e2d9_u32, 0xd6bdbb6b_u32, 0x199b4182_u32, 0xa5796edc_u32,
    0xaef9a557_u32, 0x0b80cb8b_u32, 0xb1676bd6_u32, 0x6e599537_u32,
    0xbee1a15f_u32, 0xeb10f3fb_u32, 0xfe81b17f_u32, 0x080c0204_u32,
    0x1792cc85_u32, 0x37a2c495_u32, 0x744e1d3a_u32, 0x50781428_u32,
    0x2bb0c39b_u32, 0x915763c6_u32, 0x4fe6daa9_u32, 0x69d35dba_u32,
    0x61df5fbe_u32, 0x57f2dca5_u32, 0xe9137dfa_u32, 0x1394cd87_u32,
    0xe11f7ffe_u32, 0x75c15ab4_u32, 0xad756cd8_u32, 0x6dd55cb8_u32,
    0xfb08f7f3_u32, 0x98d4264c_u32, 0xdb38ffe3_u32, 0x9354edc7_u32,
    0x874ae8cd_u32, 0x4e699d27_u32, 0xa17f6fde_u32, 0x02038e01_u32,
    0x64561932_u32, 0xbae7a05d_u32, 0xe71af0fd_u32, 0x1e11890f_u32,
    0x3c220f1e_u32, 0x1c12070e_u32, 0x86c5af43_u32, 0xcb20fbeb_u32,
    0x20300810_u32, 0x547e152a_u32, 0x342e0d1a_u32, 0x10180408_u32,
    0x04060102_u32, 0x8d4564c8_u32, 0x5bf8dfa3_u32, 0xc52976ec_u32,
    0xf90b79f2_u32, 0x53f4dda7_u32, 0xf48e3d7a_u32, 0x5874162c_u32,
    0xfc823f7e_u32, 0xdcb2376e_u32, 0xa9736dda_u32, 0xe0903870_u32,
    0xdeb1b96f_u32, 0xd13773e6_u32, 0x834ce9cf_u32, 0xd4be356a_u32,
    0x49e355aa_u32, 0xd93b71e2_u32, 0xf1077bf6_u32, 0x0a0f8c05_u32,
    0xd53172e4_u32, 0x1a17880d_u32, 0xff0ef6f1_u32, 0xa8fc2a54_u32,
    0xf8843e7c_u32, 0x65d95ebc_u32, 0x9cd2274e_u32, 0x0589468c_u32,
    0x30280c18_u32, 0x894365ca_u32, 0xbd6d68d0_u32, 0x995b61c2_u32,
    0x0c0a0306_u32, 0x23bcc19f_u32, 0x41ef57ae_u32, 0x7fced6b1_u32,
    0x43ecd9af_u32, 0x7dcd58b0_u32, 0x47ead8ad_u32, 0x854966cc_u32,
    0x7bc8d7b3_u32, 0xe89c3a74_u32, 0x078ac88d_u32, 0xf0883c78_u32,
    0xcf26fae9_u32, 0x62539631_u32, 0xa6f5a753_u32, 0x5a77982d_u32,
    0x9752ecc5_u32, 0xdab7b86d_u32, 0x3ba8c793_u32, 0x82c3ae41_u32,
    0xb96b69d2_u32, 0x31a74b96_u32, 0x96ddab4b_u32, 0x9ed1a94f_u32,
    0x814f67ce_u32, 0x283c0a14_u32, 0x018f478e_u32, 0xef16f2f9_u32,
    0xee99b577_u32, 0x88cc2244_u32, 0xb364e5d7_u32, 0x9f5eeec1_u32,
    0xc2a3be61_u32, 0xacfa2b56_u32, 0x3e21811f_u32, 0x486c1224_u32,
    0x362d831b_u32, 0x6c5a1b36_u32, 0x38240e1c_u32, 0x8cca2346_u32,
    0xf304f5f7_u32, 0x0983458a_u32, 0x84c62142_u32, 0x1f9ece81_u32,
    0x39ab4992_u32, 0xb0e82c58_u32, 0xc32cf9ef_u32, 0xbf6ee6d1_u32,
    0xe293b671_u32, 0xa0f02850_u32, 0x5c72172e_u32, 0x322b8219_u32,
    0x685c1a34_u32, 0x161d8b0b_u32, 0xdf3efee1_u32, 0x121b8a09_u32,
    0x24360912_u32, 0x038cc98f_u32, 0x26358713_u32, 0x25b94e9c_u32,
    0xa37ce1df_u32, 0xb8e42e5c_u32, 0xb762e4d5_u32, 0xa77ae0dd_u32,
    0x8b40ebcb_u32, 0x7a47903d_u32, 0xaaffa455_u32, 0x78441e3c_u32,
    0x2e398517_u32, 0x9d5d60c0_u32, 0x00000000_u32, 0x94de254a_u32,
    0xf702f4f5_u32, 0xe31cf1ff_u32, 0x6a5f9435_u32, 0x2c3a0b16_u32,
    0xbb68e7d3_u32, 0xc92375ea_u32, 0x9b58efc3_u32, 0xd0b83468_u32,
    0xc4a63162_u32, 0x77c2d4b5_u32, 0x67dad0bd_u32, 0x22338611_u32,
    0xe5197efc_u32, 0x8ec9ad47_u32, 0xd334fde7_u32, 0xa4f62952_u32,
    0xc0a03060_u32, 0xec9a3b76_u32, 0x46659f23_u32, 0xc72af8ed_u32,
    0x3faec691_u32, 0x4c6a1326_u32, 0x1814060c_u32, 0x141e050a_u32,
    0x33a4c597_u32, 0x44661122_u32, 0xc12f77ee_u32, 0xed157cf8_u32,
    0xf5017af4_u32, 0xfd0d78f0_u32, 0xd8b4366c_u32, 0x70481c38_u32,
    0xe4963972_u32, 0x79cb59b2_u32, 0x60501830_u32, 0x45e956ac_u32,
    0xf68db37b_u32, 0xfa87b07d_u32, 0x90d82448_u32, 0x80c02040_u32,
    0xf28bb279_u32, 0x724b9239_u32, 0xb6eda35b_u32, 0x27bac09d_u32,
    0x0d854488_u32, 0x955162c4_u32, 0x40601020_u32, 0xea9fb475_u32,
    0x2a3f8415_u32, 0x11974386_u32, 0x764d933b_u32, 0x2fb6c299_u32,
    0x35a14a94_u32, 0xcea9bd67_u32, 0x06058f03_u32, 0xb4ee2d5a_u32,
    0xcaafbc65_u32, 0x4a6f9c25_u32, 0xb5616ad4_u32, 0x1d9d4080_u32,
    0x1b98cf83_u32, 0xb2eba259_u32, 0x3a27801d_u32, 0x21bf4f9e_u32,
    0x7c421f3e_u32, 0x0f86ca89_u32, 0x92dbaa49_u32, 0x15914284_u32
  ]

  T3 = [
    0xbbd269ba_u32, 0xe54da854_u32, 0xe2bc5e2f_u32, 0x25cde874_u32,
    0xf751a653_u32, 0xd06bbbd3_u32, 0xd66fb9d2_u32, 0xb3299a4d_u32,
    0xfd5da050_u32, 0xcf8a45ac_u32, 0x090e078d_u32, 0xa5c663bf_u32,
    0x3ddde070_u32, 0xf155a452_u32, 0x7b52299a_u32, 0xb52d984c_u32,
    0x468fc9ea_u32, 0xc473b7d5_u32, 0x55663397_u32, 0xdc63bfd1_u32,
    0xaacc6633_u32, 0xfb59a251_u32, 0xc771b65b_u32, 0xf3a251a6_u32,
    0xfe5fa1de_u32, 0xad3d9048_u32, 0xd79a4da8_u32, 0x715e2f99_u32,
    0xe04babdb_u32, 0xacc86432_u32, 0x95e673b7_u32, 0x32d7e5fc_u32,
    0x70abdbe3_u32, 0x6342219e_u32, 0x417e3f91_u32, 0x7d562b9b_u32,
    0x76afd9e2_u32, 0xbdd66bbb_u32, 0x9b198241_u32, 0x79a5dc6e_u32,
    0xf9ae57a5_u32, 0x800b8bcb_u32, 0x67b1d66b_u32, 0x596e3795_u32,
    0xe1be5fa1_u32, 0x10ebfbf3_u32, 0x81fe7fb1_u32, 0x0c080402_u32,
    0x921785cc_u32, 0xa23795c4_u32, 0x4e743a1d_u32, 0x78502814_u32,
    0xb02b9bc3_u32, 0x5791c663_u32, 0xe64fa9da_u32, 0xd369ba5d_u32,
    0xdf61be5f_u32, 0xf257a5dc_u32, 0x13e9fa7d_u32, 0x941387cd_u32,
    0x1fe1fe7f_u32, 0xc175b45a_u32, 0x75add86c_u32, 0xd56db85c_u32,
    0x08fbf3f7_u32, 0xd4984c26_u32, 0x38dbe3ff_u32, 0x5493c7ed_u32,
    0x4a87cde8_u32, 0x694e279d_u32, 0x7fa1de6f_u32, 0x0302018e_u32,
    0x56643219_u32, 0xe7ba5da0_u32, 0x1ae7fdf0_u32, 0x111e0f89_u32,
    0x223c1e0f_u32, 0x121c0e07_u32, 0xc58643af_u32, 0x20cbebfb_u32,
    0x30201008_u32, 0x7e542a15_u32, 0x2e341a0d_u32, 0x18100804_u32,
    0x06040201_u32, 0x458dc864_u32, 0xf85ba3df_u32, 0x29c5ec76_u32,
    0x0bf9f279_u32, 0xf453a7dd_u32, 0x8ef47a3d_u32, 0x74582c16_u32,
    0x82fc7e3f_u32, 0xb2dc6e37_u32, 0x73a9da6d_u32, 0x90e07038_u32,
    0xb1de6fb9_u32, 0x37d1e673_u32, 0x4c83cfe9_u32, 0xbed46a35_u32,
    0xe349aa55_u32, 0x3bd9e271_u32, 0x07f1f67b_u32, 0x0f0a058c_u32,
    0x31d5e472_u32, 0x171a0d88_u32, 0x0efff1f6_u32, 0xfca8542a_u32,
    0x84f87c3e_u32, 0xd965bc5e_u32, 0xd29c4e27_u32, 0x89058c46_u32,
    0x2830180c_u32, 0x4389ca65_u32, 0x6dbdd068_u32, 0x5b99c261_u32,
    0x0a0c0603_u32, 0xbc239fc1_u32, 0xef41ae57_u32, 0xce7fb1d6_u32,
    0xec43afd9_u32, 0xcd7db058_u32, 0xea47add8_u32, 0x4985cc66_u32,
    0xc87bb3d7_u32, 0x9ce8743a_u32, 0x8a078dc8_u32, 0x88f0783c_u32,
    0x26cfe9fa_u32, 0x53623196_u32, 0xf5a653a7_u32, 0x775a2d98_u32,
    0x5297c5ec_u32, 0xb7da6db8_u32, 0xa83b93c7_u32, 0xc38241ae_u32,
    0x6bb9d269_u32, 0xa731964b_u32, 0xdd964bab_u32, 0xd19e4fa9_u32,
    0x4f81ce67_u32, 0x3c28140a_u32, 0x8f018e47_u32, 0x16eff9f2_u32,
    0x99ee77b5_u32, 0xcc884422_u32, 0x64b3d7e5_u32, 0x5e9fc1ee_u32,
    0xa3c261be_u32, 0xfaac562b_u32, 0x213e1f81_u32, 0x6c482412_u32,
    0x2d361b83_u32, 0x5a6c361b_u32, 0x24381c0e_u32, 0xca8c4623_u32,
    0x04f3f7f5_u32, 0x83098a45_u32, 0xc6844221_u32, 0x9e1f81ce_u32,
    0xab399249_u32, 0xe8b0582c_u32, 0x2cc3eff9_u32, 0x6ebfd1e6_u32,
    0x93e271b6_u32, 0xf0a05028_u32, 0x725c2e17_u32, 0x2b321982_u32,
    0x5c68341a_u32, 0x1d160b8b_u32, 0x3edfe1fe_u32, 0x1b12098a_u32,
    0x36241209_u32, 0x8c038fc9_u32, 0x35261387_u32, 0xb9259c4e_u32,
    0x7ca3dfe1_u32, 0xe4b85c2e_u32, 0x62b7d5e4_u32, 0x7aa7dde0_u32,
    0x408bcbeb_u32, 0x477a3d90_u32, 0xffaa55a4_u32, 0x44783c1e_u32,
    0x392e1785_u32, 0x5d9dc060_u32, 0x00000000_u32, 0xde944a25_u32,
    0x02f7f5f4_u32, 0x1ce3fff1_u32, 0x5f6a3594_u32, 0x3a2c160b_u32,
    0x68bbd3e7_u32, 0x23c9ea75_u32, 0x589bc3ef_u32, 0xb8d06834_u32,
    0xa6c46231_u32, 0xc277b5d4_u32, 0xda67bdd0_u32, 0x33221186_u32,
    0x19e5fc7e_u32, 0xc98e47ad_u32, 0x34d3e7fd_u32, 0xf6a45229_u32,
    0xa0c06030_u32, 0x9aec763b_u32, 0x6546239f_u32, 0x2ac7edf8_u32,
    0xae3f91c6_u32, 0x6a4c2613_u32, 0x14180c06_u32, 0x1e140a05_u32,
    0xa43397c5_u32, 0x66442211_u32, 0x2fc1ee77_u32, 0x15edf87c_u32,
    0x01f5f47a_u32, 0x0dfdf078_u32, 0xb4d86c36_u32, 0x4870381c_u32,
    0x96e47239_u32, 0xcb79b259_u32, 0x50603018_u32, 0xe945ac56_u32,
    0x8df67bb3_u32, 0x87fa7db0_u32, 0xd8904824_u32, 0xc0804020_u32,
    0x8bf279b2_u32, 0x4b723992_u32, 0xedb65ba3_u32, 0xba279dc0_u32,
    0x850d8844_u32, 0x5195c462_u32, 0x60402010_u32, 0x9fea75b4_u32,
    0x3f2a1584_u32, 0x97118643_u32, 0x4d763b93_u32, 0xb62f99c2_u32,
    0xa135944a_u32, 0xa9ce67bd_u32, 0x0506038f_u32, 0xeeb45a2d_u32,
    0xafca65bc_u32, 0x6f4a259c_u32, 0x61b5d46a_u32, 0x9d1d8040_u32,
    0x981b83cf_u32, 0xebb259a2_u32, 0x273a1d80_u32, 0xbf219e4f_u32,
    0x427c3e1f_u32, 0x860f89ca_u32, 0xdb9249aa_u32, 0x91158442_u32
  ]

  T4 = [
    0xbabababa_u32, 0x54545454_u32, 0x2f2f2f2f_u32, 0x74747474_u32,
    0x53535353_u32, 0xd3d3d3d3_u32, 0xd2d2d2d2_u32, 0x4d4d4d4d_u32,
    0x50505050_u32, 0xacacacac_u32, 0x8d8d8d8d_u32, 0xbfbfbfbf_u32,
    0x70707070_u32, 0x52525252_u32, 0x9a9a9a9a_u32, 0x4c4c4c4c_u32,
    0xeaeaeaea_u32, 0xd5d5d5d5_u32, 0x97979797_u32, 0xd1d1d1d1_u32,
    0x33333333_u32, 0x51515151_u32, 0x5b5b5b5b_u32, 0xa6a6a6a6_u32,
    0xdededede_u32, 0x48484848_u32, 0xa8a8a8a8_u32, 0x99999999_u32,
    0xdbdbdbdb_u32, 0x32323232_u32, 0xb7b7b7b7_u32, 0xfcfcfcfc_u32,
    0xe3e3e3e3_u32, 0x9e9e9e9e_u32, 0x91919191_u32, 0x9b9b9b9b_u32,
    0xe2e2e2e2_u32, 0xbbbbbbbb_u32, 0x41414141_u32, 0x6e6e6e6e_u32,
    0xa5a5a5a5_u32, 0xcbcbcbcb_u32, 0x6b6b6b6b_u32, 0x95959595_u32,
    0xa1a1a1a1_u32, 0xf3f3f3f3_u32, 0xb1b1b1b1_u32, 0x02020202_u32,
    0xcccccccc_u32, 0xc4c4c4c4_u32, 0x1d1d1d1d_u32, 0x14141414_u32,
    0xc3c3c3c3_u32, 0x63636363_u32, 0xdadadada_u32, 0x5d5d5d5d_u32,
    0x5f5f5f5f_u32, 0xdcdcdcdc_u32, 0x7d7d7d7d_u32, 0xcdcdcdcd_u32,
    0x7f7f7f7f_u32, 0x5a5a5a5a_u32, 0x6c6c6c6c_u32, 0x5c5c5c5c_u32,
    0xf7f7f7f7_u32, 0x26262626_u32, 0xffffffff_u32, 0xedededed_u32,
    0xe8e8e8e8_u32, 0x9d9d9d9d_u32, 0x6f6f6f6f_u32, 0x8e8e8e8e_u32,
    0x19191919_u32, 0xa0a0a0a0_u32, 0xf0f0f0f0_u32, 0x89898989_u32,
    0x0f0f0f0f_u32, 0x07070707_u32, 0xafafafaf_u32, 0xfbfbfbfb_u32,
    0x08080808_u32, 0x15151515_u32, 0x0d0d0d0d_u32, 0x04040404_u32,
    0x01010101_u32, 0x64646464_u32, 0xdfdfdfdf_u32, 0x76767676_u32,
    0x79797979_u32, 0xdddddddd_u32, 0x3d3d3d3d_u32, 0x16161616_u32,
    0x3f3f3f3f_u32, 0x37373737_u32, 0x6d6d6d6d_u32, 0x38383838_u32,
    0xb9b9b9b9_u32, 0x73737373_u32, 0xe9e9e9e9_u32, 0x35353535_u32,
    0x55555555_u32, 0x71717171_u32, 0x7b7b7b7b_u32, 0x8c8c8c8c_u32,
    0x72727272_u32, 0x88888888_u32, 0xf6f6f6f6_u32, 0x2a2a2a2a_u32,
    0x3e3e3e3e_u32, 0x5e5e5e5e_u32, 0x27272727_u32, 0x46464646_u32,
    0x0c0c0c0c_u32, 0x65656565_u32, 0x68686868_u32, 0x61616161_u32,
    0x03030303_u32, 0xc1c1c1c1_u32, 0x57575757_u32, 0xd6d6d6d6_u32,
    0xd9d9d9d9_u32, 0x58585858_u32, 0xd8d8d8d8_u32, 0x66666666_u32,
    0xd7d7d7d7_u32, 0x3a3a3a3a_u32, 0xc8c8c8c8_u32, 0x3c3c3c3c_u32,
    0xfafafafa_u32, 0x96969696_u32, 0xa7a7a7a7_u32, 0x98989898_u32,
    0xecececec_u32, 0xb8b8b8b8_u32, 0xc7c7c7c7_u32, 0xaeaeaeae_u32,
    0x69696969_u32, 0x4b4b4b4b_u32, 0xabababab_u32, 0xa9a9a9a9_u32,
    0x67676767_u32, 0x0a0a0a0a_u32, 0x47474747_u32, 0xf2f2f2f2_u32,
    0xb5b5b5b5_u32, 0x22222222_u32, 0xe5e5e5e5_u32, 0xeeeeeeee_u32,
    0xbebebebe_u32, 0x2b2b2b2b_u32, 0x81818181_u32, 0x12121212_u32,
    0x83838383_u32, 0x1b1b1b1b_u32, 0x0e0e0e0e_u32, 0x23232323_u32,
    0xf5f5f5f5_u32, 0x45454545_u32, 0x21212121_u32, 0xcececece_u32,
    0x49494949_u32, 0x2c2c2c2c_u32, 0xf9f9f9f9_u32, 0xe6e6e6e6_u32,
    0xb6b6b6b6_u32, 0x28282828_u32, 0x17171717_u32, 0x82828282_u32,
    0x1a1a1a1a_u32, 0x8b8b8b8b_u32, 0xfefefefe_u32, 0x8a8a8a8a_u32,
    0x09090909_u32, 0xc9c9c9c9_u32, 0x87878787_u32, 0x4e4e4e4e_u32,
    0xe1e1e1e1_u32, 0x2e2e2e2e_u32, 0xe4e4e4e4_u32, 0xe0e0e0e0_u32,
    0xebebebeb_u32, 0x90909090_u32, 0xa4a4a4a4_u32, 0x1e1e1e1e_u32,
    0x85858585_u32, 0x60606060_u32, 0x00000000_u32, 0x25252525_u32,
    0xf4f4f4f4_u32, 0xf1f1f1f1_u32, 0x94949494_u32, 0x0b0b0b0b_u32,
    0xe7e7e7e7_u32, 0x75757575_u32, 0xefefefef_u32, 0x34343434_u32,
    0x31313131_u32, 0xd4d4d4d4_u32, 0xd0d0d0d0_u32, 0x86868686_u32,
    0x7e7e7e7e_u32, 0xadadadad_u32, 0xfdfdfdfd_u32, 0x29292929_u32,
    0x30303030_u32, 0x3b3b3b3b_u32, 0x9f9f9f9f_u32, 0xf8f8f8f8_u32,
    0xc6c6c6c6_u32, 0x13131313_u32, 0x06060606_u32, 0x05050505_u32,
    0xc5c5c5c5_u32, 0x11111111_u32, 0x77777777_u32, 0x7c7c7c7c_u32,
    0x7a7a7a7a_u32, 0x78787878_u32, 0x36363636_u32, 0x1c1c1c1c_u32,
    0x39393939_u32, 0x59595959_u32, 0x18181818_u32, 0x56565656_u32,
    0xb3b3b3b3_u32, 0xb0b0b0b0_u32, 0x24242424_u32, 0x20202020_u32,
    0xb2b2b2b2_u32, 0x92929292_u32, 0xa3a3a3a3_u32, 0xc0c0c0c0_u32,
    0x44444444_u32, 0x62626262_u32, 0x10101010_u32, 0xb4b4b4b4_u32,
    0x84848484_u32, 0x43434343_u32, 0x93939393_u32, 0xc2c2c2c2_u32,
    0x4a4a4a4a_u32, 0xbdbdbdbd_u32, 0x8f8f8f8f_u32, 0x2d2d2d2d_u32,
    0xbcbcbcbc_u32, 0x9c9c9c9c_u32, 0x6a6a6a6a_u32, 0x40404040_u32,
    0xcfcfcfcf_u32, 0xa2a2a2a2_u32, 0x80808080_u32, 0x4f4f4f4f_u32,
    0x1f1f1f1f_u32, 0xcacacaca_u32, 0xaaaaaaaa_u32, 0x42424242_u32
  ]

  T5 = [
    0x00000000_u32, 0x01020608_u32, 0x02040c10_u32, 0x03060a18_u32,
    0x04081820_u32, 0x050a1e28_u32, 0x060c1430_u32, 0x070e1238_u32,
    0x08103040_u32, 0x09123648_u32, 0x0a143c50_u32, 0x0b163a58_u32,
    0x0c182860_u32, 0x0d1a2e68_u32, 0x0e1c2470_u32, 0x0f1e2278_u32,
    0x10206080_u32, 0x11226688_u32, 0x12246c90_u32, 0x13266a98_u32,
    0x142878a0_u32, 0x152a7ea8_u32, 0x162c74b0_u32, 0x172e72b8_u32,
    0x183050c0_u32, 0x193256c8_u32, 0x1a345cd0_u32, 0x1b365ad8_u32,
    0x1c3848e0_u32, 0x1d3a4ee8_u32, 0x1e3c44f0_u32, 0x1f3e42f8_u32,
    0x2040c01d_u32, 0x2142c615_u32, 0x2244cc0d_u32, 0x2346ca05_u32,
    0x2448d83d_u32, 0x254ade35_u32, 0x264cd42d_u32, 0x274ed225_u32,
    0x2850f05d_u32, 0x2952f655_u32, 0x2a54fc4d_u32, 0x2b56fa45_u32,
    0x2c58e87d_u32, 0x2d5aee75_u32, 0x2e5ce46d_u32, 0x2f5ee265_u32,
    0x3060a09d_u32, 0x3162a695_u32, 0x3264ac8d_u32, 0x3366aa85_u32,
    0x3468b8bd_u32, 0x356abeb5_u32, 0x366cb4ad_u32, 0x376eb2a5_u32,
    0x387090dd_u32, 0x397296d5_u32, 0x3a749ccd_u32, 0x3b769ac5_u32,
    0x3c7888fd_u32, 0x3d7a8ef5_u32, 0x3e7c84ed_u32, 0x3f7e82e5_u32,
    0x40809d3a_u32, 0x41829b32_u32, 0x4284912a_u32, 0x43869722_u32,
    0x4488851a_u32, 0x458a8312_u32, 0x468c890a_u32, 0x478e8f02_u32,
    0x4890ad7a_u32, 0x4992ab72_u32, 0x4a94a16a_u32, 0x4b96a762_u32,
    0x4c98b55a_u32, 0x4d9ab352_u32, 0x4e9cb94a_u32, 0x4f9ebf42_u32,
    0x50a0fdba_u32, 0x51a2fbb2_u32, 0x52a4f1aa_u32, 0x53a6f7a2_u32,
    0x54a8e59a_u32, 0x55aae392_u32, 0x56ace98a_u32, 0x57aeef82_u32,
    0x58b0cdfa_u32, 0x59b2cbf2_u32, 0x5ab4c1ea_u32, 0x5bb6c7e2_u32,
    0x5cb8d5da_u32, 0x5dbad3d2_u32, 0x5ebcd9ca_u32, 0x5fbedfc2_u32,
    0x60c05d27_u32, 0x61c25b2f_u32, 0x62c45137_u32, 0x63c6573f_u32,
    0x64c84507_u32, 0x65ca430f_u32, 0x66cc4917_u32, 0x67ce4f1f_u32,
    0x68d06d67_u32, 0x69d26b6f_u32, 0x6ad46177_u32, 0x6bd6677f_u32,
    0x6cd87547_u32, 0x6dda734f_u32, 0x6edc7957_u32, 0x6fde7f5f_u32,
    0x70e03da7_u32, 0x71e23baf_u32, 0x72e431b7_u32, 0x73e637bf_u32,
    0x74e82587_u32, 0x75ea238f_u32, 0x76ec2997_u32, 0x77ee2f9f_u32,
    0x78f00de7_u32, 0x79f20bef_u32, 0x7af401f7_u32, 0x7bf607ff_u32,
    0x7cf815c7_u32, 0x7dfa13cf_u32, 0x7efc19d7_u32, 0x7ffe1fdf_u32,
    0x801d2774_u32, 0x811f217c_u32, 0x82192b64_u32, 0x831b2d6c_u32,
    0x84153f54_u32, 0x8517395c_u32, 0x86113344_u32, 0x8713354c_u32,
    0x880d1734_u32, 0x890f113c_u32, 0x8a091b24_u32, 0x8b0b1d2c_u32,
    0x8c050f14_u32, 0x8d07091c_u32, 0x8e010304_u32, 0x8f03050c_u32,
    0x903d47f4_u32, 0x913f41fc_u32, 0x92394be4_u32, 0x933b4dec_u32,
    0x94355fd4_u32, 0x953759dc_u32, 0x963153c4_u32, 0x973355cc_u32,
    0x982d77b4_u32, 0x992f71bc_u32, 0x9a297ba4_u32, 0x9b2b7dac_u32,
    0x9c256f94_u32, 0x9d27699c_u32, 0x9e216384_u32, 0x9f23658c_u32,
    0xa05de769_u32, 0xa15fe161_u32, 0xa259eb79_u32, 0xa35bed71_u32,
    0xa455ff49_u32, 0xa557f941_u32, 0xa651f359_u32, 0xa753f551_u32,
    0xa84dd729_u32, 0xa94fd121_u32, 0xaa49db39_u32, 0xab4bdd31_u32,
    0xac45cf09_u32, 0xad47c901_u32, 0xae41c319_u32, 0xaf43c511_u32,
    0xb07d87e9_u32, 0xb17f81e1_u32, 0xb2798bf9_u32, 0xb37b8df1_u32,
    0xb4759fc9_u32, 0xb57799c1_u32, 0xb67193d9_u32, 0xb77395d1_u32,
    0xb86db7a9_u32, 0xb96fb1a1_u32, 0xba69bbb9_u32, 0xbb6bbdb1_u32,
    0xbc65af89_u32, 0xbd67a981_u32, 0xbe61a399_u32, 0xbf63a591_u32,
    0xc09dba4e_u32, 0xc19fbc46_u32, 0xc299b65e_u32, 0xc39bb056_u32,
    0xc495a26e_u32, 0xc597a466_u32, 0xc691ae7e_u32, 0xc793a876_u32,
    0xc88d8a0e_u32, 0xc98f8c06_u32, 0xca89861e_u32, 0xcb8b8016_u32,
    0xcc85922e_u32, 0xcd879426_u32, 0xce819e3e_u32, 0xcf839836_u32,
    0xd0bddace_u32, 0xd1bfdcc6_u32, 0xd2b9d6de_u32, 0xd3bbd0d6_u32,
    0xd4b5c2ee_u32, 0xd5b7c4e6_u32, 0xd6b1cefe_u32, 0xd7b3c8f6_u32,
    0xd8adea8e_u32, 0xd9afec86_u32, 0xdaa9e69e_u32, 0xdbabe096_u32,
    0xdca5f2ae_u32, 0xdda7f4a6_u32, 0xdea1febe_u32, 0xdfa3f8b6_u32,
    0xe0dd7a53_u32, 0xe1df7c5b_u32, 0xe2d97643_u32, 0xe3db704b_u32,
    0xe4d56273_u32, 0xe5d7647b_u32, 0xe6d16e63_u32, 0xe7d3686b_u32,
    0xe8cd4a13_u32, 0xe9cf4c1b_u32, 0xeac94603_u32, 0xebcb400b_u32,
    0xecc55233_u32, 0xedc7543b_u32, 0xeec15e23_u32, 0xefc3582b_u32,
    0xf0fd1ad3_u32, 0xf1ff1cdb_u32, 0xf2f916c3_u32, 0xf3fb10cb_u32,
    0xf4f502f3_u32, 0xf5f704fb_u32, 0xf6f10ee3_u32, 0xf7f308eb_u32,
    0xf8ed2a93_u32, 0xf9ef2c9b_u32, 0xfae92683_u32, 0xfbeb208b_u32,
    0xfce532b3_u32, 0xfde734bb_u32, 0xfee13ea3_u32, 0xffe338ab_u32
  ]

  class Cipher
    @round_key_enc : Array(Array(UInt32))
    @round_key_dec : Array(Array(UInt32))
    @n : Int32

    def initialize(key : Bytes)
      @round_key_enc = [] of Array(UInt32)
      @round_key_dec = [] of Array(UInt32)
      @n = key.size // 4
      
      key_setup(key)
    end

    private def rot(value : UInt32, r : Int32) : UInt32
      return value if r == 0
      (value >> r) & 0xffffffff_u32
    end

    private def get_byte(value : UInt32, pos : Int32) : UInt32
      ((value >> pos) & 0xff).to_u32
    end

    private def key_setup(key : Bytes)
      if @n < 4 || @n > 10
        raise "Invalid Anubis key size: #{32 * @n} bits"
      end

      kappa = Array(UInt32).new(@n, 0_u32)
      inter = Array(UInt32).new(@n, 0_u32)
      r = 8 + @n

      pos = 0
      @n.times do |i|
        kappa[i] = (
          (key[pos].to_u32! << 24) |
          (key[pos + 1].to_u32! << 16) |
          (key[pos + 2].to_u32! << 8) |
          key[pos + 3].to_u32!
        ) & 0xffffffff_u32
        pos += 4
      end

      (r + 1).times do |round|
        k0 = T4[rot(kappa[@n - 1], 24)]
        k1 = T4[get_byte(kappa[@n - 1], 16)]
        k2 = T4[get_byte(kappa[@n - 1], 8)]
        k3 = T4[kappa[@n - 1] & 0xff]

        (@n - 2).downto(0) do |t|
          k0 = (T4[rot(kappa[t], 24)] ^
               (T5[rot(k0, 24)] & 0xff000000_u32) ^
               (T5[get_byte(k0, 16)] & 0x00ff0000_u32) ^
               (T5[get_byte(k0, 8)] & 0x0000ff00_u32) ^
               (T5[k0 & 0xff] & 0x000000ff_u32)) & 0xffffffff_u32

          k1 = (T4[get_byte(kappa[t], 16)] ^
               (T5[rot(k1, 24)] & 0xff000000_u32) ^
               (T5[get_byte(k1, 16)] & 0x00ff0000_u32) ^
               (T5[get_byte(k1, 8)] & 0x0000ff00_u32) ^
               (T5[k1 & 0xff] & 0x000000ff_u32)) & 0xffffffff_u32

          k2 = (T4[get_byte(kappa[t], 8)] ^
               (T5[rot(k2, 24)] & 0xff000000_u32) ^
               (T5[get_byte(k2, 16)] & 0x00ff0000_u32) ^
               (T5[get_byte(k2, 8)] & 0x0000ff00_u32) ^
               (T5[k2 & 0xff] & 0x000000ff_u32)) & 0xffffffff_u32

          k3 = (T4[kappa[t] & 0xff] ^
               (T5[rot(k3, 24)] & 0xff000000_u32) ^
               (T5[get_byte(k3, 16)] & 0x00ff0000_u32) ^
               (T5[get_byte(k3, 8)] & 0x0000ff00_u32) ^
               (T5[k3 & 0xff] & 0x000000ff_u32)) & 0xffffffff_u32
        end

        @round_key_enc << [k0, k1, k2, k3]

        @n.times do |i|
          idx1 = (i + @n - 1) % @n
          idx2 = (i + @n - 2) % @n
          idx3 = (i + @n - 3) % @n
          
          inter[i] = (T0[rot(kappa[i], 24)] ^
                     T1[get_byte(kappa[idx1], 16)] ^
                     T2[get_byte(kappa[idx2], 8)] ^
                     T3[kappa[idx3] & 0xff]) & 0xffffffff_u32
        end

        kappa[0] = ((T0[4 * round] & 0xff000000_u32) ^
                   (T1[4 * round + 1] & 0x00ff0000_u32) ^
                   (T2[4 * round + 2] & 0x0000ff00_u32) ^
                   (T3[4 * round + 3] & 0x000000ff_u32) ^
                   inter[0]) & 0xffffffff_u32

        (1...@n).each do |i|
          kappa[i] = inter[i]
        end
      end

      # Setup decryption round keys
      @round_key_dec = Array.new(r + 1) { Array(UInt32).new(4, 0_u32) }
      @round_key_dec[0] = @round_key_enc[r]
      @round_key_dec[r] = @round_key_enc[0]

      (1...r).each do |round|
        4.times do |i|
          v = @round_key_enc[r - round][i]
          @round_key_dec[round][i] = (T0[T4[rot(v, 24)] & 0xff] ^
                                      T1[T4[get_byte(v, 16)] & 0xff] ^
                                      T2[T4[get_byte(v, 8)] & 0xff] ^
                                      T3[T4[v & 0xff] & 0xff]) & 0xffffffff_u32
        end
      end
    end

    def encrypt_block(block : Bytes) : Bytes
      crypt_block(block, @round_key_enc)
    end

    def decrypt_block(block : Bytes) : Bytes
      crypt_block(block, @round_key_dec)
    end

    private def crypt_block(block : Bytes, round_key : Array(Array(UInt32))) : Bytes
      raise "Block must be 16 bytes" if block.size != 16

      r = round_key.size - 1
      state = Array(UInt32).new(4, 0_u32)
      inter = Array(UInt32).new(4, 0_u32)

      pos = 0
      4.times do |i|
        state[i] = ((
          (block[pos].to_u32! << 24) |
          (block[pos + 1].to_u32! << 16) |
          (block[pos + 2].to_u32! << 8) |
          block[pos + 3].to_u32!
        ) ^ round_key[0][i]) & 0xffffffff_u32
        pos += 4
      end

      (1...r).each do |round|
        inter[0] = (T0[rot(state[0], 24)] ^ T1[rot(state[1], 24)] ^
                    T2[rot(state[2], 24)] ^ T3[rot(state[3], 24)] ^ round_key[round][0]) & 0xffffffff_u32
        inter[1] = (T0[get_byte(state[0], 16)] ^ T1[get_byte(state[1], 16)] ^
                    T2[get_byte(state[2], 16)] ^ T3[get_byte(state[3], 16)] ^ round_key[round][1]) & 0xffffffff_u32
        inter[2] = (T0[get_byte(state[0], 8)] ^ T1[get_byte(state[1], 8)] ^
                    T2[get_byte(state[2], 8)] ^ T3[get_byte(state[3], 8)] ^ round_key[round][2]) & 0xffffffff_u32
        inter[3] = (T0[state[0] & 0xff] ^ T1[state[1] & 0xff] ^
                    T2[state[2] & 0xff] ^ T3[state[3] & 0xff] ^ round_key[round][3]) & 0xffffffff_u32
        4.times { |i| state[i] = inter[i] }
      end

      inter[0] = ((T0[rot(state[0], 24)] & 0xff000000_u32) ^
                  (T1[rot(state[1], 24)] & 0x00ff0000_u32) ^
                  (T2[rot(state[2], 24)] & 0x0000ff00_u32) ^
                  (T3[rot(state[3], 24)] & 0x000000ff_u32) ^ round_key[r][0]) & 0xffffffff_u32
      inter[1] = ((T0[get_byte(state[0], 16)] & 0xff000000_u32) ^
                  (T1[get_byte(state[1], 16)] & 0x00ff0000_u32) ^
                  (T2[get_byte(state[2], 16)] & 0x0000ff00_u32) ^
                  (T3[get_byte(state[3], 16)] & 0x000000ff_u32) ^ round_key[r][1]) & 0xffffffff_u32
      inter[2] = ((T0[get_byte(state[0], 8)] & 0xff000000_u32) ^
                  (T1[get_byte(state[1], 8)] & 0x00ff0000_u32) ^
                  (T2[get_byte(state[2], 8)] & 0x0000ff00_u32) ^
                  (T3[get_byte(state[3], 8)] & 0x000000ff_u32) ^ round_key[r][2]) & 0xffffffff_u32
      inter[3] = ((T0[state[0] & 0xff] & 0xff000000_u32) ^
                  (T1[state[1] & 0xff] & 0x00ff0000_u32) ^
                  (T2[state[2] & 0xff] & 0x0000ff00_u32) ^
                  (T3[state[3] & 0xff] & 0x000000ff_u32) ^ round_key[r][3]) & 0xffffffff_u32

      result = Bytes.new(16)
      pos = 0
      4.times do |i|
        w = inter[i]
        result[pos] = ((w >> 24) & 0xff).to_u8
        result[pos + 1] = ((w >> 16) & 0xff).to_u8
        result[pos + 2] = ((w >> 8) & 0xff).to_u8
        result[pos + 3] = (w & 0xff).to_u8
        pos += 4
      end

      result
    end
  end

  class GCM
    BLOCK_SIZE = 16

    @cipher : Cipher
    @nonce : Bytes
    @tag_size : Int32
    @ghash_key : UInt128

    def initialize(@cipher, @nonce, @tag_size = 16)
      if @tag_size < 12 || @tag_size > 16
        raise "tag_size must be between 12 and 16 bytes"
      end

      zero_block = Bytes.new(BLOCK_SIZE, 0u8)
      encrypted_zero = @cipher.encrypt_block(zero_block)
      
      @ghash_key = bytes_to_uint128(encrypted_zero)
    end

    private def bytes_to_hex(bytes : Bytes) : String
      bytes.map { |b| b.to_s(16).rjust(2, '0') }.join
    end

    private def bytes_to_uint128(bytes : Bytes) : UInt128
      raise "Bytes must be 16 bytes" if bytes.size != 16
      
      result = 0_u128
      16.times do |i|
        result = (result << 8) | bytes[i].to_u128
      end
      result
    end

    private def uint128_to_bytes(value : UInt128) : Bytes
      bytes = Bytes.new(16)
      16.times do |i|
        bytes[15 - i] = (value & 0xFF).to_u8
        value >>= 8
      end
      bytes
    end

    private def ghash(data : Bytes) : Bytes
      return Bytes.new(BLOCK_SIZE, 0u8) if data.empty?

      # Pad data to multiple of 16 bytes
      data_copy = data
      if data_copy.size % BLOCK_SIZE != 0
        padding = BLOCK_SIZE - (data_copy.size % BLOCK_SIZE)
        temp = Bytes.new(data_copy.size + padding, 0u8)
        data_copy.size.times { |i| temp[i] = data_copy[i] }
        data_copy = temp
      end

      h = @ghash_key
      result = 0_u128

      i = 0
      while i < data_copy.size
        block = Bytes.new(BLOCK_SIZE)
        BLOCK_SIZE.times { |j| block[j] = data_copy[i + j] }
        block_int = bytes_to_uint128(block)
        result ^= block_int
        result = gmult(result, h)
        i += BLOCK_SIZE
      end

      uint128_to_bytes(result)
    end

    private def gmult(x : UInt128, y : UInt128) : UInt128
      z = 0_u128
      v = y
      r = 0xE1000000000000000000000000000000_u128

      128.times do |i|
        if ((x >> (127 - i)) & 1) == 1
          z ^= v
        end

        if (v & 1) == 1
          v >>= 1
          v ^= r
        else
          v >>= 1
        end
      end

      z
    end

    private def inc32(counter_block : Bytes) : Bytes
      counter = (counter_block[12].to_u32 << 24) |
                (counter_block[13].to_u32 << 16) |
                (counter_block[14].to_u32 << 8) |
                counter_block[15].to_u32
      
      counter = (counter + 1) & 0xFFFFFFFF

      result = Bytes.new(16)
      12.times { |i| result[i] = counter_block[i] }
      result[12] = ((counter >> 24) & 0xFF).to_u8
      result[13] = ((counter >> 16) & 0xFF).to_u8
      result[14] = ((counter >> 8) & 0xFF).to_u8
      result[15] = (counter & 0xFF).to_u8

      result
    end

    private def gctr(icb : Bytes, x : Bytes) : Bytes
      return Bytes.new(0) if x.empty?

      n = (x.size + BLOCK_SIZE - 1) // BLOCK_SIZE
      y = Bytes.new(x.size, 0u8)
      cb = Bytes.new(16)
      16.times { |i| cb[i] = icb[i] }

      n.times do |i|
        encrypted_cb = @cipher.encrypt_block(cb)

        block_size = (i == n - 1) ? (x.size % BLOCK_SIZE) : BLOCK_SIZE
        block_size = BLOCK_SIZE if block_size == 0

        x_start = i * BLOCK_SIZE
        y_start = i * BLOCK_SIZE

        block_size.times do |j|
          x_idx = x_start + j
          y_idx = y_start + j
          y[y_idx] = (x[x_idx] ^ encrypted_cb[j]).to_u8
        end

        cb = inc32(cb)
      end

      y
    end

    def encrypt(plaintext : Bytes, associated_data : Bytes = Bytes.new(0)) : {Bytes, Bytes}
      # Generate initial counter block
      if @nonce.size == 12
        icb = Bytes.new(16)
        @nonce.each_with_index { |b, i| icb[i] = b }
        icb[12] = 0u8; icb[13] = 0u8; icb[14] = 0u8; icb[15] = 1u8
      else
        s = (16 - (@nonce.size % 16)) % 16
        nonce_padded = Bytes.new(@nonce.size + s + 16, 0u8)
        
        @nonce.each_with_index { |b, i| nonce_padded[i] = b }
        
        len_nonce = @nonce.size.to_u64 * 8
        pos = @nonce.size + s + 8
        if pos + 7 < nonce_padded.size
          nonce_padded[pos] = ((len_nonce >> 56) & 0xFF).to_u8
          nonce_padded[pos + 1] = ((len_nonce >> 48) & 0xFF).to_u8
          nonce_padded[pos + 2] = ((len_nonce >> 40) & 0xFF).to_u8
          nonce_padded[pos + 3] = ((len_nonce >> 32) & 0xFF).to_u8
          nonce_padded[pos + 4] = ((len_nonce >> 24) & 0xFF).to_u8
          nonce_padded[pos + 5] = ((len_nonce >> 16) & 0xFF).to_u8
          nonce_padded[pos + 6] = ((len_nonce >> 8) & 0xFF).to_u8
          nonce_padded[pos + 7] = (len_nonce & 0xFF).to_u8
        end
        icb = ghash(nonce_padded)
      end

      cb = inc32(icb)
      ciphertext = gctr(cb, plaintext)

      # Compute tag
      len_a = associated_data.size.to_u64 * 8
      len_c = ciphertext.size.to_u64 * 8

      len_block = Bytes.new(16)
      len_block[0] = ((len_a >> 56) & 0xFF).to_u8
      len_block[1] = ((len_a >> 48) & 0xFF).to_u8
      len_block[2] = ((len_a >> 40) & 0xFF).to_u8
      len_block[3] = ((len_a >> 32) & 0xFF).to_u8
      len_block[4] = ((len_a >> 24) & 0xFF).to_u8
      len_block[5] = ((len_a >> 16) & 0xFF).to_u8
      len_block[6] = ((len_a >> 8) & 0xFF).to_u8
      len_block[7] = (len_a & 0xFF).to_u8
      len_block[8] = ((len_c >> 56) & 0xFF).to_u8
      len_block[9] = ((len_c >> 48) & 0xFF).to_u8
      len_block[10] = ((len_c >> 40) & 0xFF).to_u8
      len_block[11] = ((len_c >> 32) & 0xFF).to_u8
      len_block[12] = ((len_c >> 24) & 0xFF).to_u8
      len_block[13] = ((len_c >> 16) & 0xFF).to_u8
      len_block[14] = ((len_c >> 8) & 0xFF).to_u8
      len_block[15] = (len_c & 0xFF).to_u8

      # Pad A and C to block boundaries
      auth_data = associated_data
      if auth_data.size % BLOCK_SIZE != 0
        padding = BLOCK_SIZE - (auth_data.size % BLOCK_SIZE)
        temp = Bytes.new(auth_data.size + padding, 0u8)
        auth_data.size.times { |i| temp[i] = auth_data[i] }
        auth_data = temp
      end

      cipher_data = ciphertext
      if cipher_data.size % BLOCK_SIZE != 0
        padding = BLOCK_SIZE - (cipher_data.size % BLOCK_SIZE)
        temp = Bytes.new(cipher_data.size + padding, 0u8)
        cipher_data.size.times { |i| temp[i] = cipher_data[i] }
        cipher_data = temp
      end

      # GHASH input: A || C || len(A) || len(C)
      ghash_input = Bytes.new(auth_data.size + cipher_data.size + 16, 0u8)
      auth_data.size.times { |i| ghash_input[i] = auth_data[i] }
      
      cipher_data.size.times do |i|
        ghash_input[auth_data.size + i] = cipher_data[i]
      end
      
      16.times do |i|
        ghash_input[auth_data.size + cipher_data.size + i] = len_block[i]
      end

      s = ghash(ghash_input)
      
      tag_full = gctr(icb, s)
      tag = Bytes.new(@tag_size)
      @tag_size.times { |i| tag[i] = tag_full[i] }

      {ciphertext, tag}
    end

    def decrypt(ciphertext : Bytes, tag : Bytes, associated_data : Bytes = Bytes.new(0)) : Bytes?
      expected_tag = compute_tag(ciphertext, associated_data)
      
      return nil unless constant_time_compare(tag, expected_tag)

      if @nonce.size == 12
        icb = Bytes.new(16)
        @nonce.each_with_index { |b, i| icb[i] = b }
        icb[12] = 0u8; icb[13] = 0u8; icb[14] = 0u8; icb[15] = 1u8
      else
        s = (16 - (@nonce.size % 16)) % 16
        nonce_padded = Bytes.new(@nonce.size + s + 16, 0u8)
        
        @nonce.each_with_index { |b, i| nonce_padded[i] = b }
        
        len_nonce = @nonce.size.to_u64 * 8
        pos = @nonce.size + s + 8
        if pos + 7 < nonce_padded.size
          nonce_padded[pos] = ((len_nonce >> 56) & 0xFF).to_u8
          nonce_padded[pos + 1] = ((len_nonce >> 48) & 0xFF).to_u8
          nonce_padded[pos + 2] = ((len_nonce >> 40) & 0xFF).to_u8
          nonce_padded[pos + 3] = ((len_nonce >> 32) & 0xFF).to_u8
          nonce_padded[pos + 4] = ((len_nonce >> 24) & 0xFF).to_u8
          nonce_padded[pos + 5] = ((len_nonce >> 16) & 0xFF).to_u8
          nonce_padded[pos + 6] = ((len_nonce >> 8) & 0xFF).to_u8
          nonce_padded[pos + 7] = (len_nonce & 0xFF).to_u8
        end
        icb = ghash(nonce_padded)
      end

      cb = inc32(icb)
      gctr(cb, ciphertext)
    end

    private def compute_tag(ciphertext : Bytes, associated_data : Bytes) : Bytes
      len_a = associated_data.size.to_u64 * 8
      len_c = ciphertext.size.to_u64 * 8

      len_block = Bytes.new(16)
      len_block[0] = ((len_a >> 56) & 0xFF).to_u8
      len_block[1] = ((len_a >> 48) & 0xFF).to_u8
      len_block[2] = ((len_a >> 40) & 0xFF).to_u8
      len_block[3] = ((len_a >> 32) & 0xFF).to_u8
      len_block[4] = ((len_a >> 24) & 0xFF).to_u8
      len_block[5] = ((len_a >> 16) & 0xFF).to_u8
      len_block[6] = ((len_a >> 8) & 0xFF).to_u8
      len_block[7] = (len_a & 0xFF).to_u8
      len_block[8] = ((len_c >> 56) & 0xFF).to_u8
      len_block[9] = ((len_c >> 48) & 0xFF).to_u8
      len_block[10] = ((len_c >> 40) & 0xFF).to_u8
      len_block[11] = ((len_c >> 32) & 0xFF).to_u8
      len_block[12] = ((len_c >> 24) & 0xFF).to_u8
      len_block[13] = ((len_c >> 16) & 0xFF).to_u8
      len_block[14] = ((len_c >> 8) & 0xFF).to_u8
      len_block[15] = (len_c & 0xFF).to_u8

      # Pad A and C to block boundaries
      auth_data = associated_data
      if auth_data.size % BLOCK_SIZE != 0
        padding = BLOCK_SIZE - (auth_data.size % BLOCK_SIZE)
        temp = Bytes.new(auth_data.size + padding, 0u8)
        auth_data.size.times { |i| temp[i] = auth_data[i] }
        auth_data = temp
      end

      cipher_data = ciphertext
      if cipher_data.size % BLOCK_SIZE != 0
        padding = BLOCK_SIZE - (cipher_data.size % BLOCK_SIZE)
        temp = Bytes.new(cipher_data.size + padding, 0u8)
        cipher_data.size.times { |i| temp[i] = cipher_data[i] }
        cipher_data = temp
      end

      ghash_input = Bytes.new(auth_data.size + cipher_data.size + 16, 0u8)
      auth_data.size.times { |i| ghash_input[i] = auth_data[i] }
      
      cipher_data.size.times do |i|
        ghash_input[auth_data.size + i] = cipher_data[i]
      end
      
      16.times do |i|
        ghash_input[auth_data.size + cipher_data.size + i] = len_block[i]
      end

      s = ghash(ghash_input)
      
      if @nonce.size == 12
        icb = Bytes.new(16)
        @nonce.each_with_index { |b, i| icb[i] = b }
        icb[12] = 0u8; icb[13] = 0u8; icb[14] = 0u8; icb[15] = 1u8
      else
        s_val = (16 - (@nonce.size % 16)) % 16
        nonce_padded = Bytes.new(@nonce.size + s_val + 16, 0u8)
        @nonce.each_with_index { |b, i| nonce_padded[i] = b }
        len_nonce = @nonce.size.to_u64 * 8
        pos = @nonce.size + s_val + 8
        if pos + 7 < nonce_padded.size
          nonce_padded[pos] = ((len_nonce >> 56) & 0xFF).to_u8
          nonce_padded[pos + 1] = ((len_nonce >> 48) & 0xFF).to_u8
          nonce_padded[pos + 2] = ((len_nonce >> 40) & 0xFF).to_u8
          nonce_padded[pos + 3] = ((len_nonce >> 32) & 0xFF).to_u8
          nonce_padded[pos + 4] = ((len_nonce >> 24) & 0xFF).to_u8
          nonce_padded[pos + 5] = ((len_nonce >> 16) & 0xFF).to_u8
          nonce_padded[pos + 6] = ((len_nonce >> 8) & 0xFF).to_u8
          nonce_padded[pos + 7] = (len_nonce & 0xFF).to_u8
        end
        icb = ghash(nonce_padded)
      end

      tag_full = gctr(icb, s)
      tag = Bytes.new(@tag_size)
      @tag_size.times { |i| tag[i] = tag_full[i] }
      tag
    end

    private def constant_time_compare(a : Bytes, b : Bytes) : Bool
      return false if a.size != b.size
      result = 0
      a.size.times { |i| result |= a[i] ^ b[i] }
      result == 0
    end

    def nonce : Bytes
      @nonce
    end
  end

  class AEAD
    @key : Bytes
    @cipher : Cipher

    def initialize(@key)
      @cipher = Cipher.new(@key)
    end

    def nonce_size : Int32
      12
    end

    def overhead : Int32
      16
    end

    def seal(nonce : Bytes, plaintext : Bytes, associated_data : Bytes = Bytes.new(0)) : Bytes
      gcm = GCM.new(@cipher, nonce)
      ciphertext, tag = gcm.encrypt(plaintext, associated_data)
      
      result = Bytes.new(ciphertext.size + tag.size)
      ciphertext.size.times { |i| result[i] = ciphertext[i] }
      tag.size.times { |i| result[ciphertext.size + i] = tag[i] }
      result
    end

    def open(nonce : Bytes, ciphertext : Bytes, associated_data : Bytes = Bytes.new(0)) : Bytes?
      return nil if ciphertext.size < 16

      tag = Bytes.new(16)
      ciphertext_only = Bytes.new(ciphertext.size - 16, 0u8)
      
      (ciphertext.size - 16).times { |i| ciphertext_only[i] = ciphertext[i] }
      16.times { |i| tag[i] = ciphertext[ciphertext.size - 16 + i] }

      gcm = GCM.new(@cipher, nonce)
      gcm.decrypt(ciphertext_only, tag, associated_data)
    end
  end
end

# ====================================================================
# SHA3-256 Implementation (based on SHAKE256 but with correct padding)
# ====================================================================

module SHA3
  RATE = 136
  OUTPUT_SIZE = 32

  RC = [
    0x0000000000000001_u64, 0x0000000000008082_u64,
    0x800000000000808A_u64, 0x8000000080008000_u64,
    0x000000000000808B_u64, 0x0000000080000001_u64,
    0x8000000080008081_u64, 0x8000000000008009_u64,
    0x000000000000008A_u64, 0x0000000000000088_u64,
    0x0000000080008009_u64, 0x000000008000000A_u64,
    0x000000008000808B_u64, 0x800000000000008B_u64,
    0x8000000000008089_u64, 0x8000000000008003_u64,
    0x8000000000008002_u64, 0x8000000000000080_u64,
    0x000000000000800A_u64, 0x800000008000000A_u64,
    0x8000000080008081_u64, 0x8000000000008080_u64,
    0x0000000080000001_u64, 0x8000000080008008_u64,
  ]

  ROT = [
    [  0, 36,  3, 41, 18 ],
    [  1, 44, 10, 45,  2 ],
    [ 62,  6, 43, 15, 61 ],
    [ 28, 55, 25, 21, 56 ],
    [ 27, 20, 39,  8, 14 ],
  ]

  def self.rotl(x : UInt64, n : Int32) : UInt64
    ((x << n) | (x >> (64 - n)))
  end

  def self.keccak_f(state : Array(UInt64))
    24.times do |round|
      # Theta
      c = Array(UInt64).new(5) { |i|
        state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
      }
      d = Array(UInt64).new(5) { |i|
        c[(i+4)%5] ^ rotl(c[(i+1)%5], 1)
      }
      5.times do |i|
        5.times do |j|
          state[i + 5*j] ^= d[i]
        end
      end

      # Rho + Pi
      b = Array(UInt64).new(25, 0_u64)
      5.times do |x|
        5.times do |y|
          b[y + 5*((2*x + 3*y) % 5)] = rotl(state[x + 5*y], ROT[x][y])
        end
      end

      # Chi
      5.times do |x|
        5.times do |y|
          state[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
        end
      end

      # Iota
      state[0] ^= RC[round]
    end
  end

  def self.sha3_256(data : Bytes) : Bytes
    state = Array(UInt64).new(25, 0_u64)

    offset = 0
    data_size = data.size
    
    # Absorption
    while offset + RATE <= data_size
      block = data[offset, RATE]
      RATE.times do |i|
        state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
      end
      keccak_f(state)
      offset += RATE
    end

    # Padding for SHA3-256 (different from SHAKE!)
    block = Bytes.new(RATE, 0_u8)
    remaining = data_size - offset
    remaining.times { |i| block[i] = data[offset + i] }
    
    # SHA3-256 uses padding 0x06 (different from SHAKE which uses 0x1F)
    block[remaining] ^= 0x06
    block[RATE - 1] ^= 0x80

    RATE.times do |i|
      state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
    end
    keccak_f(state)

    # Squeeze (only 32 bytes for SHA3-256)
    output = Bytes.new(OUTPUT_SIZE)
    OUTPUT_SIZE.times do |i|
      lane = i // 8
      shift = 8 * (i % 8)
      output[i] = ((state[lane] >> shift) & 0xFF).to_u8
    end

    output
  end
end

# ====================================================================
# HMAC with SHA3-256
# ====================================================================

module HMAC
  BLOCK_SIZE = 136

  def self.hmac(key : Bytes, data : Bytes) : Bytes
    if key.size > BLOCK_SIZE
      key = SHA3.sha3_256(key)
    end

    if key.size < BLOCK_SIZE
      padded = Bytes.new(BLOCK_SIZE, 0_u8)
      key.each_with_index { |b, i| padded[i] = b }
      key = padded
    end

    ipad = Bytes.new(BLOCK_SIZE) { |i| (key[i] ^ 0x36).to_u8 }
    opad = Bytes.new(BLOCK_SIZE) { |i| (key[i] ^ 0x5C).to_u8 }

    inner = SHA3.sha3_256(ipad + data)
    SHA3.sha3_256(opad + inner)
  end
end

# ====================================================================
# HKDF with SHA3-256
# ====================================================================

module HKDF
  HASH_LEN = 32

  def self.hkdf(ikm : Bytes, length : Int32, salt : Bytes? = nil, info : Bytes = Bytes.empty) : Bytes
    salt ||= Bytes.new(HASH_LEN, 0_u8)

    # Extract
    prk = HMAC.hmac(salt, ikm)

    # Expand
    n = (length + HASH_LEN - 1) // HASH_LEN
    raise "length too large" if n > 255

    t = Bytes.empty
    okm = Bytes.new(0)

    1.upto(n) do |i|
      counter = Bytes[ i.to_u8 ]
      t = HMAC.hmac(prk, t + info + counter)
      okm += t
    end

    okm[0, length]
  end
end

# ====================================================================
# Recursive directory hashing with SHA3-256
# ====================================================================

def hash_file_sha3(path : String) : String
  data = File.read(path).to_slice
  bytes_to_hex(SHA3.sha3_256(data))
end

def hash_directory_sha3(path : String, recursive : Bool) : String
  entries = [] of String
  
  Dir.each_child(path) do |entry|
    next if entry == "." || entry == ".."
    
    full_path = File.join(path, entry)
    if File.directory?(full_path)
      if recursive
        # Hash subdirectory (recursive)
        sub_hash = hash_directory_sha3(full_path, recursive)
        entries << "#{entry}/:#{sub_hash}"
      end
    else
      # Hash file
      entries << "#{entry}:#{hash_file_sha3(full_path)}"
    end
  end
  
  # Sort for consistency
  entries.sort!
  
  # Concatenate and hash the final result
  combined = entries.join("\n").to_slice
  bytes_to_hex(SHA3.sha3_256(combined))
end

def hash_path_sha3(path : String, recursive : Bool) : String
  if File.directory?(path)
    hash_directory_sha3(path, recursive)
  else
    hash_file_sha3(path)
  end
end

# ====================================================================
# CLI (complete version with all functionalities)
# ====================================================================

VERSION = "1.0.0"
COPYRIGHT = "ALBANESE Research Lab"

class Config
  property command : String = ""
  property subcommand : String = ""
  property priv : String? = nil
  property pub : String? = nil
  property input_file : String? = nil
  property text : String? = nil
  property output_file : String? = nil
  property sig : String? = nil
  property proof : String? = nil
  property password : String? = nil
  property new_password : String? = nil
  property name : String = "key"
  property out_dir : String = "."
  property debug : Bool = false
  property key : String? = nil
  property aad : String? = nil
  property peer_key : String? = nil
  property len : Int32? = nil
  property salt : String? = nil
  property info : String? = nil
  property recursive : Bool = false
end

config = Config.new

def print_short_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto <command> [options]"
  puts ""
  puts "Available commands:"
  puts "  ed521                         E-521 curve for signatures and ZKP"
  puts "  x448                          X448 curve for key exchange"
  puts "  anubis                        Anubis-GCM cipher for encryption"
  puts "  hmac                          Generate HMAC-SHA3-256"
  puts "  hkdf                          Derive key with HKDF-SHA3-256"
  puts "  hash                          Generate SHA3-256 hash of file(s)"
  puts "  check                         Verify files with SHA3-256 checklist"
  puts "  change-password               Change private key password"
  puts ""
  puts "For more details, use: ./crypto help <command>"
  exit
end

def print_ed521_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto ed521 <command> [options]"
  puts ""
  puts "ED521 commands:"
  puts "  keygen                        Generate ED521 key pair"
  puts "    --priv FILE                 File to save private key"
  puts "    --pub FILE                  File to save public key"
  puts "    --password PASSWORD         Encrypt private key with password"
  puts ""
  puts "  sign                          Sign message with ED521"
  puts "    --priv FILE                 Private key file"
  puts "    --file FILE                 File to sign"
  puts "    --text TEXT                 Text to sign"
  puts "    --output FILE               File to save signature"
  puts "    --sig HEX                   Signature in hex (output)"
  puts "    --password PASSWORD         Private key password"
  puts ""
  puts "  verify                        Verify ED521 signature"
  puts "    --pub FILE                  Public key file"
  puts "    --file FILE                 File to verify"
  puts "    --text TEXT                 Text to verify"
  puts "    --sig HEX                   Signature in hex (input)"
  puts ""
  puts "  prove                         Generate ZKP proof of key knowledge"
  puts "    --priv FILE                 Private key file"
  puts "    --output FILE               File to save proof"
  puts "    --proof HEX                 Proof in hex (output)"
  puts "    --password PASSWORD         Private key password"
  puts ""
  puts "  verify-proof                  Verify ZKP proof"
  puts "    --pub FILE                  Public key file"
  puts "    --proof HEX                 Proof in hex (input)"
  exit
end

def print_x448_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto x448 <command> [options]"
  puts ""
  puts "X448 commands:"
  puts "  keygen                        Generate X448 key pair"
  puts "    --priv FILE                 File to save private key"
  puts "    --pub FILE                  File to save public key"
  puts "    --password PASSWORD         Encrypt private key with password"
  puts ""
  puts "  shared                        Calculate X448 shared secret"
  puts "    --priv FILE                 Private key file"
  puts "    --peer-key FILE             Peer's public key file"
  puts "    --output FILE               File to save secret"
  puts "    --password PASSWORD         Private key password"
  exit
end

def print_anubis_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto anubis <command> [options]"
  puts ""
  puts "Anubis commands:"
  puts "  encrypt                       Encrypt with Anubis-GCM"
  puts "    --key VALUE                 Key (file or hex)"
  puts "    --file FILE                 File to encrypt"
  puts "    --text TEXT                 Text to encrypt"
  puts "    --output FILE               Output file"
  puts "    --aad TEXT                  Additional Authenticated Data"
  puts ""
  puts "  decrypt                       Decrypt with Anubis-GCM"
  puts "    --key VALUE                 Key (file or hex)"
  puts "    --file FILE                 File to decrypt"
  puts "    --output FILE               Output file"
  puts "    --aad TEXT                  Additional Authenticated Data"
  exit
end

def print_hmac_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto hmac [options]"
  puts ""
  puts "Options:"
  puts "  --key VALUE                   Key (string)"
  puts "  --file FILE                   File to authenticate"
  puts "  --text TEXT                   Text to authenticate"
  exit
end

def print_hkdf_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto hkdf [options]"
  puts ""
  puts "Options:"
  puts "  --key VALUE                   IKM (string)"
  puts "  --len N                       Output size in bytes"
  puts "  --salt VALUE                  Salt (string, optional)"
  puts "  --info TEXT                   Info (optional)"
  exit
end

def print_hash_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto hash [options]"
  puts ""
  puts "Options:"
  puts "  --file FILE                   File(s) to hash (use * for multiple)"
  puts "  --text TEXT                   Text to hash"
  puts "  --recursive                   For directories, hash recursively"
  exit
end

def print_check_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto check [options]"
  puts ""
  puts "Options:"
  puts "  --file FILE                   Checklist file"
  puts ""
  puts "Or use pipe:"
  puts "  ./crypto hash --file * | ./crypto check"
  exit
end

def print_change_password_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto change-password [options]"
  puts ""
  puts "Options:"
  puts "  --priv FILE                   Private key file"
  puts "  --password PASSWORD           Current password"
  puts "  --new-password PASSWORD       New password"
  exit
end

def print_long_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto <command> [options]"
  puts ""
  puts "Available commands:"
  puts "  ed521                         E-521 curve for signatures and ZKP"
  puts "  x448                          X448 curve for key exchange"
  puts "  anubis                        Anubis-GCM cipher for encryption"
  puts "  hmac                          Generate HMAC-SHA3-256"
  puts "  hkdf                          Derive key with HKDF-SHA3-256"
  puts "  hash                          Generate SHA3-256 hash of file(s)"
  puts "  check                         Verify files with SHA3-256 checklist"
  puts "  change-password               Change ED521 private key password"
  puts ""
  puts "For specific help:"
  puts "  ./crypto help ed521"
  puts "  ./crypto help x448"
  puts "  ./crypto help anubis"
  puts "  ./crypto help hmac"
  puts "  ./crypto help hkdf"
  puts "  ./crypto help hash"
  puts "  ./crypto help check"
  puts "  ./crypto help change-password"
  exit
end

if ARGV.size == 0
  print_short_help
end

parser = OptionParser.new

parser.on("--priv FILE", "Private key file") { |f| config.priv = f }
parser.on("--pub FILE", "Public key file") { |f| config.pub = f }
parser.on("--file FILE", "File to process") { |f| config.input_file = f }
parser.on("--text TEXT", "Text to process") { |t| config.text = t }
parser.on("--output FILE", "Output file") { |o| config.output_file = o }
parser.on("--sig HEX", "Signature in hexadecimal") { |h| config.sig = h }
parser.on("--proof HEX", "ZKP proof in hexadecimal") { |h| config.proof = h }
parser.on("--password PASSWORD", "Password") { |p| config.password = p }
parser.on("--new-password PASSWORD", "New password") { |p| config.new_password = p }
parser.on("--debug", "Debug mode") { config.debug = true }
parser.on("--key VALUE", "Key (string) for HMAC/HKDF") { |v| config.key = v }
parser.on("--aad TEXT", "Additional Authenticated Data") { |a| config.aad = a }
parser.on("--peer-key FILE", "Peer's public key file") { |p| config.peer_key = p }
parser.on("--len N", "Output size in bytes") { |n| config.len = n.to_i }
parser.on("--salt VALUE", "Salt for HKDF (string)") { |s| config.salt = s }
parser.on("--info TEXT", "Info for HKDF") { |i| config.info = i }
parser.on("--recursive", "For directories, hash recursively") { config.recursive = true }
parser.on("-h", "--help", "Show help") { 
  if config.command.empty?
    print_long_help
  else
    case config.command
    when "ed521" then print_ed521_help
    when "x448" then print_x448_help
    when "anubis" then print_anubis_help
    when "hmac" then print_hmac_help
    when "hkdf" then print_hkdf_help
    when "hash" then print_hash_help
    when "check" then print_check_help
    when "change-password" then print_change_password_help
    else print_long_help
    end
  end
  exit
}

begin
  parser.parse
  
  if ARGV.size >= 1
    config.command = ARGV[0]
  else
    print_short_help
  end
  
  config.subcommand = ARGV.size >= 2 ? ARGV[1] : ""
  
  # Validate main commands
  if ["ed521", "x448", "anubis"].includes?(config.command) && config.subcommand.empty?
    puts "Error: #{config.command} requires a subcommand"
    puts "Use: ./crypto help #{config.command} for more information"
    exit 1
  end
rescue ex
  STDERR.puts "Error: #{ex.message}"
  exit 1
end

def get_message_data(config : Config) : Bytes
  if config.text && config.input_file
    raise "Error: use --text OR --file, not both"
  elsif config.text
    config.text.not_nil!.to_slice
  elsif config.input_file
    if config.input_file == "-"
      STDIN.gets_to_end.to_slice
    else
      File.read(config.input_file.not_nil!).to_slice
    end
  else
    raise "Error: provide --text or --file"
  end
end

def ensure_dir(dir : String)
  Dir.mkdir_p(dir) unless Dir.exists?(dir)
end

def read_key_from_string(key_str : String) : Bytes
  if File.exists?(key_str)
    content = File.read(key_str).strip
    if content.size == 32 || content.size == 64 || content.size == 128
      begin
        return hex_to_bytes(content)
      rescue
        return content.to_slice
      end
    else
      return content.to_slice
    end
  else
    begin
      return hex_to_bytes(key_str)
    rescue
      return key_str.to_slice
    end
  end
end

# ====================================================================
# Helper functions for file hashing
# ====================================================================

def hash_file_sha3(path : String) : String
  data = File.read(path).to_slice
  bytes_to_hex(SHA3.sha3_256(data))
end

def hash_directory_sha3(path : String, recursive : Bool) : String
  entries = [] of String
  
  Dir.each_child(path) do |entry|
    next if entry == "." || entry == ".."
    
    full_path = File.join(path, entry)
    if File.directory?(full_path)
      if recursive
        # Hash subdirectory (recursive)
        sub_hash = hash_directory_sha3(full_path, recursive)
        entries << "#{entry}/:#{sub_hash}"
      end
    else
      # Hash file
      entries << "#{entry}:#{hash_file_sha3(full_path)}"
    end
  end
  
  # Sort for consistency
  entries.sort!
  
  # Concatenate and hash the final result
  combined = entries.join("\n").to_slice
  bytes_to_hex(SHA3.sha3_256(combined))
end

def hash_path_sha3(path : String, recursive : Bool) : String
  if File.directory?(path)
    hash_directory_sha3(path, recursive)
  else
    hash_file_sha3(path)
  end
end

# ====================================================================
# Command execution
# ====================================================================

case config.command
when "ed521"
  case config.subcommand
  when "keygen"
    if config.priv.nil? || config.pub.nil?
      STDERR.puts "Error: keygen requires --priv and --pub"
      exit 1
    end
    
    ensure_dir(File.dirname(config.priv.not_nil!))
    ensure_dir(File.dirname(config.pub.not_nil!))
    
    password = config.password
    
    puts "Generating ED521 key pair..."
    
    private_key = generate_private_key
    pub_x, pub_y = get_public_key(private_key)
    
    if password
      private_pem = private_key_to_pem_encrypted(private_key, password)
      puts "Private key encrypted with Curupira192-CBC"
    else
      private_pem = private_key_to_pem_unencrypted(private_key)
    end
    
    public_pem = public_key_to_pem(pub_x, pub_y)
    
    File.write(config.priv.not_nil!, private_pem)
    File.write(config.pub.not_nil!, public_pem)
    
    puts "OK: ED521 key pair generated:"
    puts "  Private: #{config.priv}" + (password ? " (encrypted)" : "")
    puts "  Public: #{config.pub}"
    
    exit 0
    
  when "sign"
    if config.priv.nil?
      STDERR.puts "Error: sign requires --priv"
      exit 1
    end
    
    begin
      msg = get_message_data(config)
      
      pem = File.read(config.priv.not_nil!)
      is_encrypted = pem.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = parse_private_key_pem(pem, password)
      
      signature = sign(private_key, msg)
      
      if config.output_file
        File.write(config.output_file.not_nil!, signature)
        puts "ED521 signature saved to: #{config.output_file}"
      elsif config.sig
        File.write(config.sig.not_nil!, bytes_to_hex(signature))
        puts "ED521 signature saved to: #{config.sig}"
      else
        puts bytes_to_hex(signature)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "verify"
    if config.pub.nil?
      STDERR.puts "Error: verify requires --pub"
      exit 1
    end
    
    if config.sig.nil?
      STDERR.puts "Error: verify requires --sig"
      exit 1
    end
    
    begin
      msg = get_message_data(config)
      
      pem = File.read(config.pub.not_nil!)
      pub_x, pub_y = parse_public_key_pem(pem)
      
      signature = hex_to_bytes(config.sig.not_nil!)
      
      valid = verify(pub_x, pub_y, msg, signature)
      
      if valid
        puts "ED521 SIGNATURE VALID"
        exit 0
      else
        puts "ED521 SIGNATURE INVALID"
        exit 1
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "prove"
    if config.priv.nil?
      STDERR.puts "Error: prove requires --priv"
      exit 1
    end
    
    begin
      pem = File.read(config.priv.not_nil!)
      is_encrypted = pem.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = parse_private_key_pem(pem, password)
      
      proof = prove_knowledge(private_key)
      
      if config.output_file
        File.write(config.output_file.not_nil!, proof)
        puts "ED521 ZKP proof saved to: #{config.output_file}"
      elsif config.proof
        File.write(config.proof.not_nil!, bytes_to_hex(proof))
        puts "ED521 ZKP proof saved to: #{config.proof}"
      else
        puts bytes_to_hex(proof)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "verify-proof"
    if config.pub.nil?
      STDERR.puts "Error: verify-proof requires --pub"
      exit 1
    end
    
    if config.proof.nil?
      STDERR.puts "Error: verify-proof requires --proof"
      exit 1
    end
    
    begin
      pem = File.read(config.pub.not_nil!)
      pub_x, pub_y = parse_public_key_pem(pem)
      
      proof = hex_to_bytes(config.proof.not_nil!)
      
      valid = verify_knowledge(pub_x, pub_y, proof)
      
      if valid
        puts "ED521 ZKP PROOF VALID"
        exit 0
      else
        puts "ED521 ZKP PROOF INVALID"
        exit 1
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown ED521 command: #{config.subcommand}"
    puts "Use: ./crypto help ed521"
    exit 1
  end

when "x448"
  case config.subcommand
  when "keygen"
    if config.priv.nil? || config.pub.nil?
      STDERR.puts "Error: keygen requires --priv and --pub"
      exit 1
    end
    
    ensure_dir(File.dirname(config.priv.not_nil!))
    ensure_dir(File.dirname(config.pub.not_nil!))
    
    password = config.password
    
    puts "Generating X448 key pair..."
    
    private_key = x448_generate_private_key
    public_key = x448_get_public_key(private_key)
    
    private_pem = x448_private_to_pem_pkcs8(private_key, password)
    public_pem = x448_public_to_pem(public_key)
    
    File.write(config.priv.not_nil!, private_pem)
    File.write(config.pub.not_nil!, public_pem)
    
    puts "OK: X448 key pair generated:"
    puts "  Private: #{config.priv}" + (password ? " (encrypted)" : "")
    puts "  Public: #{config.pub}"
    
    exit 0
    
  when "shared"
    if config.priv.nil?
      STDERR.puts "Error: shared requires --priv"
      exit 1
    end
    
    if config.peer_key.nil?
      STDERR.puts "Error: shared requires --peer-key"
      exit 1
    end
    
    begin
      pem_content = File.read(config.priv.not_nil!).strip
      is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = parse_x448_private_key_pem(pem_content, password)
      
      peer_pem = File.read(config.peer_key.not_nil!).strip
      peer_key = parse_x448_public_key_pem(peer_pem)
      
      shared = x448_shared_secret(private_key, peer_key)
      
      if config.output_file
        File.write(config.output_file.not_nil!, bytes_to_hex(shared))
        puts "X448 shared secret saved to: #{config.output_file}"
      else
        puts bytes_to_hex(shared)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown X448 command: #{config.subcommand}"
    puts "Use: ./crypto help x448"
    exit 1
  end

when "anubis"
  case config.subcommand
  when "encrypt"
    if config.key.nil?
      STDERR.puts "Error: encrypt requires --key"
      exit 1
    end
    
    begin
      key_data = read_key_from_string(config.key.not_nil!)
      
      nonce = Random::Secure.random_bytes(12)
      
      aad = config.aad ? config.aad.not_nil!.to_slice : Bytes.new(0)
      plaintext = get_message_data(config)
      
      anubis = Anubis::AEAD.new(key_data)
      ciphertext_with_tag = anubis.seal(nonce, plaintext, aad)
      
      output = Bytes.new(nonce.size + ciphertext_with_tag.size)
      nonce.size.times { |i| output[i] = nonce[i] }
      ciphertext_with_tag.size.times { |i| output[nonce.size + i] = ciphertext_with_tag[i] }
      
      if config.output_file
        File.write(config.output_file.not_nil!, output)
        puts "Anubis-GCM encrypted data saved to: #{config.output_file}"
      else
        STDOUT.write(output)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "decrypt"
    if config.key.nil?
      STDERR.puts "Error: decrypt requires --key"
      exit 1
    end
    
    begin
      key_data = read_key_from_string(config.key.not_nil!)
      
      encrypted_data = get_message_data(config)
      
      if encrypted_data.size < 28
        STDERR.puts "Error: invalid encrypted data"
        exit 1
      end
      
      nonce = encrypted_data[0, 12]
      ciphertext_with_tag = encrypted_data[12..-1]
      
      aad = config.aad ? config.aad.not_nil!.to_slice : Bytes.new(0)
      
      anubis = Anubis::AEAD.new(key_data)
      plaintext = anubis.open(nonce, ciphertext_with_tag, aad)
      
      if plaintext.nil?
        STDERR.puts "Anubis-GCM DECRYPTION FAILED: invalid tag"
        exit 1
      end
      
      if config.output_file
        File.write(config.output_file.not_nil!, plaintext)
        puts "Anubis-GCM decrypted data saved to: #{config.output_file}"
      else
        STDOUT.write(plaintext)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown Anubis command: #{config.subcommand}"
    puts "Use: ./crypto help anubis"
    exit 1
  end

when "hmac"
    if config.key.nil?
        STDERR.puts "Error: hmac requires --key"
        exit 1
    end
    
    if config.input_file.nil? && config.text.nil?
        STDERR.puts "Error: hmac requires --file or --text"
        exit 1
    end
    
    key_data = config.key.not_nil!.to_slice
    data = get_message_data(config)
    
    mac = HMAC.hmac(key_data, data)
    puts bytes_to_hex(mac)

when "hkdf"
    if config.key.nil?
        STDERR.puts "Error: hkdf requires --key"
        exit 1
    end
    
    if config.len.nil?
        STDERR.puts "Error: hkdf requires --len"
        exit 1
    end
    
    ikm = config.key.not_nil!.to_slice
    salt = config.salt ? config.salt.not_nil!.to_slice : nil
    info = config.info ? config.info.not_nil!.to_slice : Bytes.empty
    
    okm = HKDF.hkdf(ikm, config.len.not_nil!, salt, info)
    puts bytes_to_hex(okm)

when "hash"
    if config.input_file.nil? && config.text.nil?
        STDERR.puts "Error: hash requires --file or --text"
        exit 1
    end
    
    if config.text
        data = config.text.not_nil!.to_slice
        puts bytes_to_hex(SHA3.sha3_256(data))
    else
        pattern = config.input_file.not_nil!
        
        if config.recursive
            if pattern.includes?('/')
                pattern = File.join(pattern, "**", "*")
            else
                pattern = "**/#{pattern}"
            end
        end
        
        files = Dir.glob(pattern).sort
        
        if files.empty?
            STDERR.puts "Error: No files found: #{config.input_file.not_nil!}"
            exit 1
        end
        
        files.each do |file|
            if File.directory?(file)
                next
            else
                hash = hash_file_sha3(file)
                puts "#{hash} *#{file}"
            end
        end
    end

when "check"
    if config.input_file.nil? && STDIN.tty?
        STDERR.puts "Error: check requires --file or pipe input"
        exit 1
    end
    
    checklist = if config.input_file
                   File.read_lines(config.input_file.not_nil!)
                else
                   STDIN.each_line.to_a
                end
    
    errors = 0
    total = 0
    
    checklist.each do |line|
        line = line.strip
        next if line.empty?
        
        if line.includes?('*')
            parts = line.split('*', 2)
            expected_hash = parts[0].strip
            file_path = parts[1].strip
        else
            parts = line.split(' ', 2)
            next if parts.size != 2
            expected_hash = parts[0].strip
            file_path = parts[1].strip
        end
        
        total += 1
        
        if File.exists?(file_path)
            actual_hash = hash_file_sha3(file_path)
            if actual_hash == expected_hash
                puts "#{file_path}: OK"
            else
                puts "#{file_path}: FAILED"
                errors += 1
            end
        else
            puts "#{file_path}: File not found"
            errors += 1
        end
    end
    
    if errors == 0
        puts "All #{total} files verified successfully."
        exit 0
    else
        puts "#{errors} of #{total} files failed verification."
        exit 1
    end

when "change-password"
  if config.priv.nil?
    STDERR.puts "Error: change-password requires --priv"
    exit 1
  end
  
  begin
    pem = File.read(config.priv.not_nil!)
    
    old_password = config.password
    if old_password.nil?
      STDERR.puts "Error: provide --password"
      exit 1
    end
    
    private_key = parse_private_key_pem(pem, old_password)
    
    new_password = config.new_password
    if new_password.nil?
      STDERR.puts "Error: provide --new-password"
      exit 1
    end
    
    new_pem = private_key_to_pem_encrypted(private_key, new_password)
    
    backup_file = "#{config.priv}.bak"
    File.copy(config.priv.not_nil!, backup_file)
    puts "Backup saved to: #{backup_file}"
    
    File.write(config.priv.not_nil!, new_pem)
    puts "Password changed successfully"
    
  rescue e
    STDERR.puts "Error: #{e.message}"
    exit 1
  end

when "help"
  if config.subcommand.empty?
    print_long_help
  else
    case config.subcommand
    when "ed521" then print_ed521_help
    when "x448" then print_x448_help
    when "anubis" then print_anubis_help
    when "hmac" then print_hmac_help
    when "hkdf" then print_hkdf_help
    when "hash" then print_hash_help
    when "check" then print_check_help
    when "change-password" then print_change_password_help
    else
      puts "Help not available for: #{config.subcommand}"
      print_long_help
    end
  end
  exit 0

else
  puts "Unknown command: #{config.command}"
  puts "Use ./crypto help for assistance"
  exit 1
end
