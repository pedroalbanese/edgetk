# Security Policy

## Security Assurance

The EDGETk toolkit was developed by a security engineer and includes over 140 widely recognized cryptographic algorithms. Despite not having undergone a formal third-party audit yet, its correctness and security posture can be reasonably assured based on several strong indicators:

- **Interoperability with Standard Tools:**  
  EDGETk is fully compatible with widely used cryptographic toolkits such as OpenSSL, LibreSSL, and GmSSL. This ensures that its key formats, ciphertexts, hashes, and digital signatures can be validated against independent implementations.

- **Initialization Vector and Parameter Compatibility:**  
  All implemented algorithms conform to the expected behavior defined in standard documentation. EDGETk consistently produces correct outputs when tested against standardized test vectors (e.g., NIST, ISO, GOST, SM series), demonstrating adherence to cryptographic specifications.

- **Cross-Platform Determinism:**  
  The toolkit has been tested on multiple architectures (x86, ARM) and operating systems (Linux, Windows, FreeBSD), consistently yielding identical outputs for the same inputs, which strongly supports implementation correctness.

- **Protocol-Level Validation:**  
  The TLS 1.3 and TLCP implementations have been tested in real-world scenarios and communicate successfully with compliant clients and servers, further reinforcing protocol-level correctness.

While independent auditing remains an important future milestone, the high degree of compatibility, adherence to international standards, and deterministic behavior across platforms provide strong practical evidence of correctness and reliability in EDGETk's cryptographic implementations.

## Reporting a Vulnerability

Please send a mail to pedroalbanese@hotmail.com when you found a security issue in EDGETk, even when you are not 100% certain 
that it is actually a security issue. Typically, you will receive an answer within a day or even within a few hours.
