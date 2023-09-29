#!/usr/bin/wish

# Create a new window
wm title . "EDGE Bulk Encryption Tool written in TCL/TK"
#wm geometry . 880x580

# Create a frame for the top section with a gray background
frame .topFrame2 -background gray90 -bd 1 -relief solid
grid .topFrame2 -row 0 -column 2 -rowspan 2 -columnspan 6 -sticky "nsew"

# Create a frame for the top section with a gray background2
frame .topFrame -background gray90 -bd 1 -relief solid
grid .topFrame -row 0 -column 0 -rowspan 2 -columnspan 2 -sticky "nsew"

# Create a frame for the top section with a gray background3
frame .topFrame3 -background gray90 -bd 1 -relief solid
grid .topFrame3 -row 2 -column 0 -rowspan 4 -columnspan 8 -sticky "nsew"

# Create a frame for the botton section with a gray background2
frame .bottonFrame -background gray90 -bd 1 -relief solid
grid .bottonFrame -row 6 -column 0 -rowspan 2 -columnspan 8 -sticky "nsew"

# Create Algorithm label
label .algorithmLabel -text "Algorithm:"
grid .algorithmLabel -row 0 -column 0 -sticky e -padx 10 -pady 5

# Create Algorithm ComboBox with "aes" as default value
ttk::combobox .algorithmCombo -values {"3des" "aes" "anubis" "aria" "blowfish" "camellia" "cast5" "chacha20" "chacha20poly1305" "gost89" "hc128" "hc256" "idea" "kcipher2" "kuznechik" "lea" "magma" "misty1" "rc2" "rc4" "rc5" "salsa20" "seed" "serpent" "skein512" "sm4" "threefish" "twofish" "xoodyak" "zuc128" "zuc256"} -width 30
.algorithmCombo set "aes"
grid .algorithmCombo -row 0 -column 1 -sticky w -padx 10 -pady 5

# Create KDF checkbox for Algorithm
checkbutton .kdfAlgorithmCheckbox -background gray90 -text "Use KDF (pbkdf2)" -variable ::useKDFAlgorithm
grid .kdfAlgorithmCheckbox -row 0 -column 4 -sticky w -padx 10 -pady 5

# Create Mode label
label .modeLabel -text "Mode:"
grid .modeLabel -row 1 -column 0 -sticky e -padx 10 -pady 5

# Create Mode ComboBox with "CTR" as default value
ttk::combobox .modeCombo -values {"eax" "gcm" "ocb1" "ocb3" "mgm" "ccm" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"} -width 30
.modeCombo set "ctr"
grid .modeCombo -row 1 -column 1 -sticky w -padx 10 -pady 5

# Create "Salt" label
label .saltLabel -text "Salt:"
grid .saltLabel -row 0 -column 2 -sticky e -padx 10 -pady 5

# Create "Salt" input box
entry .saltBox -width 30
grid .saltBox -row 0 -column 3 -sticky w -padx 10 -pady 5

# Create "Iter" label
label .iterLabel -text "Iter:"
grid .iterLabel -row 1 -column 2 -sticky e -padx 10 -pady 5

# Create "Iter" input box
entry .iterBox -width 10 -textvariable ::iterValue
set ::iterValue 0
grid .iterBox -row 1 -column 3 -sticky w -padx 10 -pady 5

# Create PBKDF2 Hash Algorithm ComboBox with "sha256" as default value
set hashAlgorithms {
    "blake2s256" "blake2b256" "blake2b512" "blake3" "cubehash"
    "gost94" "groestl" "jh" "keccak256" "keccak512" "lsh224"
    "lsh256" "lsh384" "lsh512" "md4" "md5" "rmd128" "rmd160"
    "rmd256" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3-224"
    "sha3-256" "sha3-384" "sha3-512" "siphash64" "siphash128"
    "skein256" "skein512" "sm3" "streebog256" "streebog512"
    "tiger" "tiger2" "whirlpool" "xoodyak"
}
ttk::combobox .pbkdf2HashCombo -values $hashAlgorithms -width 30
.pbkdf2HashCombo set "sha256" ;# Define "sha256" como o valor padrão
grid .pbkdf2HashCombo -row 1 -column 4 -sticky w -padx 10 -pady 5

# Create plaintext text box with a vertical scrollbar and Copy/Paste buttons
text .plaintextBox -width 80 -height 10 -wrap word
scrollbar .plaintextScroll -command {.plaintextBox yview}
.plaintextBox configure -yscrollcommand {.plaintextScroll set}
grid .plaintextBox -row 2 -column 0 -columnspan 6 -padx 10 -pady 10 -sticky "nsew"
grid .plaintextScroll -row 2 -column 7 -sticky "ns"
button .copyPlaintextButton -text "Copy" -background gray80 -command {clipboard clear; clipboard append [.plaintextBox get 1.0 end]}
grid .copyPlaintextButton -row 3 -column 0 -columnspan 2 -padx 10 -pady 5 -sticky "ew"
button .pastePlaintextButton -text "Paste" -background gray80 -command {pasteText .plaintextBox}
grid .pastePlaintextButton -row 3 -column 4 -columnspan 3 -padx 10 -pady 5 -sticky "ew"

# Create ciphertext text box with a vertical scrollbar and Copy/Paste buttons
text .ciphertextBox -width 80 -height 10 -wrap word
scrollbar .ciphertextScroll -command {.ciphertextBox yview}
.ciphertextBox configure -yscrollcommand {.ciphertextScroll set}
grid .ciphertextBox -row 4 -column 0 -columnspan 6 -padx 10 -pady 10 -sticky "nsew"
grid .ciphertextScroll -row 4 -column 7 -sticky "ns"
button .copyCiphertextButton -text "Copy" -background gray80 -command {clipboard clear; clipboard append [.ciphertextBox get 1.0 end]}
grid .copyCiphertextButton -row 5 -column 0 -columnspan 2 -padx 10 -pady 5 -sticky "ew"
button .pasteCiphertextButton -text "Paste" -background gray80 -command {pasteText .ciphertextBox}
grid .pasteCiphertextButton -row 5 -column 4 -columnspan 3 -padx 10 -pady 5 -sticky "ew"


# Create Key label
label .keyLabel -text "Key:"
grid .keyLabel -row 6 -column 0 -sticky e -padx 10 -pady 5

# Create IV label
label .ivLabel -text "IV:"
grid .ivLabel -row 7 -column 0 -sticky e -padx 10 -pady 5

# Create key input box
entry .keyBox -width 90
grid .keyBox -row 6 -column 1 -columnspan 4 -sticky w -padx 10 -pady 5

# Create IV input box
entry .ivBox -width 90
grid .ivBox -row 7 -column 1 -columnspan 4 -sticky w -padx 10 -pady 5

# Create Encrypt button
button .encryptButton -text "Encrypt" -background gray80 -command {encrypt}
grid .encryptButton -row 7 -column 4 -sticky e -padx 10 -pady 5

# Create Decrypt button
button .decryptButton -text "Decrypt" -background gray80 -command {decrypt}
grid .decryptButton -row 7 -column 5 -sticky e -padx 10 -pady 5

proc updateKeyEntryDisplay {} {
    global useKDFAlgorithm

    if {$useKDFAlgorithm == 1} {
        # Se o checkbox KDF estiver marcado, mostre bullets
        .keyBox configure -show "*"
    } else {
        # Caso contrário, mostre os caracteres reais
        .keyBox configure -show ""
    }
}

.kdfAlgorithmCheckbox configure -command updateKeyEntryDisplay

updateKeyEntryDisplay

# Function to perform encryption
proc encrypt {} {
    global keyBox ivBox useKDFAlgorithm saltBox iterBox pbkdf2HashCombo
    set plaintext [.plaintextBox get 1.0 end]
    set key [.keyBox get]
    set iv [.ivBox get]
    set salt [.saltBox get] ;# Obter o valor do campo "Salt"
    set iter [.iterBox get] ;# Obter o valor do campo "Iter"
    set algorithm [.algorithmCombo get]
    set mode [.modeCombo get]
    set pbkdf2Hash [.pbkdf2HashCombo get] ;# Obter o algoritmo de hash PBKDF2 selecionado

    set kdfOptionAlgorithm ""
    if {$useKDFAlgorithm == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    # Adjust the IV size based on the selected algorithm
    set ivSize 32  ;# Default value (twice the size in hexadecimal)

    switch $algorithm {
        "3des" -
        "blowfish" -
        "cast5" -
        "gost89" -
        "hight" -
        "idea" -
        "magma" -
        "misty1" -
        "rc2" -
        "rc5" {
            set ivSize 16  ;# 8 bytes
        }
        "aes" -
        "serpent" -
        "aria" -
        "lea" -
        "anubis" -
        "twofish" -
        "sm4" -
        "camellia" -
        "kuznechik" -
        "seed" -
        "hc128" -
        "zuc128" {
            set ivSize 32  ;# 16 bytes
        }
        "zuc256" {
            set ivSize 46  ;# 23 bytes
        }
        "hc256" -
        "skein512" -
	"threefish" {
            set ivSize 64  ;# 32 bytes
        }
        "rc4" -
        "chacha20poly1305" {
            set ivSize 0  ;# 0 bytes
        }
        "salsa20" -
        "chacha20" {
            set ivSize 48  ;# 24 bytes
        }
    }

    switch $mode {
        "ecb" -
        "gcm" -
        "ocb1" -
        "ocb3" -
        "mgm" -
        "ccm" -
        "eax" {
            set ivSize 0  ;# 0 bytes
        }
    }

    if {$mode == "ige"} {
        set ivSize [expr {2 * $ivSize}]
    }

    # Check if the IV field is empty and fill it with zeros of the adjusted length if necessary
    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .ivBox delete 0 end
        .ivBox insert 0 $iv
    } 

    # Perform encryption logic using edgetk
    set encryptedMsg [exec edgetk -crypt enc -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash << $plaintext | base64]

    # Update the ciphertext text box with the encrypted result
    .ciphertextBox delete 1.0 end
    .ciphertextBox insert 1.0 $encryptedMsg
}

# Function to perform decryption
proc decrypt {} {
    global keyBox ivBox useKDFAlgorithm saltBox iterBox pbkdf2HashCombo
    set ciphertext [.ciphertextBox get 1.0 end]
    set key [.keyBox get]
    set iv [.ivBox get]
    set salt [.saltBox get] ;# Obter o valor do campo "Salt"
    set iter [.iterBox get] ;# Obter o valor do campo "Iter"
    set algorithm [.algorithmCombo get]
    set mode [.modeCombo get]
    set pbkdf2Hash [.pbkdf2HashCombo get] ;# Obter o algoritmo de hash PBKDF2 selecionado

    set kdfOptionAlgorithm ""
    if {$useKDFAlgorithm == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    # Adjust the IV size based on the selected algorithm
    set ivSize 32  ;# Default value (twice the size in hexadecimal)

    switch $algorithm {
        "3des" -
        "blowfish" -
        "cast5" -
        "gost89" -
        "hight" -
        "idea" -
        "magma" -
        "misty1" -
        "rc2" -
        "rc5" {
            set ivSize 16  ;# 8 bytes
        }
        "aes" -
        "serpent" -
        "aria" -
        "lea" -
        "anubis" -
        "twofish" -
        "sm4" -
        "camellia" -
        "kuznechik" -
        "seed" -
        "hc128" -
        "zuc128" {
            set ivSize 32  ;# 16 bytes
        }
        "zuc256" {
            set ivSize 46  ;# 23 bytes
        }
        "hc256" -
        "skein512" -
	"threefish" {
            set ivSize 64  ;# 32 bytes
        }
        "rc4" -
        "chacha20poly1305" {
            set ivSize 0  ;# 0 bytes
        }
        "salsa20" -
        "chacha20" {
            set ivSize 48  ;# 24 bytes
        }
    }

    switch $mode {
        "ecb" -
        "gcm" -
        "ocb1" -
        "ocb3" -
        "mgm" -
        "ccm" -
        "eax" {
            set ivSize 0  ;# 0 bytes
        }
    }

    if {$mode == "ige"} {
        set ivSize [expr {2 * $ivSize}]
    }

    # Check if the IV field is empty and fill it with zeros of the adjusted length if necessary
    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .ivBox delete 0 end
        .ivBox insert 0 $iv
    } 

    # Perform decryption logic using edgetk
    set decryptedMsg [exec base64 -d << $ciphertext | edgetk -crypt dec -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash]

    # Update the plaintext text box with the decrypted result
    .plaintextBox delete 1.0 end
    .plaintextBox insert 1.0 $decryptedMsg
}


# Function to paste text into the given textbox
proc pasteText {textbox} {
    $textbox delete 1.0 end
    $textbox insert 1.0 [clipboard get]
}

# Start the event loop
tkwait visibility .
