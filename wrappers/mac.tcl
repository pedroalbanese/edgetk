#!/usr/bin/wish

# Create a new window
wm title . "EDGE MAC/HMAC/CMAC Calculation Tool written in TCL/TK"
wm geometry . 610x440

# Create Algorithm label
label .algorithmLabel -text "Algorithm:"
grid .algorithmLabel -row 0 -column 0 -sticky e -padx 10 -pady 5

# Create Algorithm ComboBox with "HMAC" as the default value
set macAlgorithms {"hmac" "cmac" "chaskey" "gost" "poly1305" "siphash" "skein" "xoodyak" "eia128" "eia256"}
ttk::combobox .algorithmCombo -values $macAlgorithms -width 30 -state readonly
.algorithmCombo set "hmac"
grid .algorithmCombo -row 0 -column 1 -sticky w -padx 10 -pady 5

# Function to update the variable $algorithm
proc updateAlgorithm {} {
    global algorithm
    set algorithm [.algorithmCombo get]
}

# Event handler to monitor changes in the algorithm ComboBox
bind .algorithmCombo <<ComboboxSelected>> {updateAlgorithm}

# Create Hash label
label .hashLabel -text "Hash:"
grid .hashLabel -row 1 -column 0 -sticky e -padx 10 -pady 5

# Create Hash ComboBox for HMAC with default value "sha256"
set hmacHashes {
    "blake2s256" "blake2b256" "blake2b512" "blake3" "cubehash"
    "gost94" "groestl" "jh" "keccak256" "keccak512" "lsh224"
    "lsh256" "lsh384" "lsh512" "md4" "md5" "rmd128" "rmd160"
    "rmd256" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3-224"
    "sha3-256" "sha3-384" "sha3-512" "siphash64" "siphash128"
    "skein256" "skein512" "sm3" "streebog256" "streebog512"
    "tiger" "tiger2" "whirlpool" "xoodyak"
}
ttk::combobox .hmacHashCombo -values $hmacHashes -width 30 -state readonly
.hmacHashCombo set "sha256"
grid .hmacHashCombo -row 1 -column 1 -sticky w -padx 10 -pady 5

# Create Cipher label
label .cipherLabel -text "Cipher:"
grid .cipherLabel -row 2 -column 0 -sticky e -padx 10 -pady 5

# Create Cipher ComboBox for CMAC with default value "aes"
set cmacCiphers {"3des" "aes" "anubis" "aria" "blowfish" "camellia" "cast5" "gost89" "idea" "kuznechik" "lea" "magma" "misty1" "rc2" "rc5" "seed" "serpent" "sm4" "twofish"}
ttk::combobox .cmacCipherCombo -values $cmacCiphers -width 30 -state readonly
.cmacCipherCombo set "aes"
grid .cmacCipherCombo -row 2 -column 1 -sticky w -padx 10 -pady 5

# Create Key label
label .keyLabel -text "Key:"
grid .keyLabel -row 3 -column 0 -sticky e -padx 10 -pady 5

# Create Key input box
entry .keyEntry -width 60
grid .keyEntry -row 3 -column 1 -columnspan 2 -padx 10 -pady 5 -sticky "nsew"

# Create IV label
label .ivLabel -text "IV:"
grid .ivLabel -row 4 -column 0 -sticky e -padx 10 -pady 5

# Create IV input box
entry .ivEntry -width 60
grid .ivEntry -row 4 -column 1 -columnspan 2 -padx 10 -pady 5 -sticky "nsew"

# Create Message label
label .messageLabel -text "Message:"
grid .messageLabel -row 5 -column 0 -sticky e -padx 10 -pady 5

# Create Message input box with vertical scrollbar
text .messageBox -width 60 -height 5 -wrap word
scrollbar .messageScrollbar -command {.messageBox yview}
.messageBox configure -yscrollcommand {.messageScrollbar set}
grid .messageBox -row 5 -column 1 -columnspan 2 -padx 10 -pady 5 -sticky "nsew"
grid .messageScrollbar -row 5 -column 3 -sticky "ns"

# Create Calculate button
button .calculateButton -text "Calculate" -command {calculateMAC}
grid .calculateButton -row 6 -column 1 -columnspan 2 -padx 10 -pady 10 -sticky "ew"

# Create Result label
label .resultLabel -text "Result:"
grid .resultLabel -row 7 -column 0 -sticky e -padx 10 -pady 5

# Create Result text box
text .resultBox -width 60 -height 5 -wrap word -state disabled
grid .resultBox -row 7 -column 1 -columnspan 2 -padx 10 -pady 5 -sticky "nsew"

# Create Copy button
button .copyButton -text "Copy" -command {copyResult}
grid .copyButton -row 8 -column 1 -columnspan 2 -padx 10 -pady 10 -sticky "ew"

# Function to copy the result to the clipboard
proc copyResult {} {
    set result [.resultBox get 1.0 end]
    clipboard clear
    clipboard append $result
}

# Function to calculate MAC, HMAC, or CMAC
proc calculateMAC {} {
    global algorithm

    set key [.keyEntry get]
    set iv [.ivEntry get]
    set message [.messageBox get 1.0 end]

    if {$algorithm == "hmac"} {
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            .keyEntry delete 0 end
            set key ""
        }
        set hash [.hmacHashCombo get]
        set result [exec edgetk -mac hmac -md $hash -key $key << $message]
    } elseif {$algorithm == "cmac"} {
        set cipher [.cmacCipherCombo get]

        # Check if the key is empty
        set keySize 0
        if {[string length $key] == 0 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            switch $cipher {
                "3des" -
                "blowfish" -
                "cast5" -
                "gost89" -
                "hight" -
                "idea" -
                "magma" -
                "misty1" -
                "sm4" -
                "rc2" -
                "rc5" {
                    set keySize 16
                }
                "aes" -
                "serpent" -
                "aria" -
                "lea" -
                "anubis" -
                "twofish" -
                "camellia" -
                "kuznechik" -
                "seed" {
                    set keySize 32
                }
            }
        }
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set key [string repeat "0" $keySize]
            .keyEntry delete 0 end
            .keyEntry insert 0 $key
        }
        set result [exec edgetk -mac cmac -cipher $cipher -key $key << $message]
    } else {
        set keySize 0
        switch $algorithm {
            "chaskey" {
                set keySize 8
            }
            "eia128" {
                set keySize 32
            }
            "eia256" {
                set keySize 64
            }
        }
        
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set key [string repeat "0" $keySize]
            .keyEntry delete 0 end
            .keyEntry insert 0 $key
        }

        set result [exec edgetk -mac $algorithm -key $key -iv $iv << $message 2>@1]
    }

    .resultBox configure -state normal
    .resultBox delete 1.0 end
    .resultBox insert 1.0 $result
    .resultBox configure -state disabled
}

# Function to update the UI based on algorithm selection
proc updateUI {} {
    global algorithm

    if {$algorithm == "hmac"} {
        .hmacHashCombo configure -state readonly
        .cmacCipherCombo configure -state readonly ;# Changed to readonly
    } elseif {$algorithm == "cmac"} {
        .hmacHashCombo configure -state readonly
        .cmacCipherCombo configure -state readonly
    }
}

# Set the initial algorithm to HMAC and update the UI
set algorithm "hmac"
updateUI

# Start the event loop
tkwait visibility .
