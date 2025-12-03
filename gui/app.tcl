#!/usr/bin/wish

# Style settings
set bg_color "#f5f5f5"
set accent_color "#2c3e50"
set button_color "#3498db"
set button_hover "#2980b9"
set frame_color "#ecf0f1"
set text_bg "#ffffff"

# Função para selecionar todo o texto
proc selecionarTodo {w} {
    if {[string match "*Text" [winfo class $w]]} {
        # Se for Text
        $w tag add sel 1.0 end
    } elseif {[string match "*Entry" [winfo class $w]]} {
        # Se for Entry
        $w selection range 0 end
    }
}

# Bind global para Ctrl+A
bind all <Control-a> {
    # Obter o widget que tem foco
    set w %W
    # Chamar a função
    selecionarTodo $w
    break
}

# ===== FUNÇÕES MAC (INTEGRADAS) =====

# Function to copy result to clipboard
proc copyResult {} {
    set result [.nb.mac_tab.main.output_frame.textframe.resultBox get 1.0 end]
    clipboard clear
    clipboard append [string trim $result]
}

# Function to copy file result to clipboard
proc copyFileResult {} {
    set result [.nb.mac_file_tab.main.status_frame.textframe.text get 1.0 end]
    clipboard clear
    clipboard append [string trim $result]
}

# Function to update UI based on selected algorithm
proc updateAlgorithmUI {} {
    set algorithm [.nb.mac_tab.main.algo_frame.content.algorithmCombo get]
    
    # Update Text tab
    if {$algorithm == "hmac"} {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    } elseif {$algorithm == "cmac" || $algorithm == "pmac"} {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    } elseif {$algorithm == "vmac"} {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state normal
    } else {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    }
    
    # Update Files tab
    set algorithm [.nb.mac_file_tab.main.algo_frame.content.algorithmCombo get]
    if {$algorithm == "hmac"} {
        .nb.mac_file_tab.main.algo_frame.content.hashLabel configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    } elseif {$algorithm == "cmac" || $algorithm == "pmac"} {
        .nb.mac_file_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    } elseif {$algorithm == "vmac"} {
        .nb.mac_file_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.outSizeLabel configure -state normal
        .nb.mac_file_tab.main.algo_frame.content.outSizeCombo configure -state normal
    } else {
        .nb.mac_file_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_file_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    }
}

# Function to calculate MAC, HMAC, or CMAC for text
proc calculateMAC {} {
    set algorithm [.nb.mac_tab.main.algo_frame.content.algorithmCombo get]
    set key [.nb.mac_tab.main.keys_frame.content.keyEntry get]
    set iv [.nb.mac_tab.main.keys_frame.content.ivEntry get]
    set message [.nb.mac_tab.main.input_frame.textframe.messageBox get 1.0 end]

    if {$algorithm == "hmac"} {
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            set key ""
        }
        set hash [.nb.mac_tab.main.algo_frame.content.hmacHashCombo get]
        set result [exec edgetk -mac hmac -md $hash -key $key << $message]
    } elseif {$algorithm == "cmac" || $algorithm == "pmac"} {
        set cipher [.nb.mac_tab.main.algo_frame.content.cmacCipherCombo get]

        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set keySize 0
            switch $cipher {
                "3des" -
                "blowfish" -
                "cast5" -
                "cast256" -
                "curupira" -
                "hight" -
                "idea" -
                "misty1" -
                "noekeon" -
                "present" -
                "rc2" -
                "rc5" -
                "rc6" -
                "safer+" -
                "sm4" -
                "seed" -
                "kalyna128_128" -
                "twine" {
                    set keySize 16
                }
                "aes" -
                "anubis" -
                "aria" -
                "belt" -
                "camellia" -
                "clefia" -
                "crypton" -
                "e2" -
                "kalyna128_256" -
                "khazad" -
                "kuznechik" -
                "lea" -
                "loki97" -
                "magma" -
                "gost89" -
                "magenta" -
                "mars" -
                "serpent" -
                "shacal2" -
                "kalyna256_256" -
                "twofish" -
                "threefish256" {
                    set keySize 32
                }
                "kalyna256_512" -
                "kalyna512_512" -
                "threefish512" {
                    set keySize 64
                }
                "threefish1024" {
                    set keySize 128
                }
                default {
                    set keySize 32 ;# Default size for most ciphers
                }
            }
            set key [string repeat "0" $keySize]
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.keyEntry insert 0 $key
        }
        # CMAC e PMAC não usam IV
        set result [exec edgetk -mac $algorithm -cipher $cipher -key $key << $message]
    } elseif {$algorithm == "vmac"} {
        set cipher [.nb.mac_tab.main.algo_frame.content.cmacCipherCombo get]
        set outSize [.nb.mac_tab.main.algo_frame.content.outSizeCombo get]

        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set keySize 0
            switch $cipher {
                "3des" -
                "blowfish" -
                "cast5" -
                "cast256" -
                "curupira" -
                "hight" -
                "idea" -
                "misty1" -
                "noekeon" -
                "present" -
                "rc2" -
                "rc5" -
                "rc6" -
                "safer+" -
                "sm4" -
                "seed" -
                "kalyna128_128" -
                "twine" {
                    set keySize 16
                }
                "aes" -
                "anubis" -
                "aria" -
                "belt" -
                "camellia" -
                "clefia" -
                "crypton" -
                "e2" -
                "kalyna128_256" -
                "khazad" -
                "kuznechik" -
                "lea" -
                "loki97" -
                "magma" -
                "gost89" -
                "magenta" -
                "mars" -
                "serpent" -
                "shacal2" -
                "kalyna256_256" -
                "twofish" -
                "threefish256" {
                    set keySize 32
                }
                "kalyna256_512" -
                "kalyna512_512" -
                "threefish512" {
                    set keySize 64
                }
                "threefish1024" {
                    set keySize 128
                }
                default {
                    set keySize 32 ;# Default size for most ciphers
                }
            }
            set key [string repeat "0" $keySize]
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.keyEntry insert 0 $key
        }
        
        # For VMAC, IV is required and must be 1 to block_length-1 bytes
        # Default to "00" (1 byte) if empty
        if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
            set iv "00"
            .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.ivEntry insert 0 $iv
        }
        
        set result [exec edgetk -mac vmac -cipher $cipher -key $key -iv $iv -bits [expr {$outSize * 8}] << $message]
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
            "poly1305" {
                set keySize 64
            }
            "siphash" {
                set keySize 16
            }
            "gost" {
                set keySize 32
            }
            "skein" {
                set keySize 64
            }
            "xoodyak" {
                set keySize 48
            }
        }
        
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set key [string repeat "0" $keySize]
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.keyEntry insert 0 $key
        }

        set result [exec edgetk -mac $algorithm -key $key -iv $iv << $message 2>@1]
    }

    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state normal
    .nb.mac_tab.main.output_frame.textframe.resultBox delete 1.0 end
    .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
}

# Function to calculate MAC for files
proc calculateMACFile {} {
    set algorithm [.nb.mac_file_tab.main.algo_frame.content.algorithmCombo get]
    set key [.nb.mac_file_tab.main.keys_frame.content.keyEntry get]
    set iv [.nb.mac_file_tab.main.keys_frame.content.ivEntry get]
    set inputFile [.nb.mac_file_tab.main.file_selection.input_frame.path get]
    
    if {$inputFile eq ""} {
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
        .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
        .nb.mac_file_tab.main.status_frame.textframe.text insert end "ERROR: Please select an input file first!"
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
        return
    }
    
    if {![file exists $inputFile]} {
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
        .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
        .nb.mac_file_tab.main.status_frame.textframe.text insert end "ERROR: Input file does not exist!"
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
        return
    }
    
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
    .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
    .nb.mac_file_tab.main.status_frame.textframe.text insert end "Calculating MAC for: [file tail $inputFile]\nPlease wait..."
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
    update
    
    # Calculate MAC directly from file (not stdin)
    if {[catch {
        if {$algorithm == "hmac"} {
            # Check if the key is empty
            if {[string length $key] < 1 || [string trim $key 0] eq ""} {
                .nb.mac_file_tab.main.keys_frame.content.keyEntry delete 0 end
                set key ""
            }
            set hash [.nb.mac_file_tab.main.algo_frame.content.hmacHashCombo get]
            set result [exec edgetk -mac hmac -md $hash -key $key $inputFile]
        } elseif {$algorithm == "cmac" || $algorithm == "pmac"} {
            set cipher [.nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo get]

            # Check if the key is empty
            if {[string length $key] < 1 || [string trim $key 0] eq ""} {
                # Set a null key with the appropriate size
                set keySize 0
                switch $cipher {
                    "3des" -
                    "blowfish" -
                    "cast5" -
                    "cast256" -
                    "curupira" -
                    "hight" -
                    "idea" -
                    "misty1" -
                    "noekeon" -
                    "present" -
                    "rc2" -
                    "rc5" -
                    "rc6" -
                    "safer+" -
                    "sm4" -
                    "seed" -
                    "kalyna128_128" -
                    "twine" {
                        set keySize 16
                    }
                    "aes" -
                    "anubis" -
                    "aria" -
                    "belt" -
                    "camellia" -
                    "clefia" -
                    "crypton" -
                    "e2" -
                    "gost89" -
                    "magma" -
                    "kalyna128_256" -
                    "khazad" -
                    "kuznechik" -
                    "lea" -
                    "loki97" -
                    "magenta" -
                    "mars" -
                    "serpent" -
                    "shacal2" -
                    "kalyna256_256" -
                    "twofish" -
                    "threefish256" {
                        set keySize 32
                    }
                    "kalyna256_512" -
                    "kalyna512_512" -
                    "threefish512" {
                        set keySize 64
                    }
                    "threefish1024" {
                        set keySize 128
                    }
                    default {
                        set keySize 32 ;# Default size for most ciphers
                    }
                }
                set key [string repeat "0" $keySize]
                .nb.mac_file_tab.main.keys_frame.content.keyEntry delete 0 end
                .nb.mac_file_tab.main.keys_frame.content.keyEntry insert 0 $key
            }
            # CMAC e PMAC não usam IV
            set result [exec edgetk -mac $algorithm -cipher $cipher -key $key $inputFile]
        } elseif {$algorithm == "vmac"} {
            set cipher [.nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo get]
            set outSize [.nb.mac_file_tab.main.algo_frame.content.outSizeCombo get]

            # Check if the key is empty
            if {[string length $key] < 1 || [string trim $key 0] eq ""} {
                # Set a null key with the appropriate size
                set keySize 0
                switch $cipher {
                    "3des" -
                    "blowfish" -
                    "cast5" -
                    "cast256" -
                    "curupira" -
                    "hight" -
                    "idea" -
                    "misty1" -
                    "noekeon" -
                    "present" -
                    "rc2" -
                    "rc5" -
                    "rc6" -
                    "safer+" -
                    "sm4" -
                    "seed" -
                    "kalyna128_128" -
                    "twine" {
                        set keySize 16
                    }
                    "aes" -
                    "anubis" -
                    "aria" -
                    "belt" -
                    "camellia" -
                    "clefia" -
                    "crypton" -
                    "e2" -
                    "gost89" -
                    "magma" -
                    "kalyna128_256" -
                    "khazad" -
                    "kuznechik" -
                    "lea" -
                    "loki97" -
                    "magenta" -
                    "mars" -
                    "serpent" -
                    "shacal2" -
                    "kalyna256_256" -
                    "twofish" -
                    "threefish256" {
                        set keySize 32
                    }
                    "kalyna256_512" -
                    "kalyna512_512" -
                    "threefish512" {
                        set keySize 64
                    }
                    "threefish1024" {
                        set keySize 128
                    }
                    default {
                        set keySize 32 ;# Default size for most ciphers
                    }
                }
                set key [string repeat "0" $keySize]
                .nb.mac_file_tab.main.keys_frame.content.keyEntry delete 0 end
                .nb.mac_file_tab.main.keys_frame.content.keyEntry insert 0 $key
            }
            
            # For VMAC, IV is required and must be 1 to block_length-1 bytes
            # Default to "00" (1 byte) if empty
            if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
                set iv "00"
                .nb.mac_file_tab.main.keys_frame.content.ivEntry delete 0 end
                .nb.mac_file_tab.main.keys_frame.content.ivEntry insert 0 $iv
            }
            
            set result [exec edgetk -mac vmac -cipher $cipher -key $key -iv $iv -bits [expr {$outSize * 8}] $inputFile]
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
                "poly1305" {
                    set keySize 64
                }
                "siphash" {
                    set keySize 16
                }
                "gost" {
                    set keySize 32
                }
                "skein" {
                    set keySize 64
                }
                "xoodyak" {
                    set keySize 48
                }
            }
            
            # Check if the key is empty
            if {[string length $key] < 1 || [string trim $key 0] eq ""} {
                # Set a null key with the appropriate size
                set key [string repeat "0" $keySize]
                .nb.mac_file_tab.main.keys_frame.content.keyEntry delete 0 end
                .nb.mac_file_tab.main.keys_frame.content.keyEntry insert 0 $key
            }

            set result [exec edgetk -mac $algorithm -key $key -iv $iv $inputFile 2>@1]
        }
    } errorMsg]} {
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
        .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
        .nb.mac_file_tab.main.status_frame.textframe.text insert end "ERROR: MAC calculation failed!\n$errorMsg"
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
        return
    }
    
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
    .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
    .nb.mac_file_tab.main.status_frame.textframe.text insert end "SUCCESS: MAC calculated!\nResult: $result"
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
}

# ===== FIM DAS FUNÇÕES MAC =====

# ===== FUNÇÕES ECDH (INTEGRADAS) =====

# Função para copiar o texto para a área de transferência
proc copyText {text} {
    set trimmedText [string trim $text]
    clipboard clear
    clipboard append $trimmedText
}

# Função para abrir o diretório da chave pública
proc openPublicKey {} {
    set public_key_path [.nb.ecdh_tab.main.keys_frame.content.publicKeyInput get]
    if {[file exists $public_key_path]} {
        set public_key_directory [file dirname $public_key_path]
        if {[catch {exec cmd /c start "" [file nativename $public_key_directory]} error]} {
            tk_messageBox -title "Error" -message "Não foi possível abrir o diretório: $error" -icon error
        }
    } else {
        tk_messageBox -title "Error" -message "Arquivo não encontrado: $public_key_path" -icon error
    }
}

# Função para abrir a caixa de diálogo de seleção de arquivo para a chave do peer
proc openPeerKey {} {
    set peer_key_path [tk_getOpenFile -defaultextension ".pem" -filetypes {{"PEM Files" ".pem"} {"All Files" "*"}}]
    if {$peer_key_path ne ""} {
        .nb.ecdh_tab.main.keys_frame.content.peerKeyInput delete 0 end
        .nb.ecdh_tab.main.keys_frame.content.peerKeyInput insert 0 $peer_key_path
    }
}

# Função para gerar a chave
proc generateECDHKey {} {
    set private_key_path [file join [pwd] "Private.pem"]
    set public_key_path [file join [pwd] "Public.pem"]
    set algorithm [.nb.ecdh_tab.main.algo_frame.content.algorithmCombo get]
    set bits [.nb.ecdh_tab.main.algo_frame.content.bitsCombo get]
    set paramset [.nb.ecdh_tab.main.algo_frame.content.paramsetCombo get]

    if {[catch {
        exec edgetk -pkey keygen -algorithm $algorithm -bits $bits -paramset $paramset -pass - -prv $private_key_path -pub $public_key_path 2>@1
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Error generating keys: $error"
        return
    }

    .nb.ecdh_tab.main.keys_frame.content.privateKeyInput delete 0 end
    .nb.ecdh_tab.main.keys_frame.content.privateKeyInput insert 0 $private_key_path
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput delete 0 end
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput insert 0 $public_key_path
    
    .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
    .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Keys generated successfully!\nPrivate key saved as: Private.pem\nPublic key saved as: Public.pem"
}

# Função para derivar a chave
proc deriveECDHKey {} {
    set private_key_path [.nb.ecdh_tab.main.keys_frame.content.privateKeyInput get]
    set peer_key_path [.nb.ecdh_tab.main.keys_frame.content.peerKeyInput get]
    set algorithm [.nb.ecdh_tab.main.algo_frame.content.algorithmCombo get]
    set outputKeySize [.nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo get]

    if {![file exists $private_key_path]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR: Private key file not found. Please generate keys first."
        return
    }
    
    if {![file exists $peer_key_path]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR: Peer key file not found. Please select a valid PEM file."
        return
    }

    if {[catch {
        set result [exec edgetk -pkey derive -algorithm $algorithm -key $private_key_path -pass - -pub $peer_key_path 2>@1]
        
        # Truncar a chave resultante para o tamanho desejado (se necessário)
        if {$outputKeySize > 0} {
            set result [string range $result 0 [expr {$outputKeySize * 2 - 1}]]
        }
        
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Shared Secret Derived Successfully:\n\n$result"
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR deriving key: $error"
    }
}

# Função para executar HKDF
proc executeECDHHKDF {} {
    set salt [.nb.ecdh_tab.main.kdf_frame.content.saltInput get]
    set hashAlgorithm [.nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo get]
    set inputKey [string trim [.nb.ecdh_tab.main.output_frame.textframe.outputArea get 1.0 end]]
    set outputKeySize [.nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo get]
    set outputSize [expr {$outputKeySize * 8}]
    
    # Extrair apenas o valor hexadecimal do resultado anterior
    if {[regexp {([0-9a-fA-F]+)} $inputKey match hexValue]} {
        set inputKey $hexValue
    }
    
    if {[string length $inputKey] < 1} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR: No input key found. Please derive a shared secret first."
        return
    }
    
    if {[catch {
        set hkdfResult [exec edgetk -kdf hkdf -salt $salt -md $hashAlgorithm -key $inputKey -bits $outputSize 2>@1]
        
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "HKDF Applied Successfully:\n\n$hkdfResult"
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR applying HKDF: $error"
    }
}

# ===== FIM DAS FUNÇÕES ECDH =====

# ===== FUNÇÕES COMPARTILHADAS =====

# Function to display additional info in a new window
proc executeINFOScript {} {
    # Create a new window
    toplevel .info_window
    wm title .info_window "About EDGE Crypto Suite"
    wm geometry .info_window 400x200
    wm resizable .info_window 0 0
    
    # Center the window
    set x [expr {[winfo screenwidth .] / 2 - 200}]
    set y [expr {[winfo screenheight .] / 2 - 100}]
    wm geometry .info_window +$x+$y
    
    # Main frame
    frame .info_window.main -bg white -relief solid -bd 1
    pack .info_window.main -fill both -expand true -padx 10 -pady 10
    
    # Logo/Icon
    label .info_window.main.logo -text "🔒" -font {Arial 24} -bg white
    pack .info_window.main.logo -pady 10
    
    # Title
    label .info_window.main.title -text "EDGE Crypto Suite" \
        -font {Arial 14 bold} -bg white
    pack .info_window.main.title -pady 5
    
    # Information
    label .info_window.main.version -text "Version 1.0" \
        -font {Arial 10} -bg white
    pack .info_window.main.version -pady 2
    
    label .info_window.main.dev -text "Bulk Encryption + ECDH + MAC" \
        -font {Arial 9} -bg white
    pack .info_window.main.dev -pady 2
    
    label .info_window.main.lab -text "ALBANESE Research Lab" \
        -font {Arial 9 bold} -bg white
    pack .info_window.main.lab -pady 10
    
    # OK button
    button .info_window.main.ok -text "OK" -command {destroy .info_window} \
        -bg "#3498db" -fg white -font {Arial 10 bold} -relief flat \
        -padx 20 -pady 5
    pack .info_window.main.ok -pady 10
    
    # Bind to close with ESC
    bind .info_window <Key-Escape> {destroy .info_window}
    bind .info_window <Return> {destroy .info_window}
    focus .info_window
}

# Function to select input file
proc selectInputFile {} {
    set filetypes {
        {"All files" *}
        {"Text files" {.txt .text}}
        {"PDF files" {.pdf}}
        {"Image files" {.jpg .jpeg .png .gif .bmp}}
        {"Executable files" {.exe .bin}}
        {"Data files" {.dat .data .db .sqlite}}
    }
    
    set filename [tk_getOpenFile -title "Select Input File" \
        -filetypes $filetypes]
    
    if {$filename ne ""} {
        .nb.file_tab.main.file_selection.input_frame.path configure -state normal
        .nb.file_tab.main.file_selection.input_frame.path delete 0 end
        .nb.file_tab.main.file_selection.input_frame.path insert 0 $filename
        .nb.file_tab.main.file_selection.input_frame.path configure -state readonly
        
        # Auto-generate output filename with .enc suffix for encryption
        # or remove .enc for decryption
        set outputFile ""
        if {[string match "*.enc" $filename]} {
            set outputFile [string range $filename 0 end-4]
        } else {
            set outputFile "${filename}.enc"
        }
        
        .nb.file_tab.main.file_selection.output_frame.path delete 0 end
        .nb.file_tab.main.file_selection.output_frame.path insert 0 $outputFile
        
        # Show file information
        updateStatus "Input file selected: [file tail $filename]\nSize: [formatSize [file size $filename]]\nOutput file: [file tail $outputFile]"
    }
}

# Function to select input file for MAC
proc selectInputFileMAC {} {
    set filetypes {
        {"All files" *}
        {"Text files" {.txt .text}}
        {"PDF files" {.pdf}}
        {"Image files" {.jpg .jpeg .png .gif .bmp}}
        {"Executable files" {.exe .bin}}
        {"Data files" {.dat .data .db .sqlite}}
    }
    
    set filename [tk_getOpenFile -title "Select Input File" \
        -filetypes $filetypes]
    
    if {$filename ne ""} {
        .nb.mac_file_tab.main.file_selection.input_frame.path configure -state normal
        .nb.mac_file_tab.main.file_selection.input_frame.path delete 0 end
        .nb.mac_file_tab.main.file_selection.input_frame.path insert 0 $filename
        .nb.mac_file_tab.main.file_selection.input_frame.path configure -state readonly
        
        # Show file information
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
        .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
        .nb.mac_file_tab.main.status_frame.textframe.text insert end "Input file selected: [file tail $filename]\nSize: [formatSize [file size $filename]]"
        .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
    }
}

# Function to select output file
proc selectOutputFile {} {
    set inputFile [.nb.file_tab.main.file_selection.input_frame.path get]
    
    if {$inputFile eq ""} {
        updateStatus "ERROR: Please select an input file first!"
        return
    }
    
    set filetypes {
        {"All files" *}
        {"Encrypted files" {.enc}}
        {"Decrypted files" {.dec .txt .pdf .jpg .png .exe .dat}}
    }
    
    set initialDir [file dirname $inputFile]
    set initialFile [file tail $inputFile]
    
    # Suggest .enc for encryption, .dec for decryption, or original name
    if {[string match "*.enc" $inputFile]} {
        set initialFile "[file rootname $initialFile]"
    } else {
        set initialFile "${initialFile}.enc"
    }
    
    set filename [tk_getSaveFile -title "Select Output File" \
        -initialdir $initialDir \
        -initialfile $initialFile \
        -filetypes $filetypes]
    
    if {$filename ne ""} {
        .nb.file_tab.main.file_selection.output_frame.path delete 0 end
        .nb.file_tab.main.file_selection.output_frame.path insert 0 $filename
        
        updateStatus "Output file set: [file tail $filename]"
    }
}

# Function to format file size
proc formatSize {bytes} {
    if {$bytes < 1024} {
        return "${bytes} bytes"
    } elseif {$bytes < 1048576} {
        set kb [expr {double($bytes) / 1024}]
        return [format "%.1f KB" $kb]
    } elseif {$bytes < 1073741824} {
        set mb [expr {double($bytes) / 1048576}]
        return [format "%.1f MB" $mb]
    } else {
        set gb [expr {double($bytes) / 1073741824}]
        return [format "%.1f GB" $gb]
    }
}

# Function to update status
proc updateStatus {message} {
    .nb.file_tab.main.status_frame.text configure -state normal
    .nb.file_tab.main.status_frame.text delete 1.0 end
    .nb.file_tab.main.status_frame.text insert 1.0 [clock format [clock seconds] -format "%H:%M:%S"]\n$message
    .nb.file_tab.main.status_frame.text configure -state disabled
    .nb.file_tab.main.status_frame.text see end
}

# Function to update key display (Text)
proc updateKeyEntryDisplay {} {
    global useKDFAlgorithm
    if {$useKDFAlgorithm == 1} {
        .nb.text_tab.main.keys_frame.keyBox configure -show "•"
    } else {
        .nb.text_tab.main.keys_frame.keyBox configure -show ""
    }
}

# Function to update key display (Files)
proc updateKeyEntryDisplayFiles {} {
    global useKDFAlgorithmFiles
    if {$useKDFAlgorithmFiles == 1} {
        .nb.file_tab.main.keys_frame.keyBox configure -show "•"
    } else {
        .nb.file_tab.main.keys_frame.keyBox configure -show ""
    }
}

# Function to calculate IV size
proc calculateIVSize {algorithm mode} {
    set ivSize 32
    switch $algorithm {
        "3des" - "blowfish" - "cast5" - "gost89" - "idea" - "magma" - "misty1" - "rc2" - "rc5" { set ivSize 16 }
        "aes" - "serpent" - "aria" - "lea" - "anubis" - "twofish" - "sm4" - "camellia" - "kuznechik" - "seed" - "hc128" - "zuc128" { set ivSize 32 }
        "zuc256" { set ivSize 46 }
        "hc256" - "skein512" - "threefish" - "kalyna256_256" - "shacal2" { set ivSize 64 }
        "kalyna512_512" - "threefish512" { set ivSize 128 }
        "rc4" - "chacha20poly1305" { set ivSize 0 }
        "salsa20" - "chacha20" { set ivSize 48 }
    }
    switch $mode {
        "ecb" - "gcm" - "ocb1" - "ocb3" - "mgm" - "ccm" - "eax" { set ivSize 0 }
    }
    if {$mode == "ige"} { set ivSize [expr {2 * $ivSize}] }
    return $ivSize
}

# Functions for text processing
proc encrypt {} {
    set plaintext [.nb.text_tab.main.plain_frame.textframe.text get 1.0 end]
    set key [.nb.text_tab.main.keys_frame.keyBox get]
    set iv [.nb.text_tab.main.keys_frame.ivBox get]
    set salt [.nb.text_tab.main.algo_frame.row2.saltBox get]
    set iter [.nb.text_tab.main.algo_frame.row2.iterBox get]
    set algorithm [.nb.text_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.text_tab.main.algo_frame.row1.modeCombo get]
    set pbkdf2Hash [.nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo get]

    set kdfOptionAlgorithm ""
    if {$::useKDFAlgorithm == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    set ivSize [calculateIVSize $algorithm $mode]

    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .nb.text_tab.main.keys_frame.ivBox delete 0 end
        .nb.text_tab.main.keys_frame.ivBox insert 0 $iv
    }

    set encryptedMsg [exec edgetk -crypt enc -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash << $plaintext | base64]
    .nb.text_tab.main.cipher_frame.textframe.text delete 1.0 end
    .nb.text_tab.main.cipher_frame.textframe.text insert 1.0 $encryptedMsg
}

proc decrypt {} {
    set ciphertext [.nb.text_tab.main.cipher_frame.textframe.text get 1.0 end]
    set key [.nb.text_tab.main.keys_frame.keyBox get]
    set iv [.nb.text_tab.main.keys_frame.ivBox get]
    set salt [.nb.text_tab.main.algo_frame.row2.saltBox get]
    set iter [.nb.text_tab.main.algo_frame.row2.iterBox get]
    set algorithm [.nb.text_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.text_tab.main.algo_frame.row1.modeCombo get]
    set pbkdf2Hash [.nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo get]

    set kdfOptionAlgorithm ""
    if {$::useKDFAlgorithm == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    set ivSize [calculateIVSize $algorithm $mode]

    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .nb.text_tab.main.keys_frame.ivBox delete 0 end
        .nb.text_tab.main.keys_frame.ivBox insert 0 $iv
    }

    set decryptedMsg [exec base64 -d << $ciphertext | edgetk -crypt dec -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash]
    .nb.text_tab.main.plain_frame.textframe.text delete 1.0 end
    .nb.text_tab.main.plain_frame.textframe.text insert 1.0 $decryptedMsg
}

# Functions for file processing
proc encryptFile {} {
    set inputFile [.nb.file_tab.main.file_selection.input_frame.path get]
    set outputFile [.nb.file_tab.main.file_selection.output_frame.path get]
    
    if {$inputFile eq ""} {
        updateStatus "ERROR: Please select an input file first!"
        return
    }
    
    if {$outputFile eq ""} {
        updateStatus "ERROR: Please specify an output file!"
        return
    }
    
    if {![file exists $inputFile]} {
        updateStatus "ERROR: Input file does not exist!"
        return
    }
    
    set key [.nb.file_tab.main.keys_frame.keyBox get]
    set iv [.nb.file_tab.main.keys_frame.ivBox get]
    set salt [.nb.file_tab.main.algo_frame.row2.saltBox get]
    set iter [.nb.file_tab.main.algo_frame.row2.iterBox get]
    set algorithm [.nb.file_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.file_tab.main.algo_frame.row1.modeCombo get]
    set pbkdf2Hash [.nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo get]

    set kdfOptionAlgorithm ""
    if {$::useKDFAlgorithmFiles == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    set ivSize [calculateIVSize $algorithm $mode]

    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .nb.file_tab.main.keys_frame.ivBox delete 0 end
        .nb.file_tab.main.keys_frame.ivBox insert 0 $iv
    }
    
    updateStatus "Encrypting file: [file tail $inputFile]\nOutput: [file tail $outputFile]\nPlease wait..."
    update
    
    # Construir comando edgetk
    set cmd "edgetk -crypt enc -key \"$key\" -iv \"$iv\" -cipher \"$algorithm\" -mode \"$mode\""
    
    if {$kdfOptionAlgorithm ne ""} {
        append cmd " -kdf \"$kdfOptionAlgorithm\" -salt \"$salt\" -iter \"$iter\" -md \"$pbkdf2Hash\""
    }
    
    # Adicionar arquivo de entrada e redirecionar stdout para arquivo de saída
    append cmd " \"$inputFile\" > \"$outputFile\""
    
    if {[catch {
        exec {*}$cmd
    } errorMsg]} {
        updateStatus "ERROR: Encryption failed!\n$errorMsg"
        return
    }
    
    updateStatus "SUCCESS: File encrypted!\nInput: [file tail $inputFile]\nOutput: [file tail $outputFile]\nSize: [formatSize [file size $outputFile]]"
}

proc decryptFile {} {
    set inputFile [.nb.file_tab.main.file_selection.input_frame.path get]
    set outputFile [.nb.file_tab.main.file_selection.output_frame.path get]
    
    if {$inputFile eq ""} {
        updateStatus "ERROR: Please select an input file first!"
        return
    }
    
    if {$outputFile eq ""} {
        updateStatus "ERROR: Please specify an output file!"
        return
    }
    
    if {![file exists $inputFile]} {
        updateStatus "ERROR: Input file does not exist!"
        return
    }
    
    set key [.nb.file_tab.main.keys_frame.keyBox get]
    set iv [.nb.file_tab.main.keys_frame.ivBox get]
    set salt [.nb.file_tab.main.algo_frame.row2.saltBox get]
    set iter [.nb.file_tab.main.algo_frame.row2.iterBox get]
    set algorithm [.nb.file_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.file_tab.main.algo_frame.row1.modeCombo get]
    set pbkdf2Hash [.nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo get]

    set kdfOptionAlgorithm ""
    if {$::useKDFAlgorithmFiles == 1} {
        set kdfOptionAlgorithm "pbkdf2"
    }

    set ivSize [calculateIVSize $algorithm $mode]

    if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
        set iv [string repeat "0" $ivSize]
        .nb.file_tab.main.keys_frame.ivBox delete 0 end
        .nb.file_tab.main.keys_frame.ivBox insert 0 $iv
    }
    
    updateStatus "Decrypting file: [file tail $inputFile]\nOutput: [file tail $outputFile]\nPlease wait..."
    update
    
    # Construir comando edgetk
    set cmd "edgetk -crypt dec -key \"$key\" -iv \"$iv\" -cipher \"$algorithm\" -mode \"$mode\""
    
    if {$kdfOptionAlgorithm ne ""} {
        append cmd " -kdf \"$kdfOptionAlgorithm\" -salt \"$salt\" -iter \"$iter\" -md \"$pbkdf2Hash\""
    }
    
    # Adicionar arquivo de entrada e redirecionar stdout para arquivo de saída
    append cmd " \"$inputFile\" > \"$outputFile\""
    
    if {[catch {
        exec {*}$cmd
    } errorMsg]} {
        updateStatus "ERROR: Decryption failed!\n$errorMsg"
        return
    }
    
    updateStatus "SUCCESS: File decrypted!\nInput: [file tail $inputFile]\nOutput: [file tail $outputFile]\nSize: [formatSize [file size $outputFile]]"
}

# ===== FIM DAS FUNÇÕES COMPARTILHADAS =====

# Main window configuration
wm title . "EDGE Crypto Suite - Professional Cryptographic Toolkit"
wm geometry . 850x650
wm minsize . 800 600

# Configure main window background
. configure -background $bg_color

# Button styling
option add *Button*background $button_color
option add *Button*foreground white
option add *Button*font {Arial 9 bold}
option add *Button*relief flat
option add *Button*pady 3

# Label styling
option add *Label*background $bg_color
option add *Label*font {Arial 9}
option add *Label*foreground $accent_color

# Entry and combobox styling
option add *Entry*background white
option add *Entry*font {Arial 9}
option add *Entry*relief solid
option add *Entry*bd 1
option add *Combobox*background white
option add *Combobox*font {Arial 9}

# Text widget styling
option add *Text*background $text_bg
option add *Text*font {Consolas 9}
option add *Text*relief solid
option add *Text*bd 1

# Checkbutton styling
option add *Checkbutton*background $bg_color
option add *Checkbutton*font {Arial 9}

# Create header frame
frame .header -bg $accent_color -height 60
pack .header -fill x

# Title in header
label .header.title -text "EDGE CRYPTO SUITE v1" \
    -bg $accent_color -fg white -font {Arial 14 bold}
pack .header.title -pady 2

# Subtitle
label .header.subtitle -text "Professional Cryptographic Toolkit - Bulk Encryption + ECDH + MAC" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .header.subtitle -pady 0

# Notebook for tabs (Text, Files, ECDH, and MAC)
ttk::notebook .nb
pack .nb -fill both -expand yes -padx 8 -pady 5

# Notebook style configuration
ttk::style configure TNotebook -background $bg_color
ttk::style configure TNotebook.Tab -padding {10 5}
ttk::style map TNotebook.Tab \
    -background [list selected $accent_color !selected $frame_color] \
    -foreground [list selected white !selected $accent_color]

# ========== TEXT TAB (ORIGINAL LAYOUT) ==========
frame .nb.text_tab -bg $bg_color
.nb add .nb.text_tab -text " Encrypt Text "

# Main frame for content (Text)
frame .nb.text_tab.main -bg $bg_color
pack .nb.text_tab.main -fill both -expand yes

# Grid configuration for expansion (Text)
grid columnconfigure .nb.text_tab.main 0 -weight 1
grid rowconfigure .nb.text_tab.main 8 -weight 1

# Algorithm configuration frame (Text)
frame .nb.text_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.algo_frame -row 0 -column 0 -columnspan 6 -sticky "ew" -padx 8 -pady 5

# Título ALGORITHM SETTINGS
label .nb.text_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" \
    -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.text_tab.main.algo_frame.title -anchor w -padx 8 -pady 5

# Row 1: Algorithm and Mode (Text)
frame .nb.text_tab.main.algo_frame.row1 -bg $frame_color
pack .nb.text_tab.main.algo_frame.row1 -fill x -padx 8 -pady 3

label .nb.text_tab.main.algo_frame.row1.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.text_tab.main.algo_frame.row1.algorithmCombo \
    -values {"3des" "aes" "anubis" "aria" "belt" "blowfish" "camellia" "cast5" "chacha20" "chacha20poly1305" "gost89" "hc128" "hc256" "idea" "kalyna128_128" "kalyna128_256" "kalyna256_256" "kalyna512_512" "kcipher2" "kuznechik" "lea" "magma" "misty1" "rc2" "rc4" "rc5" "salsa20" "seed" "serpent" "shacal2" "skein512" "sm4" "threefish" "threefish512" "twofish" "xoodyak" "zuc128" "zuc256"} \
    -width 18 -state readonly
.nb.text_tab.main.algo_frame.row1.algorithmCombo set "aes"

label .nb.text_tab.main.algo_frame.row1.modeLabel -text "Mode:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.text_tab.main.algo_frame.row1.modeCombo \
    -values {"eax" "gcm" "ocb1" "ocb3" "mgm" "ccm" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"} \
    -width 18 -state readonly
.nb.text_tab.main.algo_frame.row1.modeCombo set "ctr"

pack .nb.text_tab.main.algo_frame.row1.algorithmLabel .nb.text_tab.main.algo_frame.row1.algorithmCombo \
     .nb.text_tab.main.algo_frame.row1.modeLabel .nb.text_tab.main.algo_frame.row1.modeCombo -side left -padx 5

# Row 2: KDF settings (Text)
frame .nb.text_tab.main.algo_frame.row2 -bg $frame_color
pack .nb.text_tab.main.algo_frame.row2 -fill x -padx 8 -pady 3

checkbutton .nb.text_tab.main.algo_frame.row2.kdfAlgorithmCheckbox -text "Use KDF" \
    -variable ::useKDFAlgorithm -font {Arial 9} -bg $frame_color \
    -command updateKeyEntryDisplay

label .nb.text_tab.main.algo_frame.row2.saltLabel -text "Salt:" -font {Arial 9 bold} -bg $frame_color
entry .nb.text_tab.main.algo_frame.row2.saltBox -width 12 -font {Arial 9}

label .nb.text_tab.main.algo_frame.row2.iterLabel -text "Iter:" -font {Arial 9 bold} -bg $frame_color
entry .nb.text_tab.main.algo_frame.row2.iterBox -width 6 -font {Arial 9} -textvariable ::iterValue
set ::iterValue 10000

set hashAlgorithms {
    bash224 bash256 bash384 bash512
    belt
    blake2b256 blake2b512
    blake2s128 blake2s256
    blake3
    bmw224 bmw256 bmw384 bmw512
    cubehash256 cubehash512
    echo224 echo256 echo384 echo512
    esch256 esch384
    fugue224 fugue256 fugue384 fugue512
    fugue512
    gost94
    groestl224 groestl256 groestl384 groestl512
    hamsi224 hamsi256 hamsi384 hamsi512
    has160
    jh224 jh256 jh384 jh512
    keccak256 keccak512
    kupyna256 kupyna384 kupyna512
    lsh224 lsh256 lsh384 lsh512 lsh512-224 lsh512-256
    luffa224 luffa256 luffa384 luffa512
    md4 md5
    md6-224 md6-256 md6-384 md6-512
    radiogatun32 radiogatun64
    ripemd128 ripemd160 ripemd256 ripemd320
    sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512
    sha512-256
    shake128 shake256
    shavite224 shavite256 shavite384 shavite512
    simd224 simd256 simd384 simd512
    siphash64 siphash
    skein256 skein512
    sm3
    streebog256 streebog512
    tiger tiger2
    whirlpool
    xoodyak
}
ttk::combobox .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo -values $hashAlgorithms -width 12 -state readonly
.nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo set "sha3-256"

pack .nb.text_tab.main.algo_frame.row2.kdfAlgorithmCheckbox .nb.text_tab.main.algo_frame.row2.saltLabel .nb.text_tab.main.algo_frame.row2.saltBox \
     .nb.text_tab.main.algo_frame.row2.iterLabel .nb.text_tab.main.algo_frame.row2.iterBox .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo \
     -side left -padx 3

# Plaintext frame (shorter)
frame .nb.text_tab.main.plain_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.plain_frame -row 1 -column 0 -columnspan 6 -sticky "nsew" -padx 8 -pady 5
grid rowconfigure .nb.text_tab.main.plain_frame 1 -weight 1
grid columnconfigure .nb.text_tab.main.plain_frame 0 -weight 1

label .nb.text_tab.main.plain_frame.label -text "PLAINTEXT" -font {Arial 10 bold} -bg $frame_color
grid .nb.text_tab.main.plain_frame.label -row 0 -column 0 -sticky w -padx 8 -pady 3

# Create plaintext text box with scrollbar (shorter)
frame .nb.text_tab.main.plain_frame.textframe -bg $frame_color
grid .nb.text_tab.main.plain_frame.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 8 -pady 3
grid rowconfigure .nb.text_tab.main.plain_frame.textframe 0 -weight 1
grid columnconfigure .nb.text_tab.main.plain_frame.textframe 0 -weight 1

text .nb.text_tab.main.plain_frame.textframe.text -width 60 -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.text_tab.main.plain_frame.textframe.scroll -command {.nb.text_tab.main.plain_frame.textframe.text yview}
.nb.text_tab.main.plain_frame.textframe.text configure -yscrollcommand {.nb.text_tab.main.plain_frame.textframe.scroll set}
grid .nb.text_tab.main.plain_frame.textframe.text -row 0 -column 0 -sticky "nsew"
grid .nb.text_tab.main.plain_frame.textframe.scroll -row 0 -column 1 -sticky "ns"

# Buttons for plaintext
frame .nb.text_tab.main.plain_frame.buttons -bg $frame_color
grid .nb.text_tab.main.plain_frame.buttons -row 2 -column 0 -sticky "ew" -padx 8 -pady 3

button .nb.text_tab.main.plain_frame.buttons.copy -text "📋 Copy" -command {
    clipboard clear; clipboard append [.nb.text_tab.main.plain_frame.textframe.text get 1.0 end]
} -bg "#27ae60" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.plain_frame.buttons.copy -side left -padx 3

button .nb.text_tab.main.plain_frame.buttons.paste -text "📥 Paste" -command {
    .nb.text_tab.main.plain_frame.textframe.text delete 1.0 end
    .nb.text_tab.main.plain_frame.textframe.text insert 1.0 [clipboard get]
} -bg "#e67e22" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.plain_frame.buttons.paste -side left -padx 3

button .nb.text_tab.main.plain_frame.buttons.clear -text "🗑️ Clear" -command {
    .nb.text_tab.main.plain_frame.textframe.text delete 1.0 end
} -bg "#e74c3c" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.plain_frame.buttons.clear -side left -padx 3

# Ciphertext frame (shorter)
frame .nb.text_tab.main.cipher_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.cipher_frame -row 2 -column 0 -columnspan 6 -sticky "nsew" -padx 8 -pady 5
grid rowconfigure .nb.text_tab.main.cipher_frame 1 -weight 1
grid columnconfigure .nb.text_tab.main.cipher_frame 0 -weight 1

label .nb.text_tab.main.cipher_frame.label -text "CIPHERTEXT (Base64)" -font {Arial 10 bold} -bg $frame_color
grid .nb.text_tab.main.cipher_frame.label -row 0 -column 0 -sticky w -padx 8 -pady 3

# Create ciphertext text box with scrollbar (shorter)
frame .nb.text_tab.main.cipher_frame.textframe -bg $frame_color
grid .nb.text_tab.main.cipher_frame.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 8 -pady 3
grid rowconfigure .nb.text_tab.main.cipher_frame.textframe 0 -weight 1
grid columnconfigure .nb.text_tab.main.cipher_frame.textframe 0 -weight 1

text .nb.text_tab.main.cipher_frame.textframe.text -width 60 -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.text_tab.main.cipher_frame.textframe.scroll -command {.nb.text_tab.main.cipher_frame.textframe.text yview}
.nb.text_tab.main.cipher_frame.textframe.text configure -yscrollcommand {.nb.text_tab.main.cipher_frame.textframe.scroll set}
grid .nb.text_tab.main.cipher_frame.textframe.text -row 0 -column 0 -sticky "nsew"
grid .nb.text_tab.main.cipher_frame.textframe.scroll -row 0 -column 1 -sticky "ns"

# Buttons for ciphertext
frame .nb.text_tab.main.cipher_frame.buttons -bg $frame_color
grid .nb.text_tab.main.cipher_frame.buttons -row 2 -column 0 -sticky "ew" -padx 8 -pady 3

button .nb.text_tab.main.cipher_frame.buttons.copy -text "📋 Copy" -command {
    clipboard clear; clipboard append [.nb.text_tab.main.cipher_frame.textframe.text get 1.0 end]
} -bg "#27ae60" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.cipher_frame.buttons.copy -side left -padx 3

button .nb.text_tab.main.cipher_frame.buttons.paste -text "📥 Paste" -command {
    .nb.text_tab.main.cipher_frame.textframe.text delete 1.0 end
    .nb.text_tab.main.cipher_frame.textframe.text insert 1.0 [clipboard get]
} -bg "#e67e22" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.cipher_frame.buttons.paste -side left -padx 3

button .nb.text_tab.main.cipher_frame.buttons.clear -text "🗑️ Clear" -command {
    .nb.text_tab.main.cipher_frame.textframe.text delete 1.0 end
} -bg "#e74c3c" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.cipher_frame.buttons.clear -side left -padx 3

# Keys frame (more compact)
frame .nb.text_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.keys_frame -row 3 -column 0 -columnspan 6 -sticky "ew" -padx 8 -pady 5

# Create Key label
label .nb.text_tab.main.keys_frame.keyLabel -text "Key:" -font {Arial 9 bold} -width 8 -anchor e
grid .nb.text_tab.main.keys_frame.keyLabel -row 0 -column 0 -sticky e -padx 5 -pady 3

# Create key input box
entry .nb.text_tab.main.keys_frame.keyBox -width 50 -font {Consolas 9} -show ""
grid .nb.text_tab.main.keys_frame.keyBox -row 0 -column 1 -columnspan 4 -sticky "ew" -padx 5 -pady 3
grid columnconfigure .nb.text_tab.main.keys_frame 1 -weight 1

# Create IV label
label .nb.text_tab.main.keys_frame.ivLabel -text "IV:" -font {Arial 9 bold} -width 8 -anchor e
grid .nb.text_tab.main.keys_frame.ivLabel -row 1 -column 0 -sticky e -padx 5 -pady 3

# Create IV input box
entry .nb.text_tab.main.keys_frame.ivBox -width 50 -font {Consolas 9}
grid .nb.text_tab.main.keys_frame.ivBox -row 1 -column 1 -columnspan 4 -sticky "ew" -padx 5 -pady 3

# Action buttons frame
frame .nb.text_tab.main.action_frame -bg $bg_color
grid .nb.text_tab.main.action_frame -row 4 -column 0 -columnspan 6 -sticky "e" -padx 8 -pady 8

# Create Encrypt button
button .nb.text_tab.main.action_frame.encryptButton -text "🔒 Encrypt" \
    -command {encrypt} -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.text_tab.main.action_frame.encryptButton -side left -padx 8

# Create Decrypt button
button .nb.text_tab.main.action_frame.decryptButton -text "🔓 Decrypt" \
    -command {decrypt} -bg "#3498db" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.text_tab.main.action_frame.decryptButton -side left -padx 8

# ========== FILES TAB ==========
frame .nb.file_tab -bg $bg_color
.nb add .nb.file_tab -text " Encrypt Files "

# Main frame for content (Files)
frame .nb.file_tab.main -bg $bg_color
pack .nb.file_tab.main -fill both -expand yes

# Grid configuration for expansion (Files)
grid columnconfigure .nb.file_tab.main 0 -weight 1
grid rowconfigure .nb.file_tab.main 6 -weight 1

# Algorithm configuration frame (Files)
frame .nb.file_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
grid .nb.file_tab.main.algo_frame -row 0 -column 0 -columnspan 3 -sticky "ew" -padx 8 -pady 5

# Título ALGORITHM SETTINGS
label .nb.file_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" \
    -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.file_tab.main.algo_frame.title -anchor w -padx 8 -pady 5

# Row 1: Algorithm and Mode (Files)
frame .nb.file_tab.main.algo_frame.row1 -bg $frame_color
pack .nb.file_tab.main.algo_frame.row1 -fill x -padx 8 -pady 3

label .nb.file_tab.main.algo_frame.row1.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.file_tab.main.algo_frame.row1.algorithmCombo \
    -values {"3des" "aes" "anubis" "aria" "belt" "blowfish" "camellia" "cast5" "chacha20" "chacha20poly1305" "gost89" "hc128" "hc256" "idea" "kalyna128_128" "kalyna128_256" "kalyna256_256" "kalyna512_512" "kcipher2" "kuznechik" "lea" "magma" "misty1" "rc2" "rc4" "rc5" "salsa20" "seed" "serpent" "shacal2" "skein512" "sm4" "threefish" "threefish512" "twofish" "xoodyak" "zuc128" "zuc256"} \
    -width 18 -state readonly
.nb.file_tab.main.algo_frame.row1.algorithmCombo set "aes"

label .nb.file_tab.main.algo_frame.row1.modeLabel -text "Mode:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.file_tab.main.algo_frame.row1.modeCombo \
    -values {"eax" "gcm" "ocb1" "ocb3" "mgm" "ccm" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"} \
    -width 18 -state readonly
.nb.file_tab.main.algo_frame.row1.modeCombo set "ctr"

pack .nb.file_tab.main.algo_frame.row1.algorithmLabel .nb.file_tab.main.algo_frame.row1.algorithmCombo \
     .nb.file_tab.main.algo_frame.row1.modeLabel .nb.file_tab.main.algo_frame.row1.modeCombo -side left -padx 5

# Row 2: KDF settings (Files)
frame .nb.file_tab.main.algo_frame.row2 -bg $frame_color
pack .nb.file_tab.main.algo_frame.row2 -fill x -padx 8 -pady 3

checkbutton .nb.file_tab.main.algo_frame.row2.kdfAlgorithmCheckbox -text "Use KDF" \
    -variable ::useKDFAlgorithmFiles -font {Arial 9} -bg $frame_color \
    -command updateKeyEntryDisplayFiles

label .nb.file_tab.main.algo_frame.row2.saltLabel -text "Salt:" -font {Arial 9 bold} -bg $frame_color
entry .nb.file_tab.main.algo_frame.row2.saltBox -width 12 -font {Arial 9}

label .nb.file_tab.main.algo_frame.row2.iterLabel -text "Iter:" -font {Arial 9 bold} -bg $frame_color
entry .nb.file_tab.main.algo_frame.row2.iterBox -width 6 -font {Arial 9} -textvariable ::iterValueFiles
set ::iterValueFiles 10000

set hashAlgorithms {
    bash224 bash256 bash384 bash512
    belt
    blake2b256 blake2b512
    blake2s128 blake2s256
    blake3
    bmw224 bmw256 bmw384 bmw512
    cubehash256 cubehash512
    echo224 echo256 echo384 echo512
    esch256 esch384
    fugue224 fugue256 fugue384 fugue512
    fugue512
    gost94
    groestl224 groestl256 groestl384 groestl512
    hamsi224 hamsi256 hamsi384 hamsi512
    has160
    jh224 jh256 jh384 jh512
    keccak256 keccak512
    kupyna256 kupyna384 kupyna512
    lsh224 lsh256 lsh384 lsh512 lsh512-224 lsh512-256
    luffa224 luffa256 luffa384 luffa512
    md4 md5
    md6-224 md6-256 md6-384 md6-512
    radiogatun32 radiogatun64
    ripemd128 ripemd160 ripemd256 ripemd320
    sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512
    sha512-256
    shake128 shake256
    shavite224 shavite256 shavite384 shavite512
    simd224 simd256 simd384 simd512
    siphash64 siphash
    skein256 skein512
    sm3
    streebog256 streebog512
    tiger tiger2
    whirlpool
    xoodyak
}
ttk::combobox .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo -values $hashAlgorithms -width 12 -state readonly
.nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo set "sha3-256"

pack .nb.file_tab.main.algo_frame.row2.kdfAlgorithmCheckbox .nb.file_tab.main.algo_frame.row2.saltLabel .nb.file_tab.main.algo_frame.row2.saltBox \
     .nb.file_tab.main.algo_frame.row2.iterLabel .nb.file_tab.main.algo_frame.row2.iterBox .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo \
     -side left -padx 3

# File selection frame (compact - both input and output)
frame .nb.file_tab.main.file_selection -bg $frame_color -relief solid -bd 1
grid .nb.file_tab.main.file_selection -row 1 -column 0 -columnspan 3 -sticky "ew" -padx 8 -pady 5

label .nb.file_tab.main.file_selection.label -text "FILE SELECTION" -font {Arial 10 bold} -bg $frame_color
grid .nb.file_tab.main.file_selection.label -row 0 -column 0 -sticky w -padx 8 -pady 8

# Input file row
frame .nb.file_tab.main.file_selection.input_frame -bg $frame_color
grid .nb.file_tab.main.file_selection.input_frame -row 1 -column 0 -columnspan 3 -sticky "ew" -padx 8 -pady 5
grid columnconfigure .nb.file_tab.main.file_selection.input_frame 0 -weight 1

label .nb.file_tab.main.file_selection.input_frame.label -text "Input File:" -font {Arial 9 bold} -bg $frame_color -width 12 -anchor e
grid .nb.file_tab.main.file_selection.input_frame.label -row 0 -column 0 -sticky e -padx 5

entry .nb.file_tab.main.file_selection.input_frame.path -width 40 -font {Arial 9} \
    -bg white -state readonly
grid .nb.file_tab.main.file_selection.input_frame.path -row 0 -column 1 -sticky "ew" -padx 5

button .nb.file_tab.main.file_selection.input_frame.browse -text "📁 Browse" \
    -command selectInputFile -bg $button_color -fg white -font {Arial 9 bold} \
    -width 10
grid .nb.file_tab.main.file_selection.input_frame.browse -row 0 -column 2 -sticky "e" -padx 5

# Output file row
frame .nb.file_tab.main.file_selection.output_frame -bg $frame_color
grid .nb.file_tab.main.file_selection.output_frame -row 2 -column 0 -columnspan 3 -sticky "ew" -padx 8 -pady 5
grid columnconfigure .nb.file_tab.main.file_selection.output_frame 0 -weight 1

label .nb.file_tab.main.file_selection.output_frame.label -text "Output File:" -font {Arial 9 bold} -bg $frame_color -width 12 -anchor e
grid .nb.file_tab.main.file_selection.output_frame.label -row 0 -column 0 -sticky e -padx 5

entry .nb.file_tab.main.file_selection.output_frame.path -width 40 -font {Arial 9} \
    -bg white
grid .nb.file_tab.main.file_selection.output_frame.path -row 0 -column 1 -sticky "ew" -padx 5

button .nb.file_tab.main.file_selection.output_frame.browse -text "📁 Browse" \
    -command selectOutputFile -bg $button_color -fg white -font {Arial 9 bold} \
    -width 10
grid .nb.file_tab.main.file_selection.output_frame.browse -row 0 -column 2 -sticky "e" -padx 5

# Keys frame (Files)
frame .nb.file_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
grid .nb.file_tab.main.keys_frame -row 2 -column 0 -columnspan 3 -sticky "ew" -padx 8 -pady 5

# Create Key label (Files)
label .nb.file_tab.main.keys_frame.keyLabel -text "Key:" -font {Arial 9 bold} -width 8 -anchor e
grid .nb.file_tab.main.keys_frame.keyLabel -row 0 -column 0 -sticky e -padx 5 -pady 8

# Create key input box (Files)
entry .nb.file_tab.main.keys_frame.keyBox -width 50 -font {Consolas 9} -show ""
grid .nb.file_tab.main.keys_frame.keyBox -row 0 -column 1 -columnspan 2 -sticky "ew" -padx 5 -pady 3
grid columnconfigure .nb.file_tab.main.keys_frame 1 -weight 1

# Create IV label (Files)
label .nb.file_tab.main.keys_frame.ivLabel -text "IV:" -font {Arial 9 bold} -width 8 -anchor e
grid .nb.file_tab.main.keys_frame.ivLabel -row 1 -column 0 -sticky e -padx 5 -pady 3

# Create IV input box (Files)
entry .nb.file_tab.main.keys_frame.ivBox -width 50 -font {Consolas 9}
grid .nb.file_tab.main.keys_frame.ivBox -row 1 -column 1 -columnspan 2 -sticky "ew" -padx 5 -pady 8

# Action buttons frame (Files)
frame .nb.file_tab.main.action_frame -bg $bg_color
grid .nb.file_tab.main.action_frame -row 3 -column 0 -columnspan 3 -sticky "e" -padx 8 -pady 15

# Buttons for file processing
button .nb.file_tab.main.action_frame.encryptButton -text "🔒 Encrypt File" \
    -command {encryptFile} -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.file_tab.main.action_frame.encryptButton -side left -padx 8

button .nb.file_tab.main.action_frame.decryptButton -text "🔓 Decrypt File" \
    -command {decryptFile} -bg "#3498db" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.file_tab.main.action_frame.decryptButton -side left -padx 8

# Status frame (Files)
frame .nb.file_tab.main.status_frame -bg $frame_color -relief solid -bd 1
grid .nb.file_tab.main.status_frame -row 6 -column 0 -columnspan 3 -sticky "nsew" -padx 8 -pady 5
grid rowconfigure .nb.file_tab.main.status_frame 1 -weight 1
grid columnconfigure .nb.file_tab.main.status_frame 0 -weight 1

label .nb.file_tab.main.status_frame.label -text "STATUS" -font {Arial 10 bold} -bg $frame_color
grid .nb.file_tab.main.status_frame.label -row 0 -column 0 -sticky w -padx 8 -pady 5

# Status area
text .nb.file_tab.main.status_frame.text -width 60 -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1 -state disabled
grid .nb.file_tab.main.status_frame.text -row 1 -column 0 -sticky "nsew" -padx 8 -pady 5

# ========== ECDH TAB ==========
frame .nb.ecdh_tab -bg $bg_color
.nb add .nb.ecdh_tab -text " Diffie-Hellman "

# Main frame for content (ECDH)
frame .nb.ecdh_tab.main -bg $bg_color
pack .nb.ecdh_tab.main -fill both -expand yes -padx 8 -pady 5

# Frame para configurações de algoritmo
frame .nb.ecdh_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.ecdh_tab.main.algo_frame.title -text "CRYPTOGRAPHIC SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.ecdh_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.ecdh_tab.main.algo_frame.content -bg $frame_color
pack .nb.ecdh_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Create Algorithm ComboBox
set ::algorithmComboData {"ecdsa" "sm2" "gost2012" "x25519" "x448"}
label .nb.ecdh_tab.main.algo_frame.content.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.algo_frame.content.algorithmCombo -values $::algorithmComboData -state readonly -width 12
.nb.ecdh_tab.main.algo_frame.content.algorithmCombo set "ecdsa"

# Create Bits ComboBox
set ::bitsComboData {"224" "256" "384" "512" "521"}
label .nb.ecdh_tab.main.algo_frame.content.bitsLabel -text "Bits:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.algo_frame.content.bitsCombo -values $::bitsComboData -state readonly -width 8
.nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"

# Create Paramset ComboBox
set ::paramsetComboData {"A" "B" "C" "D"}
label .nb.ecdh_tab.main.algo_frame.content.paramsetLabel -text "Paramset:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.algo_frame.content.paramsetCombo -values $::paramsetComboData -state readonly -width 8
.nb.ecdh_tab.main.algo_frame.content.paramsetCombo set "A"

# Create Output Key Size ComboBox
set ::outputKeySizeComboData {"16" "24" "32" "40" "64"}
label .nb.ecdh_tab.main.algo_frame.content.outputKeySizeLabel -text "Out Size:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo -values $::outputKeySizeComboData -state readonly -width 8
.nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo set "32"

# Grid para configurações de algoritmo
grid .nb.ecdh_tab.main.algo_frame.content.algorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.algorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.bitsLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.bitsCombo -row 0 -column 3 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.paramsetLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.paramsetCombo -row 1 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.outputKeySizeLabel -row 1 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo -row 1 -column 3 -sticky w -padx 3 -pady 3

# Frame para gerenciamento de chaves
frame .nb.ecdh_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.keys_frame -fill x -padx 8 -pady 5

label .nb.ecdh_tab.main.keys_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color
pack .nb.ecdh_tab.main.keys_frame.title -anchor w -padx 8 -pady 3

frame .nb.ecdh_tab.main.keys_frame.content -bg $frame_color
pack .nb.ecdh_tab.main.keys_frame.content -fill x -padx 8 -pady 3

# Private Key
label .nb.ecdh_tab.main.keys_frame.content.privateKeyLabel -text "Private Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.privateKeyInput -width 40 -font {Consolas 9}
button .nb.ecdh_tab.main.keys_frame.content.generateButton -text "🔑 Generate" -command generateECDHKey \
    -bg "#27ae60" -fg white -font {Arial 9 bold}

grid .nb.ecdh_tab.main.keys_frame.content.privateKeyLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.privateKeyInput -row 0 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.generateButton -row 0 -column 2 -sticky w -padx 3 -pady 3

# Public Key
label .nb.ecdh_tab.main.keys_frame.content.publicKeyLabel -text "Public Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.publicKeyInput -width 40 -font {Consolas 9}

grid .nb.ecdh_tab.main.keys_frame.content.publicKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.publicKeyInput -row 1 -column 1 -sticky ew -padx 3 -pady 3

# Peer Key
label .nb.ecdh_tab.main.keys_frame.content.peerKeyLabel -text "Peer Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.peerKeyInput -width 40 -font {Consolas 9}
button .nb.ecdh_tab.main.keys_frame.content.openPeerKeyButton -text "📂 Open" -command openPeerKey \
    -bg "#3498db" -fg white -font {Arial 9 bold}

grid .nb.ecdh_tab.main.keys_frame.content.peerKeyLabel -row 2 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.peerKeyInput -row 2 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.openPeerKeyButton -row 2 -column 2 -sticky w -padx 3 -pady 3

# Configure column weights
grid columnconfigure .nb.ecdh_tab.main.keys_frame.content 1 -weight 1

# Frame para KDF
frame .nb.ecdh_tab.main.kdf_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.kdf_frame -fill x -padx 8 -pady 5

label .nb.ecdh_tab.main.kdf_frame.title -text "KEY DERIVATION SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.ecdh_tab.main.kdf_frame.title -anchor w -padx 8 -pady 3

frame .nb.ecdh_tab.main.kdf_frame.content -bg $frame_color
pack .nb.ecdh_tab.main.kdf_frame.content -fill x -padx 8 -pady 3

# Hash Algorithm ComboBox
set ::hashAlgorithmComboData {
    bash224 bash256 bash384 bash512
    belt
    blake2b256 blake2b512
    blake2s128 blake2s256
    blake3
    bmw224 bmw256 bmw384 bmw512
    cubehash256 cubehash512
    echo224 echo256 echo384 echo512
    esch256 esch384
    fugue224 fugue256 fugue384 fugue512
    fugue512
    gost94
    groestl224 groestl256 groestl384 groestl512
    hamsi224 hamsi256 hamsi384 hamsi512
    has160
    jh224 jh256 jh384 jh512
    keccak256 keccak512
    kupyna256 kupyna384 kupyna512
    lsh224 lsh256 lsh384 lsh512 lsh512-224 lsh512-256
    luffa224 luffa256 luffa384 luffa512
    md4 md5
    md6-224 md6-256 md6-384 md6-512
    radiogatun32 radiogatun64
    ripemd128 ripemd160 ripemd256 ripemd320
    sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512
    sha512-256
    shake128 shake256
    shavite224 shavite256 shavite384 shavite512
    simd224 simd256 simd384 simd512
    siphash64 siphash
    skein256 skein512
    sm3
    streebog256 streebog512
    tiger tiger2
    whirlpool
    xoodyak
}
label .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmLabel -text "Hash:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo -values $::hashAlgorithmComboData -state readonly -width 15
.nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo set "sha3-256"

# Salt Input
label .nb.ecdh_tab.main.kdf_frame.content.saltLabel -text "Salt:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.kdf_frame.content.saltInput -width 25 -font {Consolas 9}

grid .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.saltLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.saltInput -row 0 -column 3 -sticky ew -padx 3 -pady 3

grid columnconfigure .nb.ecdh_tab.main.kdf_frame.content 3 -weight 1

# Frame para saída
frame .nb.ecdh_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.output_frame -fill both -expand true -padx 8 -pady 5

label .nb.ecdh_tab.main.output_frame.title -text "SHARED SECRET OUTPUT" -font {Arial 10 bold} -bg $frame_color
pack .nb.ecdh_tab.main.output_frame.title -anchor w -padx 8 -pady 3

# Create output text area with scrollbar
frame .nb.ecdh_tab.main.output_frame.textframe -bg $frame_color
pack .nb.ecdh_tab.main.output_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.ecdh_tab.main.output_frame.textframe.outputArea -width 60 -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.ecdh_tab.main.output_frame.textframe.scroll -command {.nb.ecdh_tab.main.output_frame.textframe.outputArea yview}
.nb.ecdh_tab.main.output_frame.textframe.outputArea configure -yscrollcommand {.nb.ecdh_tab.main.output_frame.textframe.scroll set}

grid .nb.ecdh_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.ecdh_tab.main.output_frame.textframe.scroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.ecdh_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.ecdh_tab.main.output_frame.textframe 0 -weight 1

# Botões para output
frame .nb.ecdh_tab.main.output_frame.buttons -bg $frame_color
pack .nb.ecdh_tab.main.output_frame.buttons -fill x -padx 8 -pady 3

button .nb.ecdh_tab.main.output_frame.buttons.deriveButton -text "🔄 Derive" -command deriveECDHKey \
    -bg "#9b59b6" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.deriveButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.hkdfButton -text "🔐 HKDF" -command executeECDHHKDF \
    -bg "#e67e22" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.hkdfButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.copyButton -text "📋 Copy" -command {
    copyText [.nb.ecdh_tab.main.output_frame.textframe.outputArea get 1.0 end]
} -bg "#27ae60" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.copyButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.clearButton -text "🗑️ Clear" -command {
    .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
} -bg "#e74c3c" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.clearButton -side left -padx 3

# ========== MAC TEXT TAB ==========
frame .nb.mac_tab -bg $bg_color
.nb add .nb.mac_tab -text " MAC Text "

# Main frame for content (MAC Text)
frame .nb.mac_tab.main -bg $bg_color
pack .nb.mac_tab.main -fill both -expand true

# Frame for algorithm settings
frame .nb.mac_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.mac_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.mac_tab.main.algo_frame.content -bg $frame_color
pack .nb.mac_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Create Algorithm ComboBox
set macAlgorithms {"hmac" "cmac" "chaskey" "gost" "poly1305" "siphash" "skein" "xoodyak" "eia128" "eia256" "pmac" "vmac"}
label .nb.mac_tab.main.algo_frame.content.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_tab.main.algo_frame.content.algorithmCombo -values $macAlgorithms -state readonly -width 12
.nb.mac_tab.main.algo_frame.content.algorithmCombo set "hmac"

# Create Hash ComboBox for HMAC
set hmacHashes {
    bash224 bash256 bash384 bash512
    belt
    blake2b256 blake2b512
    blake2s128 blake2s256
    blake3
    bmw224 bmw256 bmw384 bmw512
    cubehash256 cubehash512
    echo224 echo256 echo384 echo512
    esch256 esch384
    fugue224 fugue256 fugue384 fugue512
    fugue512
    gost94
    groestl224 groestl256 groestl384 groestl512
    hamsi224 hamsi256 hamsi384 hamsi512
    has160
    jh224 jh256 jh384 jh512
    keccak256 keccak512
    kupyna256 kupyna384 kupyna512
    lsh224 lsh256 lsh384 lsh512 lsh512-224 lsh512-256
    luffa224 luffa256 luffa384 luffa512
    md4 md5
    md6-224 md6-256 md6-384 md6-512
    radiogatun32 radiogatun64
    ripemd128 ripemd160 ripemd256 ripemd320
    sha1 sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512
    sha512-256
    shake128 shake256
    shavite224 shavite256 shavite384 shavite512
    simd224 simd256 simd384 simd512
    siphash64 siphash
    skein256 skein512
    sm3
    streebog256 streebog512
    tiger tiger2
    whirlpool
    xoodyak
}
label .nb.mac_tab.main.algo_frame.content.hashLabel -text "Hash:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_tab.main.algo_frame.content.hmacHashCombo -values $hmacHashes -state readonly -width 12
.nb.mac_tab.main.algo_frame.content.hmacHashCombo set "sha3-256"

# Create Cipher ComboBox for CMAC/PMAC/VMAC
set cmacCiphers {
    3des
    aes
    anubis
    aria
    belt
    blowfish
    camellia
    cast5
    cast256
    clefia
    crypton
    curupira
    e2
    gost89
    hight
    idea
    kalyna128_128
    kalyna128_256
    kalyna256_256
    kalyna256_512
    kalyna512_512
    khazad
    kuznechik
    lea
    loki97
    magma
    magenta
    mars
    misty1
    noekeon
    present
    rc2
    rc5
    rc6
    safer+
    seed
    serpent
    shacal2
    sm4
    threefish256
    threefish512
    threefish1024
    twine
    twofish
}

label .nb.mac_tab.main.algo_frame.content.cipherLabel -text "Cipher:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_tab.main.algo_frame.content.cmacCipherCombo -values $cmacCiphers -state readonly -width 12
.nb.mac_tab.main.algo_frame.content.cmacCipherCombo set "aes"

# Out Size ComboBox para VMAC (Text)
label .nb.mac_tab.main.algo_frame.content.outSizeLabel -text "Out Size:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_tab.main.algo_frame.content.outSizeCombo -values {8 16 32} -state readonly -width 6
.nb.mac_tab.main.algo_frame.content.outSizeCombo set "8"

# Grid for algorithm settings
grid .nb.mac_tab.main.algo_frame.content.algorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.algorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.hashLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.hmacHashCombo -row 0 -column 3 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.outSizeLabel -row 0 -column 4 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.outSizeCombo -row 0 -column 5 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.cipherLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.algo_frame.content.cmacCipherCombo -row 1 -column 1 -sticky w -padx 3 -pady 3

# Frame for key management
frame .nb.mac_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.keys_frame -fill x -padx 8 -pady 5

label .nb.mac_tab.main.keys_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.keys_frame.title -anchor w -padx 8 -pady 3

frame .nb.mac_tab.main.keys_frame.content -bg $frame_color
pack .nb.mac_tab.main.keys_frame.content -fill x -padx 8 -pady 3

# Key Entry
label .nb.mac_tab.main.keys_frame.content.keyLabel -text "Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.mac_tab.main.keys_frame.content.keyEntry -width 50 -font {Consolas 9}
grid .nb.mac_tab.main.keys_frame.content.keyLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.keys_frame.content.keyEntry -row 0 -column 1 -sticky ew -padx 3 -pady 3

# IV Entry
label .nb.mac_tab.main.keys_frame.content.ivLabel -text "IV:" -font {Arial 9 bold} -bg $frame_color
entry .nb.mac_tab.main.keys_frame.content.ivEntry -width 50 -font {Consolas 9}
grid .nb.mac_tab.main.keys_frame.content.ivLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.keys_frame.content.ivEntry -row 1 -column 1 -sticky ew -padx 3 -pady 3

grid columnconfigure .nb.mac_tab.main.keys_frame.content 1 -weight 1

# Frame for message input
frame .nb.mac_tab.main.input_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.input_frame -fill both -expand true -padx 8 -pady 5

label .nb.mac_tab.main.input_frame.title -text "MESSAGE INPUT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.input_frame.title -anchor w -padx 8 -pady 3

# Create Message input area with scrollbar
frame .nb.mac_tab.main.input_frame.textframe -bg $frame_color
pack .nb.mac_tab.main.input_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.mac_tab.main.input_frame.textframe.messageBox -width 60 -height 4 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.mac_tab.main.input_frame.textframe.messageScroll -command {.nb.mac_tab.main.input_frame.textframe.messageBox yview}
.nb.mac_tab.main.input_frame.textframe.messageBox configure -yscrollcommand {.nb.mac_tab.main.input_frame.textframe.messageScroll set}

grid .nb.mac_tab.main.input_frame.textframe.messageBox -row 0 -column 0 -sticky "nsew"
grid .nb.mac_tab.main.input_frame.textframe.messageScroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.mac_tab.main.input_frame.textframe 0 -weight 1
grid columnconfigure .nb.mac_tab.main.input_frame.textframe 0 -weight 1

# Frame for output
frame .nb.mac_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.output_frame -fill both -expand true -padx 8 -pady 5

label .nb.mac_tab.main.output_frame.title -text "MAC RESULT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.output_frame.title -anchor w -padx 8 -pady 3

# Create Result text area with scrollbar
frame .nb.mac_tab.main.output_frame.textframe -bg $frame_color
pack .nb.mac_tab.main.output_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.mac_tab.main.output_frame.textframe.resultBox -width 60 -height 4 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1 -state disabled
scrollbar .nb.mac_tab.main.output_frame.textframe.resultScroll -command {.nb.mac_tab.main.output_frame.textframe.resultBox yview}
.nb.mac_tab.main.output_frame.textframe.resultBox configure -yscrollcommand {.nb.mac_tab.main.output_frame.textframe.resultScroll set}

grid .nb.mac_tab.main.output_frame.textframe.resultBox -row 0 -column 0 -sticky "nsew"
grid .nb.mac_tab.main.output_frame.textframe.resultScroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.mac_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.mac_tab.main.output_frame.textframe 0 -weight 1

# Action buttons
frame .nb.mac_tab.main.action_frame -bg $bg_color
pack .nb.mac_tab.main.action_frame -fill x -padx 8 -pady 8

button .nb.mac_tab.main.action_frame.calculateButton -text "🧮 Calculate MAC" -command calculateMAC \
    -bg "#27ae60" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_tab.main.action_frame.calculateButton -side left -padx 5

button .nb.mac_tab.main.action_frame.copyButton -text "📋 Copy Result" -command copyResult \
    -bg "#3498db" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_tab.main.action_frame.copyButton -side left -padx 5

button .nb.mac_tab.main.action_frame.clearButton -text "🗑️ Clear All" -command {
    .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
    .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
    .nb.mac_tab.main.input_frame.textframe.messageBox delete 1.0 end
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state normal
    .nb.mac_tab.main.output_frame.textframe.resultBox delete 1.0 end
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
} -bg "#e74c3c" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_tab.main.action_frame.clearButton -side left -padx 5

# ========== MAC FILES TAB ==========
frame .nb.mac_file_tab -bg $bg_color
.nb add .nb.mac_file_tab -text " MAC Files "

# Main frame for content (MAC Files)
frame .nb.mac_file_tab.main -bg $bg_color
pack .nb.mac_file_tab.main -fill both -expand true

# Frame for algorithm settings (Files)
frame .nb.mac_file_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_file_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.mac_file_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_file_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.mac_file_tab.main.algo_frame.content -bg $frame_color
pack .nb.mac_file_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Create Algorithm ComboBox (Files)
label .nb.mac_file_tab.main.algo_frame.content.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_file_tab.main.algo_frame.content.algorithmCombo -values $macAlgorithms -state readonly -width 12
.nb.mac_file_tab.main.algo_frame.content.algorithmCombo set "hmac"

# Create Hash ComboBox for HMAC (Files)
label .nb.mac_file_tab.main.algo_frame.content.hashLabel -text "Hash:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo -values $hmacHashes -state readonly -width 12
.nb.mac_file_tab.main.algo_frame.content.hmacHashCombo set "sha3-256"

# Create Cipher ComboBox for CMAC/PMAC/VMAC (Files)
label .nb.mac_file_tab.main.algo_frame.content.cipherLabel -text "Cipher:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo -values $cmacCiphers -state readonly -width 12
.nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo set "aes"

# Out Size ComboBox para VMAC (Files)
label .nb.mac_file_tab.main.algo_frame.content.outSizeLabel -text "Out Size:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.mac_file_tab.main.algo_frame.content.outSizeCombo -values {8 16 32} -state readonly -width 6
.nb.mac_file_tab.main.algo_frame.content.outSizeCombo set "8"

# Grid for algorithm settings (Files)
grid .nb.mac_file_tab.main.algo_frame.content.algorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.algorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.hashLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.hmacHashCombo -row 0 -column 3 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.outSizeLabel -row 0 -column 4 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.outSizeCombo -row 0 -column 5 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.cipherLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.algo_frame.content.cmacCipherCombo -row 1 -column 1 -sticky w -padx 3 -pady 3

# File selection frame
frame .nb.mac_file_tab.main.file_selection -bg $frame_color -relief solid -bd 1
pack .nb.mac_file_tab.main.file_selection -fill x -padx 8 -pady 5

label .nb.mac_file_tab.main.file_selection.title -text "FILE SELECTION" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_file_tab.main.file_selection.title -anchor w -padx 8 -pady 3

# Input file row
frame .nb.mac_file_tab.main.file_selection.input_frame -bg $frame_color
pack .nb.mac_file_tab.main.file_selection.input_frame -fill x -padx 8 -pady 5

label .nb.mac_file_tab.main.file_selection.input_frame.label -text "Input File:" -font {Arial 9 bold} -bg $frame_color -width 12 -anchor e
grid .nb.mac_file_tab.main.file_selection.input_frame.label -row 0 -column 0 -sticky e -padx 5

entry .nb.mac_file_tab.main.file_selection.input_frame.path -width 40 -font {Arial 9} \
    -bg white -state readonly
grid .nb.mac_file_tab.main.file_selection.input_frame.path -row 0 -column 1 -sticky "ew" -padx 5

button .nb.mac_file_tab.main.file_selection.input_frame.browse -text "📁 Browse" \
    -command selectInputFileMAC -bg $button_color -fg white -font {Arial 9 bold} \
    -width 10
grid .nb.mac_file_tab.main.file_selection.input_frame.browse -row 0 -column 2 -sticky "e" -padx 5

grid columnconfigure .nb.mac_file_tab.main.file_selection.input_frame 1 -weight 1

# Frame for key management (Files)
frame .nb.mac_file_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_file_tab.main.keys_frame -fill x -padx 8 -pady 5

label .nb.mac_file_tab.main.keys_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_file_tab.main.keys_frame.title -anchor w -padx 8 -pady 3

frame .nb.mac_file_tab.main.keys_frame.content -bg $frame_color
pack .nb.mac_file_tab.main.keys_frame.content -fill x -padx 8 -pady 3

# Key Entry (Files)
label .nb.mac_file_tab.main.keys_frame.content.keyLabel -text "Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.mac_file_tab.main.keys_frame.content.keyEntry -width 50 -font {Consolas 9}
grid .nb.mac_file_tab.main.keys_frame.content.keyLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.keys_frame.content.keyEntry -row 0 -column 1 -sticky ew -padx 3 -pady 3

# IV Entry (Files)
label .nb.mac_file_tab.main.keys_frame.content.ivLabel -text "IV:" -font {Arial 9 bold} -bg $frame_color
entry .nb.mac_file_tab.main.keys_frame.content.ivEntry -width 50 -font {Consolas 9}
grid .nb.mac_file_tab.main.keys_frame.content.ivLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_file_tab.main.keys_frame.content.ivEntry -row 1 -column 1 -sticky ew -padx 3 -pady 3

grid columnconfigure .nb.mac_file_tab.main.keys_frame.content 1 -weight 1

# Action buttons (Files)
frame .nb.mac_file_tab.main.action_frame -bg $bg_color
pack .nb.mac_file_tab.main.action_frame -fill x -padx 8 -pady 8

button .nb.mac_file_tab.main.action_frame.calculateButton -text "🧮 Calculate MAC" -command calculateMACFile \
    -bg "#27ae60" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_file_tab.main.action_frame.calculateButton -side left -padx 5

button .nb.mac_file_tab.main.action_frame.copyButton -text "📋 Copy Result" -command copyFileResult \
    -bg "#3498db" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_file_tab.main.action_frame.copyButton -side left -padx 5

button .nb.mac_file_tab.main.action_frame.clearButton -text "🗑️ Clear All" -command {
    .nb.mac_file_tab.main.file_selection.input_frame.path configure -state normal
    .nb.mac_file_tab.main.file_selection.input_frame.path delete 0 end
    .nb.mac_file_tab.main.file_selection.input_frame.path configure -state readonly
    .nb.mac_file_tab.main.keys_frame.content.keyEntry delete 0 end
    .nb.mac_file_tab.main.keys_frame.content.ivEntry delete 0 end
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state normal
    .nb.mac_file_tab.main.status_frame.textframe.text delete 1.0 end
    .nb.mac_file_tab.main.status_frame.textframe.text configure -state disabled
} -bg "#e74c3c" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_file_tab.main.action_frame.clearButton -side left -padx 5

# Status frame (Files)
frame .nb.mac_file_tab.main.status_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_file_tab.main.status_frame -fill both -expand true -padx 8 -pady 5

label .nb.mac_file_tab.main.status_frame.title -text "STATUS & RESULT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_file_tab.main.status_frame.title -anchor w -padx 8 -pady 3

# Status area
frame .nb.mac_file_tab.main.status_frame.textframe -bg $frame_color
pack .nb.mac_file_tab.main.status_frame.textframe -fill both -expand true -padx 8 -pady 3

# Create text widget and scrollbar using pack
text .nb.mac_file_tab.main.status_frame.textframe.text -width 60 -height 4 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1 -state disabled
scrollbar .nb.mac_file_tab.main.status_frame.textframe.scroll -command {.nb.mac_file_tab.main.status_frame.textframe.text yview}
.nb.mac_file_tab.main.status_frame.textframe.text configure -yscrollcommand {.nb.mac_file_tab.main.status_frame.textframe.scroll set}

# Pack them side by side
pack .nb.mac_file_tab.main.status_frame.textframe.text -side left -fill both -expand true
pack .nb.mac_file_tab.main.status_frame.textframe.scroll -side right -fill y

# Execute Menu
menu .menubar -tearoff 0 -bg $accent_color -fg white -activebackground $button_hover
. configure -menu .menubar

.menubar add cascade -label "Info" -menu .executeMenu -background $accent_color
menu .executeMenu -tearoff 0 -bg white -fg $accent_color -activebackground $button_color
.executeMenu add command -label "About" -command executeINFOScript

# Footer
frame .footer -bg $accent_color -height 25
pack .footer -fill x
label .footer.text -text "ALBANESE Research Lab © 2024 | Secure Cryptographic Operations" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .footer.text -pady 3

# Configure resizing
grid columnconfigure .nb.text_tab.main.keys_frame 1 -weight 1
grid columnconfigure .nb.file_tab.main.keys_frame 1 -weight 1
grid columnconfigure .nb.mac_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.mac_file_tab.main.keys_frame.content 1 -weight 1

# Bind the combobox to update UI when algorithm changes
bind .nb.mac_tab.main.algo_frame.content.algorithmCombo <<ComboboxSelected>> {updateAlgorithmUI}
bind .nb.mac_file_tab.main.algo_frame.content.algorithmCombo <<ComboboxSelected>> {updateAlgorithmUI}

# Initialize key displays
updateKeyEntryDisplay
updateKeyEntryDisplayFiles
updateAlgorithmUI

# Start the event loop
tkwait visibility .
