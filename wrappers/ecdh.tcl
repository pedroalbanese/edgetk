package require Tk

# Função para copiar o texto para a área de transferência
proc copyText {text} {
    set trimmedText [string trim $text]
    clipboard clear
    clipboard append $trimmedText
}

# Função para abrir o diretório da chave pública
proc openPublicKey {} {
    set public_key_path [.publicKeyInput get]
    set public_key_directory [file dirname $public_key_path]
    exec cmd /c start "" [file nativename $public_key_directory]
}

# Função para abrir a caixa de diálogo de seleção de arquivo para a chave do peer
proc openPeerKey {} {
    set peer_key_path [tk_getOpenFile -defaultextension ".pem" -filetypes {{"PEM Files" ".pem"}}]
    .peerKeyInput delete 0 end
    .peerKeyInput insert 0 $peer_key_path
}

# Função para gerar a chave
proc generateKey {} {
    set private_key_path [file join [pwd] "Private.pem"]
    set public_key_path [file join [pwd] "Public.pem"]
    set algorithmIndex [expr {[lsearch $::algorithmComboData [.algorithmCombo get]]}]
    set bitsIndex [expr {[lsearch $::bitsComboData [.bitsCombo get]]}]
    set paramsetIndex [expr {[lsearch $::paramsetComboData [.paramsetCombo get]]}]
    
    set algorithm [lindex $::algorithmComboData $algorithmIndex]
    set bits [lindex $::bitsComboData $bitsIndex]
    set paramset [lindex $::paramsetComboData $paramsetIndex]

    exec edgetk -pkey keygen -algorithm $algorithm -bits $bits -paramset $paramset -pwd - -priv $private_key_path -pub $public_key_path 2>@1

    .privateKeyInput delete 0 end
    .privateKeyInput insert 0 $private_key_path
    .publicKeyInput delete 0 end
    .publicKeyInput insert 0 $public_key_path
}

# Função para derivar a chave
proc deriveKey {} {
    set private_key_path [.privateKeyInput get]
    set peer_key_path [.peerKeyInput get]

    set algorithmIndex [expr {[lsearch $::algorithmComboData [.algorithmCombo get]]}]
    set algorithm [lindex $::algorithmComboData $algorithmIndex]

    set outputKeySize [lindex $::outputKeySizeComboData [.outputKeySizeCombo current]]

    set result [exec edgetk -pkey derive -algorithm $algorithm -key $private_key_path -pwd - -pub $peer_key_path]

    # Truncar a chave resultante para o tamanho desejado
    set result [string range $result 0 [expr {$outputKeySize * 2 - 1}]]

    .outputArea delete 1.0 end
    .outputArea insert end $result
}

# Função para executar HKDF
proc executeHKDF {} {
    set salt [.saltInput get]
    set hashAlgorithm [lindex $::hashAlgorithmComboData [.hashAlgorithmCombo current]]
    
    set inputKey [string trim [.outputArea get 1.0 end]]
    
    set outputKeySize [lindex $::outputKeySizeComboData [.outputKeySizeCombo current]]
    set outputSize [expr {$outputKeySize * 8}]
    set hkdfResult [exec edgetk -kdf hkdf -salt $salt -md $hashAlgorithm -key $inputKey -bits $outputSize]
    
    .outputArea delete 1.0 end
    .outputArea insert end $hkdfResult
}

# Cria a janela principal
wm title . "EDGE Diffie-Hellman Tool"
wm geometry . 620x450

# Cria as caixas de entrada de texto
entry .privateKeyInput -textvariable ::privateKeyInput
entry .publicKeyInput -textvariable ::publicKeyInput
entry .peerKeyInput -textvariable ::peerKeyInput
text .outputArea
entry .saltInput

# Posiciona as caixas de entrada de texto
grid .privateKeyInput -row 0 -column 1 -sticky "ew"
grid .publicKeyInput -row 1 -column 1 -sticky "ew"
grid .peerKeyInput -row 2 -column 1 -sticky "ew"
grid .outputArea -row 3 -column 1 -columnspan 1 -sticky "nsew"
grid .saltInput -row 4 -column 1 -sticky "ew"

# Cria os rótulos
label .privateKeyLabel -text "Private Key:"
label .publicKeyLabel -text "Public Key:"
label .peerKeyLabel -text "Peer Key:"
label .saltLabel -text "Salt:"

# Posiciona os rótulos
grid .privateKeyLabel -row 0 -column 0 -sticky "e"
grid .publicKeyLabel -row 1 -column 0 -sticky "e"
grid .peerKeyLabel -row 2 -column 0 -sticky "e"
grid .saltLabel -row 4 -column 0 -sticky "e"

# Cria os ComboBoxes para seleção de algoritmo, bits, paramset e tamanho da chave de saída
set ::algorithmComboData {"ecdsa" "sm2" "gost2012" "x25519"}
set ::bitsComboData {"224" "256" "384" "512" "521"}
set ::paramsetComboData {"A" "B" "C" "D"}
set ::outputKeySizeComboData {"16" "24" "32" "40" "64" "128"}
set ::hashAlgorithmComboData {
    "blake2s256" "blake2b256" "blake2b512" "blake3" "cubehash"
    "gost94" "groestl" "jh" "keccak256" "keccak512" "lsh224"
    "lsh256" "lsh384" "lsh512" "md4" "md5" "rmd128" "rmd160"
    "rmd256" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3-224"
    "sha3-256" "sha3-384" "sha3-512" "siphash64" "siphash128"
    "skein256" "skein512" "sm3" "streebog256" "streebog512"
    "tiger" "tiger2" "whirlpool" "xoodyak"
}

ttk::combobox .algorithmCombo -values $::algorithmComboData -state readonly
ttk::combobox .bitsCombo -values $::bitsComboData -state readonly
ttk::combobox .paramsetCombo -values $::paramsetComboData -state readonly
ttk::combobox .outputKeySizeCombo -values $::outputKeySizeComboData -state readonly
ttk::combobox .hashAlgorithmCombo -values $::hashAlgorithmComboData -state readonly

# Configura os valores padrão
.algorithmCombo set "ecdsa"
.bitsCombo set "256"
.paramsetCombo set "A"
.outputKeySizeCombo set "32"
.hashAlgorithmCombo set "sha256"

# Cria os rótulos para os ComboBoxes
label .algorithmLabel -text "Algorithm:   "
label .bitsLabel -text "Bits:   "
label .paramsetLabel -text "Paramset:   "
label .outputKeySizeLabel -text "Output Key Size:"
label .hashAlgorithmLabel -text "Hash Algorithm:"

# Posiciona os ComboBoxes e rótulos
grid .algorithmLabel -row 5 -column 0 -sticky "e"
grid .algorithmCombo -row 5 -column 1 -sticky "ew"
grid .bitsLabel -row 6 -column 0 -sticky "e"
grid .bitsCombo -row 6 -column 1 -sticky "ew"
grid .paramsetLabel -row 7 -column 0 -sticky "e"
grid .paramsetCombo -row 7 -column 1 -sticky "ew"
grid .outputKeySizeLabel -row 8 -column 0 -sticky "e"
grid .outputKeySizeCombo -row 8 -column 1 -sticky "ew"
grid .hashAlgorithmLabel -row 9 -column 0 -sticky "e"
grid .hashAlgorithmCombo -row 9 -column 1 -sticky "ew"

# Cria os botões
button .generateButton -text "Generate" -command {generateKey}
button .openPublicKeyButton -text "Open" -command {openPublicKey}
button .openPeerKeyButton -text "Open" -command {openPeerKey}
button .deriveButton -text "Derive" -command {deriveKey}
button .copyOutputButton -text "Copy" -command {copyText [.outputArea get 1.0 end]}
button .executeHKDFButton -text "Execute HKDF" -command {executeHKDF}

# Posiciona os botões
grid .generateButton -row 0 -column 2 -sticky "ew"
grid .openPublicKeyButton -row 1 -column 2 -sticky "ew"
grid .openPeerKeyButton -row 2 -column 2 -sticky "ew"
grid .deriveButton -row 3 -column 2 -sticky "ew"
grid .copyOutputButton -row 10 -column 1 -sticky "ew"
grid .executeHKDFButton -row 11 -column 1 -sticky "ew"

# Configura margens
grid configure .privateKeyInput -padx 10 -pady 5
grid configure .publicKeyInput -padx 10 -pady 5
grid configure .peerKeyInput -padx 10 -pady 5
grid configure .saltInput -padx 10 -pady 5
grid configure .privateKeyLabel -padx 10 -pady 5
grid configure .publicKeyLabel -padx 10 -pady 5
grid configure .peerKeyLabel -padx 10 -pady 5
grid configure .saltLabel -padx 10 -pady 5
grid configure .outputArea -padx 10 -pady 5
grid configure .generateButton -padx 10 -pady 5
grid configure .openPublicKeyButton -padx 10 -pady 5
grid configure .openPeerKeyButton -padx 10 -pady 5
grid configure .deriveButton -padx 10 -pady 5
grid configure .copyOutputButton -padx 10 -pady 5
grid configure .executeHKDFButton -padx 10 -pady 5
grid configure .algorithmCombo -padx 10 -pady 5
grid configure .bitsCombo -padx 10 -pady 5
grid configure .paramsetCombo -padx 10 -pady 5
grid configure .outputKeySizeLabel -padx 10 -pady 5
grid configure .outputKeySizeCombo -padx 10 -pady 5
grid configure .hashAlgorithmLabel -padx 10 -pady 5
grid configure .hashAlgorithmCombo -padx 10 -pady 5

# Configure o redimensionamento das células da grade
grid columnconfigure . 1 -weight 1
grid rowconfigure . 3 -weight 1

# Inicializa o loop principal do Tcl/Tk
wm deiconify .
tkwait window .
