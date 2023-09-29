package require Tk

# Função para copiar o texto para a área de transferência
proc copyText {text} {
    clipboard clear
    clipboard append $text
}

# Função para gerar o par de chaves
proc generateKeyPair {} {
    set private_key_path [file join [pwd] "private.pem"]
    set public_key_path [file join [pwd] "public.pem"]
    set algorithm [string tolower [.algorithmCombo get]]
    set bits [.bitsCombo get]
    set hash_algorithm [string tolower [.hashAlgorithmCombo get]]
    set paramset [.paramsetCombo get]
  
    set displayed_algorithm [string tolower [.algorithmCombo get]]  
    set algorithm [expr {$displayed_algorithm eq "ed25519ph" ? "ed25519" : $displayed_algorithm}]

    exec edgetk -pkey keygen -algorithm $algorithm -bits $bits -paramset $paramset -pwd - -priv $private_key_path -pub $public_key_path 2>@1

    .privateKeyInput delete 0 end
    .privateKeyInput insert 0 $private_key_path
    .publicKeyInput delete 0 end
    .publicKeyInput insert 0 $public_key_path
}

# Função para assinar digitalmente um texto
proc signText {} {
    set private_key_path [.privateKeyInput get]
    set text_to_sign [.textInput get 1.0 end]
    set algorithm [string tolower [.algorithmCombo get]]
    set hash_algorithm [string tolower [.hashAlgorithmCombo get]]
    
    if {$private_key_path eq ""} {
        set signature "No private key provided."
    } elseif {$text_to_sign eq ""} {
        set signature "No text to sign."
    } else {
        set signature [exec edgetk -pkey sign -algorithm $algorithm -md $hash_algorithm -key $private_key_path -pwd - << $text_to_sign]
    }

    .signatureOutput delete 1.0 end ;# Limpa o texto anterior
    .signatureOutput insert end $signature
}

# Função para verificar a assinatura digital
proc verifySignature {} {
    set public_key_path [.publicKeyInput get]
    set text_to_verify [.textInput get 1.0 end]
    set full_signature [.signatureOutput get 1.0 end]
    set space_index [string first " " $full_signature]  ;# Encontra a posição do primeiro espaço em branco
    set signature [string range $full_signature [expr $space_index + 1] end]  ;# Obtém a parte da assinatura após o espaço
    set signature [string map {\n ""} $signature]
    set algorithm [string tolower [.algorithmCombo get]]
    set hash_algorithm [string tolower [.hashAlgorithmCombo get]]

    # Executa o comando diretamente com os argumentos
    set return_code [catch {
        exec edgetk -pkey verify -algorithm $algorithm -md $hash_algorithm -key $public_key_path -signature $signature << $text_to_verify
    } result]
    
    if {$return_code == 0} {
        set verification_result "Signature verified successfully."
    } else {
        set verification_result "Signature verification failed: $result"
    }
    
    .verificationResultLabel configure -text $verification_result
}

# Função para abrir a chave privada
proc openPrivateKey {} {
    set file_path [tk_getOpenFile -filetypes {{"Private Key Files" {.pem}}}]
    if {$file_path ne ""} {
        .privateKeyInput delete 0 end
        .privateKeyInput insert 0 $file_path
    }
}

# Função para abrir a chave pública
proc openPublicKey {} {
    set file_path [tk_getOpenFile -filetypes {{"Public Key Files" {.pem}}}]
    if {$file_path ne ""} {
        .publicKeyInput delete 0 end
        .publicKeyInput insert 0 $file_path
    }
}

# Cria a janela principal
wm title . "EDGE Digital Signature Tool written in TCL/TK"

# Create a frame for the top section with a gray background
frame .topFrame -background gray90 -bd 1 -relief solid
grid .topFrame -row 0 -column 0 -rowspan 2 -columnspan 6 -sticky "nsew"

# Create a frame for the top section with a gray background2
frame .topFrame2 -background gray90 -bd 1 -relief solid
grid .topFrame2 -row 2 -column 0 -rowspan 4 -columnspan 6 -sticky "nsew"

# Create a frame for the top section with a gray background3
frame .topFrame3 -background gray90 -bd 1 -relief solid
grid .topFrame3 -row 6 -column 0 -rowspan 8 -columnspan 6 -sticky "nsew"

# Cria as caixas de entrada de texto com largura ajustada
entry .privateKeyInput -textvariable ::privateKeyInput -width 50
entry .publicKeyInput -textvariable ::publicKeyInput -width 50
text .textInput -wrap word -height 8 -width 50 -yscrollcommand ".textScroll set"
text .signatureOutput -height 5 -width 50 -yscrollcommand ".signatureScroll set"
label .verificationResultLabel -text ""

# Posiciona as caixas de entrada de texto
grid .privateKeyInput -row 0 -column 1 -sticky "ew"
grid .publicKeyInput -row 1 -column 1 -sticky "ew"
grid .textInput -row 2 -column 1 -columnspan 3 -sticky "nsew"
grid .signatureOutput -row 3 -column 1 -columnspan 3 -sticky "nsew"
grid .verificationResultLabel -row 13 -column 0 -columnspan 2 -sticky "w"

# Configura barras de rolagem para os campos de texto
scrollbar .textScroll -command ".textInput yview"
scrollbar .signatureScroll -command ".signatureOutput yview"

# Posiciona as barras de rolagem
grid .textScroll -row 2 -column 5 -sticky "ns"
grid .signatureScroll -row 3 -column 5 -sticky "ns"

# Cria os rótulos
label .privateKeyLabel -text "Private Key:"
label .publicKeyLabel -text "Public Key:"
label .textLabel -text "Text to Sign:"
label .signatureLabel -text "Signature:"
label .algorithmLabel -text "Algorithm:"
label .bitsLabel -text "Bits:"
label .paramsetLabel -text "Paramset:"
label .hashAlgorithmLabel -text "Hash Algorithm:"

# Posiciona os rótulos
grid .privateKeyLabel -row 0 -column 0 -sticky "e"
grid .publicKeyLabel -row 1 -column 0 -sticky "e"
grid .textLabel -row 2 -column 0 -sticky "e"
grid .signatureLabel -row 3 -column 0 -sticky "e"
grid .algorithmLabel -row 7 -column 0 -sticky "e"
grid .bitsLabel -row 8 -column 0 -sticky "e"
grid .paramsetLabel -row 9 -column 0 -sticky "e"
grid .hashAlgorithmLabel -row 10 -column 0 -sticky "e"

# Cria os botões
button .generateKeyPairButton -text "Generate Key Pair" -background gray80 -command {generateKeyPair}
button .openPrivateKeyButton -text "Open Private Key" -background gray80 -command {openPrivateKey}
button .openPublicKeyButton -text "Open Public Key" -background gray80 -command {openPublicKey}
button .signButton -text "Sign" -background gray80 -command {signText}
button .verifyButton -text "Verify" -background gray80 -command {verifySignature}
button .copySignatureButton -text "Copy Signature" -background gray80 -command {copyText [.signatureOutput get 1.0 end]}

# Posiciona os botões
grid .openPrivateKeyButton -row 0 -column 3 -sticky "ew"
grid .openPublicKeyButton -row 1 -column 2 -columnspan 2 -sticky "ew"
grid .generateKeyPairButton -row 0 -column 2 -sticky "ew"
grid .signButton -row 4 -column 2 -sticky "ew"
grid .verifyButton -row 4 -column 3 -sticky "ew"
grid .copySignatureButton -row 4 -column 1 -columnspan 1 -sticky "ew"

# Configura margens
grid configure .privateKeyInput -padx 10 -pady 5
grid configure .publicKeyInput -padx 10 -pady 5
grid configure .textInput -padx 10 -pady 5
grid configure .signatureOutput -padx 10 -pady 5
grid configure .privateKeyLabel -padx 10 -pady 5
grid configure .publicKeyLabel -padx 10 -pady 5
grid configure .textLabel -padx 10 -pady 5
grid configure .signatureLabel -padx 10 -pady 5
grid configure .verificationResultLabel -padx 10 -pady 5
grid configure .generateKeyPairButton -padx 10 -pady 5
grid configure .openPrivateKeyButton -padx 10 -pady 5
grid configure .openPublicKeyButton -padx 10 -pady 5
grid configure .signButton -padx 10 -pady 5
grid configure .verifyButton -padx 10 -pady 5
grid configure .copySignatureButton -padx 10 -pady 5

# Cria os ComboBoxes
ttk::combobox .algorithmCombo -values {"ecdsa" "sm2" "gost2012" "ed25519" "ed25519ph" "rsa"} -state readonly
ttk::combobox .bitsCombo -values {"224" "256" "384" "512" "521" "2048" "3072" "4096"} -state readonly
ttk::combobox .paramsetCombo -values {"A" "B" "C" "D"} -state readonly
ttk::combobox .hashAlgorithmCombo -values {
    "blake2s256" "blake2b256" "blake2b512" "blake3" "cubehash"
    "gost94" "groestl" "jh" "keccak256" "keccak512" "lsh224"
    "lsh256" "lsh384" "lsh512" "md4" "md5" "rmd128" "rmd160"
    "rmd256" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3-224"
    "sha3-256" "sha3-384" "sha3-512" "siphash64" "siphash128"
    "skein256" "skein512" "sm3" "streebog256" "streebog512"
    "tiger" "tiger2" "whirlpool" "xoodyak"
} -state readonly

# Configura os valores padrão
.algorithmCombo set "ecdsa"
.bitsCombo set "256"
.paramsetCombo set "A"
.hashAlgorithmCombo set "sha256"

# Posiciona os ComboBoxes e seus rótulos
grid .algorithmLabel -row 6 -column 0 -sticky "e"
grid .algorithmCombo -row 6 -column 1 -sticky "w"
grid .bitsLabel -row 8 -column 0 -sticky "e"
grid .bitsCombo -row 8 -column 1 -sticky "w"
grid .paramsetLabel -row 10 -column 0 -sticky "e"
grid .paramsetCombo -row 10 -column 1 -sticky "w"
grid .hashAlgorithmLabel -row 12 -column 0 -sticky "e"
grid .hashAlgorithmCombo -row 12 -column 1 -sticky "w"

# Configura margens para os ComboBoxes e rótulos dos ComboBoxes
grid configure .algorithmLabel -padx 10 -pady 5
grid configure .algorithmCombo -padx 10 -pady 5
grid configure .bitsLabel -padx 10 -pady 5
grid configure .bitsCombo -padx 10 -pady 5
grid configure .paramsetLabel -padx 10 -pady 5
grid configure .paramsetCombo -padx 10 -pady 5
grid configure .hashAlgorithmLabel -padx 10 -pady 5
grid configure .hashAlgorithmCombo -padx 10 -pady 5

# Configura o redimensionamento das células da grade
grid columnconfigure . 1 -weight 1
grid rowconfigure . 3 -weight 1

# Inicializa o loop principal do Tcl/Tk
wm deiconify .
tkwait window .
