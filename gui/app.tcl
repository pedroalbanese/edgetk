#!/usr/bin/wish
###############################################################################
#   EDGE Crypto Suite -- Pure Tcl/Tk Graphical Cryptographic Toolkit          #
#   Copyright (C) 2020-2025 Pedro F. Albanese <pedroalbanese@hotmail.com>     #
#                                                                             #
#   This program is free software: you can redistribute it and/or modify it   #
#   under the terms of the ISC License.                                       #
#                                                                             #
#   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES  #
#   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF          #
#   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR   #
#   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES    #
#   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN     #
#   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF   #
#   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.            #
###############################################################################

# Style settings
set bg_color "#f5f5f5"
set accent_color "#2c3e50"
set button_color "#3498db"
set button_hover "#2980b9"
set frame_color "#ecf0f1"
set text_bg "#ffffff"

# Global variables
set signature_data ""
set useKDFAlgorithm 0
set useKDFAlgorithmFiles 0
set iterValue 10000
set iterValueFiles 10000

# ===== SHARED FUNCTIONS =====

# Function to copy text to clipboard
proc copyText {text} {
    set trimmedText [string trim $text]
    clipboard clear
    clipboard append $trimmedText
}

# Function to select all text
proc selectAll {w} {
    if {[string match "*Text" [winfo class $w]]} {
        $w tag add sel 1.0 end
    } elseif {[string match "*Entry" [winfo class $w]]} {
        $w selection range 0 end
    }
}

# Global bind for Ctrl+A
bind all <Control-a> {
    set w %W
    selectAll $w
    break
}

# Function to open file dialog
proc openFileDialog {entry_widget} {
    set file_path [tk_getOpenFile]
    if {$file_path ne ""} {
        $entry_widget delete 0 end
        $entry_widget insert 0 $file_path
    }
}

# About window for EDGE Crypto Suite
proc showAbout {} {
    toplevel .about_window
    wm title .about_window "About EDGE Crypto Suite"
    wm geometry .about_window 460x500
    wm resizable .about_window 0 0

    set x [expr {[winfo screenwidth .] / 2 - 230}]
    set y [expr {[winfo screenheight .] / 2 - 180}]
    wm geometry .about_window +$x+$y

    frame .about_window.main -bg white -relief solid -bd 1
    pack .about_window.main -fill both -expand true -padx 12 -pady 12

    # Logo
    if {$::tcl_platform(os) ne "Windows NT"} {
        label .about_window.main.logo -text "🔏" -font {"Segoe UI Emoji" 28} -bg white
        pack .about_window.main.logo -pady 10
    } else {
        label .about_window.main.logo -text "\uF023" -font {"Segoe UI Emoji" 40} -bg white
        pack .about_window.main.logo -pady 6
    }

    # Title
    label .about_window.main.title -text "EDGE Crypto Suite" \
        -font {Arial 15 bold} -bg white
    pack .about_window.main.title -pady 4

    # Version
    label .about_window.main.version -text "Version 1.1" \
        -font {Arial 10} -bg white
    pack .about_window.main.version -pady 2

    # Description
    label .about_window.main.desc -text \
"EDGE Crypto Suite is a research and development project in
applied cryptography, designed to provide a unified, reliable,
and cross-platform environment for data protection and secure
communications.

Developed in accordance with internationally recognized
cryptographic standards, the software emphasizes
interoperability, technical correctness, and conceptual
consistency across different operating systems and computing
architectures.

The project reflects a commitment to sound security engineering
practices, methodological transparency, and alignment with the
current state of the art in modern cryptography." \
        -font {Arial 9} -bg white -justify center -wraplength 480
    pack .about_window.main.desc -pady 10

    # Author / Lab
    label .about_window.main.features -text "All-in-One Cryptographic Toolkit" \
        -font {Arial 9} -bg white
    pack .about_window.main.features -pady 2

    label .about_window.main.lab -text "ALBANESE Research Lab" \
        -font {Arial 9 bold} -bg white
    pack .about_window.main.lab -pady 10

    # OK Button
    button .about_window.main.ok -text "OK" -command {destroy .about_window} \
        -bg "#2c3e50" -fg white -font {Arial 10 bold} -relief flat \
        -padx 22 -pady 6
    pack .about_window.main.ok -pady 14

    bind .about_window <Key-Escape> {destroy .about_window}
    bind .about_window <Return> {destroy .about_window}
    focus .about_window
}

# ===== SIGNATURE CODE FUNCTIONS (first code) =====

# Function to generate key pair - WITH ABSOLUTE PATHS
proc generateKey {} {
    set algorithm [.nb.signatures_tab.main.algo_frame.content.algorithmCombo get]
    set bits [.nb.signatures_tab.main.algo_frame.content.bitsCombo get]
    set paramset [.nb.signatures_tab.main.algo_frame.content.paramsetCombo get]
    set curve [.nb.signatures_tab.main.algo_frame.content.curveCombo get]
    set passphrase [.nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passEntry get]
    set cipher [.nb.signatures_tab.main.keys_frame.title_frame.pass_frame.cipherCombo get]
    
    # If passphrase is empty, use "nil"
    if {$passphrase eq ""} {
        set passphrase "nil"
    }
    
    # Get current directory
    set current_dir [pwd]
    
    # Generate unique filenames
    set clean_algo [string map {"ph" ""} $algorithm]
    set algo_upper [string toupper $clean_algo]
    
    # Base names
    set base_private_name "${algo_upper}_Private"
    set base_public_name "${algo_upper}_Public"
    
    # Default paths without suffix
    set default_private_path [file join $current_dir "${base_private_name}.pem"]
    set default_public_path [file join $current_dir "${base_public_name}.pem"]
    
    # Get current values from input fields (if any)
    set current_private [.nb.signatures_tab.main.keys_frame.content.privateKeyInput get]
    set current_public [.nb.signatures_tab.main.keys_frame.content.publicKeyInput get]
    
    # Check if input fields already have values with numeric suffix
    set has_numeric_suffix 0
    set private_key_path $default_private_path
    set public_key_path $default_public_path
    
    if {$current_private ne "" && [file exists $current_private]} {
        # User already selected a specific file, check if it has numeric suffix
        set filename [file tail $current_private]
        if {[regexp {_(\d+)\.pem$} $filename]} {
            # File has numeric suffix, use it
            set private_key_path $current_private
            set has_numeric_suffix 1
            
            # Check if corresponding public key exists with same suffix
            if {[regexp {^(.*)_(\d+)\.pem$} $filename -> base suffix]} {
                set public_candidate [file join $current_dir "${base_public_name}_${suffix}.pem"]
                if {[file exists $public_candidate] && $current_public eq ""} {
                    set public_key_path $public_candidate
                }
            }
        }
    }
    
    # If user manually entered public key, use it
    if {$current_public ne "" && [file exists $current_public]} {
        set public_key_path $current_public
    }
    
    # Check if the selected files already exist
    set private_exists [file exists $private_key_path]
    set public_exists [file exists $public_key_path]
    
    if {$private_exists || $public_exists} {
        # Show dialog window
        set files_message ""
        if {$private_exists && $public_exists} {
            set files_message "Both private and public key files already exist."
        } elseif {$private_exists} {
            set files_message "Private key file already exists."
        } else {
            set files_message "Public key file already exists."
        }
        
        set choice [tk_messageBox \
            -title "Keys Already Exist" \
            -message "Files already exist:\n\nPrivate: [file tail $private_key_path]\nPublic: [file tail $public_key_path]\n\nWhat do you want to do?" \
            -type yesnocancel \
            -icon warning \
            -detail "Yes: Overwrite existing files\nNo: Generate with NEW numeric suffix (rename)\nCancel: Abort operation" \
            -default cancel]
        
        if {$choice eq "cancel"} {
            # User canceled
            .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Key generation cancelled."
            return
        } elseif {$choice eq "no"} {
            # User wants to rename with NEW numeric suffix
            # Find NEXT available name for private key
            set counter 1
            set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
            
            # Start from 1 and find the first available number
            while {[file exists $new_private_path]} {
                incr counter
                set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
            }
            
            # Use the same counter for public key
            set new_public_path [file join $current_dir "${base_public_name}_${counter}.pem"]
            
            # If public key with that number already exists, find next available
            while {[file exists $new_public_path]} {
                incr counter
                set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
                set new_public_path [file join $current_dir "${base_public_name}_${counter}.pem"]
            }
            
            set private_key_path $new_private_path
            set public_key_path $new_public_path
        }
        # If choice is "yes", keep the existing paths (will be overwritten)
    } else {
        # Files don't exist, check if we should use the current input values
        if {$current_private ne "" && [file dirname $current_private] eq $current_dir} {
            # User has entered a specific path, use it
            set private_key_path $current_private
        }
        
        if {$current_public ne "" && [file dirname $current_public] eq $current_dir} {
            # User has entered a specific path, use it
            set public_key_path $current_public
        }
    }
    
    # Update entry fields with full paths
    .nb.signatures_tab.main.keys_frame.content.privateKeyInput delete 0 end
    .nb.signatures_tab.main.keys_frame.content.privateKeyInput insert 0 $private_key_path
    
    .nb.signatures_tab.main.keys_frame.content.publicKeyInput configure -state normal
    .nb.signatures_tab.main.keys_frame.content.publicKeyInput delete 0 end
    .nb.signatures_tab.main.keys_frame.content.publicKeyInput insert 0 $public_key_path
    
    # Execute key generation command with -pass nil
    if {[catch {
        # Use -curve flag for elliptic curve based algorithms
        exec edgetk -pkey keygen -algorithm [string map {"ph" ""} $algorithm] -bits $bits -paramset $paramset -curve $curve -cipher $cipher -pass $passphrase -prv $private_key_path -pub $public_key_path 2>@1
    } result]} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error generating keys:\n$result"
    } else {
        # Show result in output area
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Key pair generated successfully!\n\n"
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Private key: [file tail $private_key_path]\n"
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Public key: [file tail $public_key_path]"
    }
}

# Function to select input type (text or file)
proc selectInputType {} {
    set input_type [.nb.signatures_tab.main.input_frame.content.inputTypeCombo get]
    if {$input_type eq "Text"} {
        # Enable text area, disable file entry
        .nb.signatures_tab.main.input_frame.content.textframe.inputText configure -state normal
        .nb.signatures_tab.main.input_frame.content.inputFile configure -state disabled
        .nb.signatures_tab.main.input_frame.content.openFileButton configure -state disabled
        .nb.signatures_tab.main.input_frame.content.inputFile configure -background "#f0f0f0"
        .nb.signatures_tab.main.input_frame.content.textframe.inputText configure -background "white"
        # Clear file entry when switching to text mode
        .nb.signatures_tab.main.input_frame.content.inputFile delete 0 end
    } else {
        # Enable file entry, disable text area
        .nb.signatures_tab.main.input_frame.content.textframe.inputText configure -state disabled
        .nb.signatures_tab.main.input_frame.content.inputFile configure -state normal
        .nb.signatures_tab.main.input_frame.content.openFileButton configure -state normal
        .nb.signatures_tab.main.input_frame.content.inputFile configure -background "white"
        .nb.signatures_tab.main.input_frame.content.textframe.inputText configure -background "#f0f0f0"
        # Clear text area when switching to file mode
        .nb.signatures_tab.main.input_frame.content.textframe.inputText delete 1.0 end
    }
}

# Function to select input type (text or file) in MAC tab
proc selectMACInputType {} {
    set input_type [.nb.mac_tab.main.input_frame.content.inputTypeCombo get]
    if {$input_type eq "Text"} {
        # Enable text area, disable file entry
        .nb.mac_tab.main.input_frame.content.textframe.inputText configure -state normal
        .nb.mac_tab.main.input_frame.content.inputFile configure -state disabled
        .nb.mac_tab.main.input_frame.content.openFileButton configure -state disabled
        .nb.mac_tab.main.input_frame.content.inputFile configure -background "#f0f0f0"
        .nb.mac_tab.main.input_frame.content.textframe.inputText configure -background "white"
        # Clear file entry when switching to text mode
        .nb.mac_tab.main.input_frame.content.inputFile delete 0 end
    } else {
        # Enable file entry, disable text area
        .nb.mac_tab.main.input_frame.content.textframe.inputText configure -state disabled
        .nb.mac_tab.main.input_frame.content.inputFile configure -state normal
        .nb.mac_tab.main.input_frame.content.openFileButton configure -state normal
        .nb.mac_tab.main.input_frame.content.inputFile configure -background "white"
        .nb.mac_tab.main.input_frame.content.textframe.inputText configure -background "#f0f0f0"
        # Clear text area when switching to file mode
        .nb.mac_tab.main.input_frame.content.textframe.inputText delete 1.0 end
    }
}

# Function to create signature - SHOWS FULL EDGETK OUTPUT WITH HASH
proc createSignature {} {
    global signature_data
    
    set private_key_path [.nb.signatures_tab.main.keys_frame.content.privateKeyInput get]
    set algorithm [.nb.signatures_tab.main.algo_frame.content.algorithmCombo get]
    set hash_algorithm [.nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo get]
    set passphrase [.nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passEntry get]
    
    # Validate private key
    if {$private_key_path eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a private key!"
        return
    }
    
    if {![file exists $private_key_path]} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Private key file not found:\n$private_key_path"
        return
    }
    
    set input_type [.nb.signatures_tab.main.input_frame.content.inputTypeCombo get]
    
    # Clear output area
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
    
    if {$input_type eq "Text"} {
        # Get text input
        set input_text [.nb.signatures_tab.main.input_frame.content.textframe.inputText get 1.0 end-1c]
        
        if {[string trim $input_text] eq ""} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please enter text to sign!"
            return
        }
        
        # Create signature from text
        if {[catch {
            # USE PIPE (<<) instead of file redirection
            set result [exec edgetk -pkey sign -algorithm $algorithm -md $hash_algorithm -key $private_key_path -pass $passphrase << $input_text 2>@1]
        } result]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error creating signature from text:\n$result"
            set signature_data ""
            return
        }
    } else {
        # Get file input
        set input_file [.nb.signatures_tab.main.input_frame.content.inputFile get]
        
        if {$input_file eq "" || ![file exists $input_file]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a valid file!"
            return
        }
        
        # Create signature from file - ALWAYS with -md flag
        if {[catch {
            # ALWAYS use -md flag with selected hash
            set result [exec edgetk -pkey sign -algorithm $algorithm -md $hash_algorithm -key $private_key_path -pass $passphrase $input_file 2>@1]
        } result]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error creating signature from file:\n$result"
            set signature_data ""
            return
        }
    }
    
    # Save the complete output
    set signature_data $result
    
    # Show complete edgetk output in output area
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
    .nb.signatures_tab.main.output_frame.textframe.outputArea insert end $result
}

# Function to extract signature from edgetk output
proc extractSignatureFromOutput {output} {
    # Try to extract just the signature part (after "=" or last word)
    if {[regexp {=\s*(\S+)$} $output -> signature]} {
        return $signature
    } elseif {[regexp {\s+(\S+)$} $output -> signature]} {
        return $signature
    }
    # If no pattern found, return the whole string trimmed
    return [string trim $output]
}

# Function to verify signature - USES ONLY THE SIGNATURE (part after "=") WITH HASH
proc verifySignature {} {
    global signature_data
    
    set public_key_path [.nb.signatures_tab.main.keys_frame.content.publicKeyInput get]
    set algorithm [.nb.signatures_tab.main.algo_frame.content.algorithmCombo get]
    set hash_algorithm [.nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo get]
    set passphrase [.nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passEntry get]
    
    # Validate public key
    if {$public_key_path eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a public key!"
        return
    }
    
    if {![file exists $public_key_path]} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Public key file not found:\n$public_key_path"
        return
    }
    
    # Get signature from output area
    set output_text [string trim [.nb.signatures_tab.main.output_frame.textframe.outputArea get 1.0 end-1c]]
    
    # Extract just the signature part from output
    set signature [extractSignatureFromOutput $output_text]
    
    # If output area is empty, use last signature from global variable
    if {$signature eq "" && $signature_data ne ""} {
        # Extract signature from stored output
        set signature [extractSignatureFromOutput $signature_data]
    }
    
    if {$signature eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: No signature to verify!\nPlease create a signature first or enter one in the output area."
        return
    }
    
    set input_type [.nb.signatures_tab.main.input_frame.content.inputTypeCombo get]
    
    # Clear output area
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
    
    if {$input_type eq "Text"} {
        # Get text input
        set input_text [.nb.signatures_tab.main.input_frame.content.textframe.inputText get 1.0 end-1c]
        
        if {[string trim $input_text] eq ""} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please enter text to verify!"
            return
        }
        
        # Verify signature from text
        if {[catch {
            # USE PIPE (<<) instead of file redirection
            set result [exec edgetk -pkey verify -algorithm $algorithm -md $hash_algorithm -key $public_key_path -signature $signature << $input_text 2>@1]
        } result]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature INVALID!\n\n$result"
        } else {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature VALID!\n\n$result"
        }
    } else {
        # Get file input
        set input_file [.nb.signatures_tab.main.input_frame.content.inputFile get]
        
        if {$input_file eq "" || ![file exists $input_file]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a valid file!"
            return
        }
        
        # Verify signature from file - ALWAYS with -md flag
        if {[catch {
            # ALWAYS use -md flag with selected hash
            set result [exec edgetk -pkey verify -algorithm $algorithm -md $hash_algorithm -key $public_key_path -signature $signature < $input_file 2>@1]
        } result]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature INVALID!\n\n$result"
        } else {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature VALID!\n\n$result"
        }
    }
}

# ===== END OF SIGNATURE FUNCTIONS =====

# ===== MAC FUNCTIONS (from second code) =====

# Function to copy result to clipboard
proc copyResult {} {
    set result [.nb.mac_tab.main.output_frame.textframe.resultBox get 1.0 end]
    clipboard clear
    clipboard append [string trim $result]
}

# Function to update UI based on selected algorithm
proc updateAlgorithmUI {} {
    set algorithm [.nb.mac_tab.main.algo_frame.content.algorithmCombo get]
    
    # List of 64-bit block ciphers
    set block64_ciphers {
        blowfish cast5 gost89 magma hight khazad idea misty1 present rc2 rc5
        rc6 seed twine safer+
    }
    
    # List of 128-bit block ciphers
    set block128_ciphers {
        aes anubis aria belt camellia cast256 clefia crypton e2 kalyna128_128
        kalyna128_256 kuznechik lea loki97
        magenta mars noekeon serpent sm4 twofish
    }
    
    # Combination of 64 and 128 bit ciphers for CMAC
    set cmac_compatible_ciphers [concat $block64_ciphers $block128_ciphers]
    
    # Complete list of all ciphers
    set all_cmac_ciphers {
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
    
    # Update Text tab
    if {$algorithm == "hmac"} {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
        
    } elseif {$algorithm == "cmac"} {
        # ONLY CMAC: show only 64 and 128 bit ciphers
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
        
        # For CMAC: show only 64 and 128 bit ciphers
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -values $cmac_compatible_ciphers
        
        # Check if current cipher is compatible, if not change to default
        set current_cipher [.nb.mac_tab.main.algo_frame.content.cmacCipherCombo get]
        if {$current_cipher ni $cmac_compatible_ciphers} {
            .nb.mac_tab.main.algo_frame.content.cmacCipherCombo set "aes"
        }
        
    } elseif {$algorithm == "pmac"} {
        # PMAC: can have all ciphers
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
        
        # For PMAC: show all ciphers
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -values $all_cmac_ciphers
        
    } elseif {$algorithm == "vmac"} {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state normal
        # For other algorithms, keep default VMAC values
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -values {8 16 32}
        .nb.mac_tab.main.algo_frame.content.outSizeCombo set "8"
        
        # For VMAC: show all ciphers
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -values $all_cmac_ciphers
        
    } elseif {$algorithm == "eia256"} {
        # Only EIA256 has configurable output size
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state normal
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state normal
        # Configure values for EIA256: 4, 8, 16 bits
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -values {4 8 16}
        .nb.mac_tab.main.algo_frame.content.outSizeCombo set "16"
    } else {
        .nb.mac_tab.main.algo_frame.content.hashLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.hmacHashCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cipherLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.cmacCipherCombo configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeLabel configure -state disabled
        .nb.mac_tab.main.algo_frame.content.outSizeCombo configure -state disabled
    }
    
    # IV field control for Text tab
    # Algorithms that need IV: vmac, gost, eia128, eia256
    if {$algorithm in {"vmac" "gost" "eia128" "eia256"}} {
        .nb.mac_tab.main.keys_frame.content.ivLabel configure -state normal
        .nb.mac_tab.main.keys_frame.content.ivEntry configure -state normal
        .nb.mac_tab.main.keys_frame.content.ivEntry configure -background "white"
    } else {
        .nb.mac_tab.main.keys_frame.content.ivLabel configure -state disabled
        .nb.mac_tab.main.keys_frame.content.ivEntry configure -state disabled
        .nb.mac_tab.main.keys_frame.content.ivEntry configure -background "#f0f0f0"
    }
}

# Function to update signature tab UI based on selected algorithm
proc updateSignatureUI {} {
    set algorithm [.nb.signatures_tab.main.algo_frame.content.algorithmCombo get]
    
    # Define which algorithms have fixed size
    set fixed_size_algorithms {ed25519 ed25519ph ed448 ed448ph ed521 ed521ph x25519 x448 sm2 sm2ph}
    # GOST2012 is NOT here because it uses sizes
    
    # Define which algorithms use paramset
    set paramset_algorithms {gost2012}
    
    # Define which algorithms don't need hash (pre-hash)
    # SM2 doesn't use external hash (uses fixed internal hash)
    # Versions without "ph" (pre-hash) also don't use external hash
    set no_hash_algorithms {ed25519 ed448 ed521 sm2}
    
    # Define which algorithms don't use curve
    # GOST2012 does NOT use curve - only size and paramset
    set no_curve_algorithms {ed25519 ed25519ph ed448 ed448ph ed521 ed521ph rsa bign sm2 sm2ph gost2012}
    
    # COMPLETE list of all hash algorithms available in the system
    set all_hash_algorithms {
        bash224 bash256 bash384 bash512
        belt
        blake2b256 blake2b512
        blake2s256
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
    
    # List of hashes compatible only with RSA
    set rsa_hash_algorithms {md5 sha256 sha384 sha512 ripemd160}
    
    # Get current hash value before making changes
    set current_hash [.nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo get]
    
    # Get current bits value before making changes
    set current_bits [.nb.signatures_tab.main.algo_frame.content.bitsCombo get]
    
    # 1. Control bits combo box (size)
    if {[lsearch $fixed_size_algorithms $algorithm] >= 0} {
        # Algorithm with fixed size - disable bits combo
        .nb.signatures_tab.main.algo_frame.content.bitsLabel configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -background "#f0f0f0"
    } else {
        # Algorithm with variable size - enable bits combo
        .nb.signatures_tab.main.algo_frame.content.bitsLabel configure -state normal
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -state normal
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -background "white"
    }
    
    # 2. Control paramset combo box
    if {[lsearch $paramset_algorithms $algorithm] >= 0} {
        # GOST2012 needs paramset - enable
        .nb.signatures_tab.main.algo_frame.content.paramsetLabel configure -state normal
        .nb.signatures_tab.main.algo_frame.content.paramsetCombo configure -state normal
        .nb.signatures_tab.main.algo_frame.content.paramsetCombo configure -background "white"
    } else {
        # Other algorithms don't use paramset - disable
        .nb.signatures_tab.main.algo_frame.content.paramsetLabel configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.paramsetCombo configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.paramsetCombo configure -background "#f0f0f0"
    }
    
    # 3. Control hash combo box (digest)
    if {[lsearch $no_hash_algorithms $algorithm] >= 0} {
        # Algorithms that don't use external hash - disable hash
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmLabel configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -background "#f0f0f0"
    } else {
        # Algorithms that need hash - enable hash
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmLabel configure -state normal
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -state normal
        .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -background "white"
        
        # Control which hashes are available
        if {$algorithm eq "rsa"} {
            # ONLY for RSA: use reduced hash list
            .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -values $rsa_hash_algorithms
            
            # Check if current hash is in RSA-compatible list
            if {$current_hash ni $rsa_hash_algorithms} {
                .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo set "sha256"
            }
        } else {
            # For ALL other algorithms: restore COMPLETE hash list
            .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo configure -values $all_hash_algorithms
            
            # Set default hash based on algorithm - ONLY if necessary
            if {$algorithm eq "sm2ph"} {
                # SM2ph uses SM3 as default hash
                if {$current_hash eq "" || $current_hash eq "sm3"} {
                    .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo set "sm3"
                }
            } elseif {$algorithm eq "bign"} {
                # BIGN: bash256 as default
                if {$current_hash eq "" || $current_hash eq "bash256"} {
                    .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo set "bash256"
                }
            } elseif {$algorithm eq "gost2012"} {
                # GOST2012: streebog256 as default
                if {$current_hash eq "" || $current_hash eq "streebog256"} {
                    .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo set "streebog256"
                }
            }
            # For ECDSA and others: DO NOT automatically change to sha3-256
            # Keep whatever hash the user has selected
        }
    }
    
    # 4. Control curve combo box
    if {[lsearch $no_curve_algorithms $algorithm] >= 0} {
        # Algorithms that don't use curve - disable curve
        .nb.signatures_tab.main.algo_frame.content.curveLabel configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.curveCombo configure -state disabled
        .nb.signatures_tab.main.algo_frame.content.curveCombo configure -background "#f0f0f0"
    } else {
        # Algorithms that use curve - enable curve
        .nb.signatures_tab.main.algo_frame.content.curveLabel configure -state normal
        .nb.signatures_tab.main.algo_frame.content.curveCombo configure -state normal
        .nb.signatures_tab.main.algo_frame.content.curveCombo configure -background "white"
        
        # Complete list of all available curves (assuming these are available)
        set all_curves {
            secp224r1
            secp256r1
            secp384r1
            secp521r1
            sect283r1
            sect409r1
            sect571r1
            sect283k1
            sect409k1
            sect571k1
            brainpoolp256r1
            brainpoolp384r1
            brainpoolp512r1
            brainpoolp256t1
            brainpoolp384t1
            brainpoolp512t1
            numsp256d1
            numsp384d1
            numsp512d1
            numsp256t1
            numsp384t1
            numsp512t1
            tom256
            tom384
            kg256r1
            kg384r1
            frp256v1
            secp256k1
        }
        
        # Filter curves based on algorithm
        if {$algorithm eq "ecdsa"} {
            # For ECDSA: remove sect and brainpool
            set filtered_curves {}
            foreach curve $all_curves {
                if {![string match "sect*" $curve] && ![string match "brainpool*" $curve]} {
                    lappend filtered_curves $curve
                }
            }
            .nb.signatures_tab.main.algo_frame.content.curveCombo configure -values $filtered_curves
            .nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256r1"
            
        } elseif {$algorithm in {"bip0340" "ecsda" "ecgdsa" "eckcdsa"}} {
            # For BIP0340, ECSDA, ECGDS and ECKCDSA: remove kg and sm2
            set filtered_curves {}
            foreach curve $all_curves {
                if {![string match "kg*" $curve] && ![string match "sm2*" $curve]} {
                    lappend filtered_curves $curve
                }
            }
            .nb.signatures_tab.main.algo_frame.content.curveCombo configure -values $filtered_curves
            
            # Set default curve based on algorithm
            if {$algorithm eq "bip0340"} {
                .nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256k1"
            } else {
                .nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256r1"
            }
            
        } else {
            # For other algorithms that use curve: show all curves
            .nb.signatures_tab.main.algo_frame.content.curveCombo configure -values $all_curves
            .nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256r1"
        }
    }
    
    # 5. Update available values in bits combo based on algorithm
    # Define available bits for each algorithm type
    if {[string match "rsa*" $algorithm]} {
        # RSA: values 1024, 2048, 3072, 4096
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -values {1024 2048 3072 4096}
        
        # Check if current bits is valid for RSA
        if {$current_bits in {1024 2048 3072 4096}} {
            # Keep current value if valid
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set $current_bits
        } else {
            # Otherwise set default
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "2048"
        }
        
    } elseif {[string match "bign*" $algorithm]} {
        # BIGN: values 256, 384, 512
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -values {256 384 512}
        
        # Check if current bits is valid for BIGN
        if {$current_bits in {256 384 512}} {
            # Keep current value if valid
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set $current_bits
        } else {
            # Otherwise set default
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"
        }
        
    } elseif {[string match "ed*" $algorithm]} {
        # EdDSA has fixed sizes based on algorithm
        if {[string match "*25519*" $algorithm]} {
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"
        } elseif {[string match "*448*" $algorithm]} {
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "448"
        } elseif {[string match "*521*" $algorithm]} {
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "521"
        }
        
    } elseif {$algorithm eq "sm2" || $algorithm eq "sm2ph"} {
        # SM2 has fixed size 256
        .nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"
        
    } elseif {$algorithm eq "gost2012"} {
        # GOST: values 256, 512
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -values {256 512}
        
        # Check if current bits is valid for GOST2012
        if {$current_bits in {256 512}} {
            # Keep current value if valid
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set $current_bits
        } else {
            # Otherwise set default
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"
        }
        
    } else {
        # ECDSA and variants use these sizes: 224, 256, 384, 521
        .nb.signatures_tab.main.algo_frame.content.bitsCombo configure -values {224 256 384 521}
        
        # Check if current bits is valid for ECDSA
        if {$current_bits in {224 256 384 521}} {
            # Keep current value if valid
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set $current_bits
        } else {
            # Otherwise set default
            .nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"
        }
    }
    
    # 6. Update default curve based on algorithm
    if {$algorithm eq "bip0340"} {
        .nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256k1"
    }
}

# Function to update ECDH tab UI based on selected algorithm
proc updateECDHUI {} {
    set algorithm [.nb.ecdh_tab.main.algo_frame.content.algorithmCombo get]
    
    # Define which ECDH algorithms have fixed size
    set fixed_size_algorithms {x25519 x448 sm2}
    # x25519 and x448 have fixed size, SM2 too
    
    # Define which algorithms use paramset (ONLY GOST2012)
    set paramset_algorithms {gost2012}
    
    # 1. Control bits combo box (size)
    if {[lsearch $fixed_size_algorithms $algorithm] >= 0} {
        # Algorithm with fixed size - disable bits combo
        .nb.ecdh_tab.main.algo_frame.content.bitsLabel configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -background "#f0f0f0"
    } elseif {$algorithm in {"anssi" "koblitz"}} {
        # For ANSI or Koblitz, completely disable (gray out size)
        .nb.ecdh_tab.main.algo_frame.content.bitsLabel configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -background "#f0f0f0"
    } else {
        # Algorithm with variable size - enable bits combo
        .nb.ecdh_tab.main.algo_frame.content.bitsLabel configure -state normal
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -state normal
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -background "white"
    }
    
    # 2. Control paramset combo box
    if {[lsearch $paramset_algorithms $algorithm] >= 0} {
        # ONLY GOST2012 uses paramset - enable paramset
        .nb.ecdh_tab.main.algo_frame.content.paramsetLabel configure -state normal
        .nb.ecdh_tab.main.algo_frame.content.paramsetCombo configure -state normal
        .nb.ecdh_tab.main.algo_frame.content.paramsetCombo configure -background "white"
    } else {
        # All other algorithms do NOT use paramset - disable paramset
        .nb.ecdh_tab.main.algo_frame.content.paramsetLabel configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.paramsetCombo configure -state disabled
        .nb.ecdh_tab.main.algo_frame.content.paramsetCombo configure -background "#f0f0f0"
    }
    
    # 3. Update available values in bits combo based on algorithm
    if {$algorithm eq "x25519"} {
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } elseif {$algorithm eq "x448"} {
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "448"
    } elseif {$algorithm eq "sm2"} {
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } elseif {$algorithm eq "gost2012"} {
        # For GOST2012, allow only 256 and 512
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -values {256 512}
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } elseif {$algorithm eq "ec"} {
        # For EC, allow only 256 and 384
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -values {256 384}
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } elseif {$algorithm in {"tom" "kg"}} {
        # For TOM and KG, only 256 and 384
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -values {256 384}
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } elseif {$algorithm in {"anssi" "koblitz"}} {
        # For ANSI or Koblitz, set values but disabled
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -values {256 384 512}
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    } else {
        # For other algorithms (nums, etc.)
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo configure -values {256 384 512}
        .nb.ecdh_tab.main.algo_frame.content.bitsCombo set "256"
    }
}

# ===== FUNCTIONS FOR THE FIRST TWO TABS =====

# Function to update text tab UI based on selected algorithm
proc updateTextUI {} {
    set algorithm [.nb.text_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.text_tab.main.algo_frame.row1.modeCombo get]
    set useKDF $::useKDFAlgorithm
    
    # Define which algorithms are block, stream or AEAD
    set block_ciphers {
        3des aes anubis aria belt blowfish camellia cast5 cast256 clefia
        crypton curupira e2 gost89 hight idea kalyna128_128 kalyna128_256
        kalyna256_256 kalyna512_512 khazad kuznechik lea loki97 magma
        magenta mars misty1 noekeon present rc2 rc5 rc6 safer+ seed
        serpent shacal2 sm4 threefish threefish512 threefish1024 twine twofish
    }
    
    set stream_ciphers {
        chacha20 chacha20poly1305 ascon grain128a grain hc128 hc256 rc4 salsa20 zuc128 zuc256 xoodyak
    }
    
    set aead_ciphers {
        chacha20poly1305 ascon grain xoodyak
    }
    
    # 64-bit ciphers (block size)
    set block64_ciphers {
        3des blowfish cast5 gost89 hight idea misty1 present rc2 rc5
        rc6 seed twine kalyna128_128 kalyna128_256
    }
    
    # 1. Control Mode combo box
    if {$algorithm in $stream_ciphers} {
        # Stream ciphers: disable mode
        .nb.text_tab.main.algo_frame.row1.modeLabel configure -state disabled
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -state disabled
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -background "#f0f0f0"
        
        # For stream ciphers, set mode automatically
        if {$algorithm eq "rc4"} {
            .nb.text_tab.main.algo_frame.row1.modeCombo set "ecb"
        } else {
            .nb.text_tab.main.algo_frame.row1.modeCombo set "ctr"
        }
    } elseif {$algorithm eq "xoodyak"} {
        # Xoodyak (permutation): fixed mode
        .nb.text_tab.main.algo_frame.row1.modeLabel configure -state disabled
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -state disabled
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -background "#f0f0f0"
        .nb.text_tab.main.algo_frame.row1.modeCombo set "siv"
    } elseif {$algorithm in $block64_ciphers} {
        # For 64-bit ciphers: conventional modes + eax, mgm, siv
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "mgm" "siv" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
            
        # CORRECTION: Check if current mode is compatible with 64-bit ciphers
        # AEAD modes that are NOT compatible with 64-bit ciphers
        set incompatible_modes {gcm ocb1 ocb3 ccm lettersoup}
            
        if {$mode in $incompatible_modes} {
            # If current mode is not compatible, change to "eax" (default for 64 bits)
            .nb.text_tab.main.algo_frame.row1.modeCombo set "eax"
        }
    } else {
        # Block ciphers: enable mode
        .nb.text_tab.main.algo_frame.row1.modeLabel configure -state normal
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -state normal
        .nb.text_tab.main.algo_frame.row1.modeCombo configure -background "white"
        
        # Define available modes based on cipher
        if {$algorithm eq "curupira"} {
            # For Curupira: only lettersoup and eax
            .nb.text_tab.main.algo_frame.row1.modeCombo configure -values {"lettersoup" "eax" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
            set incompatible_modes {gcm ocb1 ocb3 ccm mgm}
            
            if {$mode in $incompatible_modes} {
                # If current mode is not compatible, change to "eax" (default for 64 bits)
                .nb.text_tab.main.algo_frame.row1.modeCombo set "lettersoup"
            }
        } elseif {$algorithm in $block64_ciphers} {
            # For 64-bit ciphers: conventional modes + eax, mgm, siv
            .nb.text_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "mgm" "siv" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
        } elseif {$algorithm in {"kalyna256_256" "kalyna256_512" "kalyna512_512" "threefish" "threefish512" "shacal2"}} {
            # For Kalyna, Threefish and Shacal: only conventional modes + eax and siv
            .nb.text_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "siv" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
        } else {
            # For other ciphers: all modes except lettersoup
            .nb.text_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "siv" "gcm" "ocb1" "ocb3" "mgm" "ccm" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
        }
    }
    
    # 2. Control KDF fields
    if {$useKDF} {
        # KDF active: enable fields
        .nb.text_tab.main.algo_frame.row2.saltLabel configure -state normal
        .nb.text_tab.main.algo_frame.row2.saltBox configure -state normal
        .nb.text_tab.main.algo_frame.row2.saltBox configure -background "white"
        
        .nb.text_tab.main.algo_frame.row2.iterLabel configure -state normal
        .nb.text_tab.main.algo_frame.row2.iterBox configure -state normal
        .nb.text_tab.main.algo_frame.row2.iterBox configure -background "white"
        
        .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo configure -state normal
        .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo configure -background "white"
    } else {
        # KDF inactive: disable fields
        .nb.text_tab.main.algo_frame.row2.saltLabel configure -state disabled
        .nb.text_tab.main.algo_frame.row2.saltBox configure -state disabled
        .nb.text_tab.main.algo_frame.row2.saltBox configure -background "#f0f0f0"
        
        .nb.text_tab.main.algo_frame.row2.iterLabel configure -state disabled
        .nb.text_tab.main.algo_frame.row2.iterBox configure -state disabled
        .nb.text_tab.main.algo_frame.row2.iterBox configure -background "#f0f0f0"
        
        .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo configure -state disabled
        .nb.text_tab.main.algo_frame.row2.pbkdf2HashCombo configure -background "#f0f0f0"
    }
    
    # 3. Control IV field
    # Define AEAD modes that don't use IV
    set aead_modes {eax siv gcm ocb1 ocb3 mgm ccm lettersoup}
    
    if {$algorithm in $aead_ciphers || $algorithm eq "xoodyak" || $mode in $aead_modes} {
        # AEAD ciphers or AEAD modes: disable IV
        .nb.text_tab.main.keys_frame.ivLabel configure -state disabled
        .nb.text_tab.main.keys_frame.ivBox configure -state disabled
        .nb.text_tab.main.keys_frame.ivBox configure -background "#f0f0f0"
    } else {
        # Other cases: enable IV
        .nb.text_tab.main.keys_frame.ivLabel configure -state normal
        .nb.text_tab.main.keys_frame.ivBox configure -state normal
        .nb.text_tab.main.keys_frame.ivBox configure -background "white"
    }
}

# Function to update files tab UI based on selected algorithm
proc updateFilesUI {} {
    set algorithm [.nb.file_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.file_tab.main.algo_frame.row1.modeCombo get]
    set useKDF $::useKDFAlgorithmFiles
    
    # Define which algorithms are block, stream or AEAD
    set block_ciphers {
        3des aes anubis aria belt blowfish camellia cast5 cast256 clefia
        crypton curupira e2 gost89 hight idea kalyna128_128 kalyna128_256
        kalyna256_256 kalyna512_512 khazad kuznechik lea loki97 magma
        magenta mars misty1 noekeon present rc2 rc5 rc6 safer+ seed
        serpent shacal2 sm4 threefish threefish512 threefish1024 twine twofish
    }
    
    set stream_ciphers {
        chacha20 chacha20poly1305 ascon grain128a grain hc128 hc256 rc4 salsa20 zuc128 zuc256 xoodyak
    }
    
    set aead_ciphers {
        chacha20poly1305 ascon grain xoodyak
    }
    
    # 64-bit ciphers (block size)
    set block64_ciphers {
        3des blowfish cast5 curupira gost89 hight idea misty1 present rc2 rc5
        rc6 seed twine kalyna128_128 kalyna128_256
    }
    
    # 1. Control Mode combo box
    if {$algorithm in $stream_ciphers} {
        # Stream ciphers: disable mode
        .nb.file_tab.main.algo_frame.row1.modeLabel configure -state disabled
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -state disabled
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -background "#f0f0f0"
        
        # For stream ciphers, set mode automatically
        if {$algorithm eq "rc4"} {
            .nb.file_tab.main.algo_frame.row1.modeCombo set "ecb"
        } else {
            .nb.file_tab.main.algo_frame.row1.modeCombo set "ctr"
        }
    } elseif {$algorithm eq "xoodyak"} {
        # Xoodyak (permutation): fixed mode
        .nb.file_tab.main.algo_frame.row1.modeLabel configure -state disabled
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -state disabled
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -background "#f0f0f0"
        .nb.file_tab.main.algo_frame.row1.modeCombo set "siv"
    } else {
        # Block ciphers: enable mode
        .nb.file_tab.main.algo_frame.row1.modeLabel configure -state normal
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -state normal
        .nb.file_tab.main.algo_frame.row1.modeCombo configure -background "white"
        
        # Define available modes based on cipher
        if {$algorithm eq "curupira"} {
            # For Curupira: only lettersoup and eax
            .nb.file_tab.main.algo_frame.row1.modeCombo configure -values {"lettersoup" "eax" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
            set incompatible_modes {gcm ocb1 ocb3 ccm mgm}
            if {$mode in $incompatible_modes} {
                # If current mode is not compatible, change to "eax" (default for 64 bits)
                .nb.file_tab.main.algo_frame.row1.modeCombo set "lettersoup"
            }
        } elseif {$algorithm in $block64_ciphers} {
            # For 64-bit ciphers: conventional modes + eax, mgm, siv
            .nb.file_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "mgm" "siv" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
            
            # CORRECTION: Check if current mode is compatible with 64-bit ciphers
            # AEAD modes that are NOT compatible with 64-bit ciphers
            set incompatible_modes {gcm ocb1 ocb3 ccm lettersoup}
            
            if {$mode in $incompatible_modes} {
                # If current mode is not compatible, change to "eax" (default for 64 bits)
                .nb.file_tab.main.algo_frame.row1.modeCombo set "eax"
            }
        } elseif {$algorithm in {"kalyna256_256" "kalyna256_512" "kalyna512_512" "threefish" "threefish512" "shacal2"}} {
            # For Kalyna, Threefish and Shacal: only conventional modes + eax and siv
            .nb.file_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "siv" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
        } else {
            # For other ciphers: all modes except lettersoup
            .nb.file_tab.main.algo_frame.row1.modeCombo configure -values {"eax" "siv" "gcm" "ocb1" "ocb3" "mgm" "ccm" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"}
        }
    }
    
    # 2. Control KDF fields
    if {$useKDF} {
        # KDF active: enable fields
        .nb.file_tab.main.algo_frame.row2.saltLabel configure -state normal
        .nb.file_tab.main.algo_frame.row2.saltBox configure -state normal
        .nb.file_tab.main.algo_frame.row2.saltBox configure -background "white"
        
        .nb.file_tab.main.algo_frame.row2.iterLabel configure -state normal
        .nb.file_tab.main.algo_frame.row2.iterBox configure -state normal
        .nb.file_tab.main.algo_frame.row2.iterBox configure -background "white"
        
        .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo configure -state normal
        .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo configure -background "white"
    } else {
        # KDF inactive: disable fields
        .nb.file_tab.main.algo_frame.row2.saltLabel configure -state disabled
        .nb.file_tab.main.algo_frame.row2.saltBox configure -state disabled
        .nb.file_tab.main.algo_frame.row2.saltBox configure -background "#f0f0f0"
        
        .nb.file_tab.main.algo_frame.row2.iterLabel configure -state disabled
        .nb.file_tab.main.algo_frame.row2.iterBox configure -state disabled
        .nb.file_tab.main.algo_frame.row2.iterBox configure -background "white"
        
        .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo configure -state disabled
        .nb.file_tab.main.algo_frame.row2.pbkdf2HashCombo configure -background "#f0f0f0"
    }
    
    # 3. Control IV field
    # Define AEAD modes that don't use IV
    set aead_modes {eax siv gcm ocb1 ocb3 mgm ccm lettersoup}
    
    if {$algorithm in $aead_ciphers || $algorithm eq "xoodyak" || $mode in $aead_modes} {
        # AEAD ciphers or AEAD modes: disable IV
        .nb.file_tab.main.keys_frame.ivLabel configure -state disabled
        .nb.file_tab.main.keys_frame.ivBox configure -state disabled
        .nb.file_tab.main.keys_frame.ivBox configure -background "#f0f0f0"
    } else {
        # Other cases: enable IV
        .nb.file_tab.main.keys_frame.ivLabel configure -state normal
        .nb.file_tab.main.keys_frame.ivBox configure -state normal
        .nb.file_tab.main.keys_frame.ivBox configure -background "white"
    }
}

# Function to update when KDF is changed (Text)
proc updateKDFText {} {
    updateKeyEntryDisplay
    updateTextUI
}

# Function to update when KDF is changed (Files)
proc updateKDFFiles {} {
    updateKeyEntryDisplayFiles
    updateFilesUI
}

# Function to update when algorithm is changed (Text)
proc updateAlgorithmText {} {
    updateTextUI
}

# Function to update when algorithm is changed (Files)
proc updateAlgorithmFiles {} {
    updateFilesUI
}

# Function to update when mode is changed (Text)
proc updateModeText {} {
    updateTextUI
}

# Function to update when mode is changed (Files)
proc updateModeFiles {} {
    updateFilesUI
}

# Function to calculate MAC, HMAC, or CMAC for text OR file
proc calculateMAC {} {
    set algorithm [.nb.mac_tab.main.algo_frame.content.algorithmCombo get]
    set key [.nb.mac_tab.main.keys_frame.content.keyEntry get]
    set iv [.nb.mac_tab.main.keys_frame.content.ivEntry get]
    
    set input_type [.nb.mac_tab.main.input_frame.content.inputTypeCombo get]
    
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state normal
    .nb.mac_tab.main.output_frame.textframe.resultBox delete 1.0 end
    
    # Check if it's text or file input
    if {$input_type eq "Text"} {
        set message [.nb.mac_tab.main.input_frame.content.textframe.inputText get 1.0 end]
        
        if {[string trim $message] eq ""} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "Error: Please enter text to calculate MAC!"
            .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
            return
        }
        
        set use_stdin 1
        set input_arg "<< $message"
    } else {
        set input_file [.nb.mac_tab.main.input_frame.content.inputFile get]
        
        if {$input_file eq "" || ![file exists $input_file]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "Error: Please select a valid file!"
            .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
            return
        }
        
        set use_stdin 0
        set input_arg $input_file
    }
    
    if {$algorithm == "hmac"} {
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            set key ""
        }
        set hash [.nb.mac_tab.main.algo_frame.content.hmacHashCombo get]
        
        # USE CATCH TO CAPTURE ERRORS
        if {[catch {
            if {$use_stdin} {
                set result [exec edgetk -mac hmac -md $hash -key $key << $message 2>@1]
            } else {
                set result [exec edgetk -mac hmac -md $hash -key $key $input_file 2>@1]
            }
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
        } errorMsg]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "ERROR: $errorMsg"
        }
        
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
                "curupira" {
                    set keySize 24
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
        # CMAC and PMAC don't use IV
        
        # USE CATCH TO CAPTURE ERRORS
        if {[catch {
            if {$use_stdin} {
                set result [exec edgetk -mac $algorithm -cipher $cipher -key $key << $message 2>@1]
            } else {
                set result [exec edgetk -mac $algorithm -cipher $cipher -key $key $input_file 2>@1]
            }
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
        } errorMsg]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "ERROR: $errorMsg"
        }
        
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
                "curupira" {
                    set keySize 24
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
        
        # USE CATCH TO CAPTURE ERRORS
        if {[catch {
            if {$use_stdin} {
                set result [exec edgetk -mac vmac -cipher $cipher -key $key -iv $iv -bits [expr {$outSize * 8}] << $message 2>@1]
            } else {
                set result [exec edgetk -mac vmac -cipher $cipher -key $key -iv $iv -bits [expr {$outSize * 8}] $input_file 2>@1]
            }
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
        } errorMsg]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "ERROR: $errorMsg"
        }
        
    } elseif {$algorithm in {"eia128" "eia256" "gost"}} {
        set outSize [.nb.mac_tab.main.algo_frame.content.outSizeCombo get]
        set keySize 0
        switch $algorithm {
            "eia128" {
                set keySize 32
                # EIA128: 128-bit = 16 bytes = 32 hex characters
                if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
                    set iv "00000000000000000000000000000000"
                    .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
                    .nb.mac_tab.main.keys_frame.content.ivEntry insert 0 $iv
                }
            }
            "eia256" {
                set keySize 64
                # EIA256: 184-bit = 23 bytes = 46 hex characters
                if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
                    set iv "0000000000000000000000000000000000000000000000"
                    .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
                    .nb.mac_tab.main.keys_frame.content.ivEntry insert 0 $iv
                }
            }
            "gost" {
                set keySize 32
                # GOST: 64-bit = 8 bytes = 16 hex characters
                if {[string length $iv] < 1 || [string trim $iv 0] eq ""} {
                    set iv "0000000000000000"
                    .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
                    .nb.mac_tab.main.keys_frame.content.ivEntry insert 0 $iv
                }
            }
        }
        
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set key [string repeat "0" $keySize]
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.keyEntry insert 0 $key
        }

        # USE CATCH TO CAPTURE ERRORS
        if {[catch {
            if {$use_stdin} {
                set result [exec edgetk -mac $algorithm -key $key -iv $iv -bits [expr {$outSize * 8}] << $message 2>@1]
            } else {
                set result [exec edgetk -mac $algorithm -key $key -iv $iv -bits [expr {$outSize * 8}] $input_file 2>@1]
            }
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
        } errorMsg]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "ERROR: $errorMsg"
        }
        
    } else {
        set keySize 0
        switch $algorithm {
            "chaskey" {
                set keySize 16
            }
            "poly1305" {
                set keySize 32
            }
            "siphash" {
                set keySize 16
            }
            "skein" {
                set keySize 64
            }
            "xoodyak" {
                set keySize 32
            }
        }
        
        # Check if the key is empty
        if {[string length $key] < 1 || [string trim $key 0] eq ""} {
            # Set a null key with the appropriate size
            set key [string repeat "0" $keySize]
            .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
            .nb.mac_tab.main.keys_frame.content.keyEntry insert 0 $key
        }

        # USE CATCH TO CAPTURE ERRORS
        if {[catch {
            if {$use_stdin} {
                set result [exec edgetk -mac $algorithm -key $key -iv $iv << $message 2>@1]
            } else {
                set result [exec edgetk -mac $algorithm -key $key -iv $iv $input_file 2>@1]
            }
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 $result
        } errorMsg]} {
            .nb.mac_tab.main.output_frame.textframe.resultBox insert 1.0 "ERROR: $errorMsg"
        }
    }
    
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
}

# ===== END OF MAC FUNCTIONS =====

# ===== ECDH FUNCTIONS (from second code) =====

# Function to open file dialog for private key
proc openPrivateKeyECDH {} {
    set file_path [tk_getOpenFile -defaultextension ".pem" -filetypes {{"PEM Files" ".pem"} {"All Files" "*"}}]
    if {$file_path ne ""} {
        .nb.ecdh_tab.main.keys_frame.content.privateKeyInput delete 0 end
        .nb.ecdh_tab.main.keys_frame.content.privateKeyInput insert 0 $file_path
    }
}

# Function to open file dialog for public key
proc openPublicKeyECDH {} {
    set file_path [tk_getOpenFile -defaultextension ".pem" -filetypes {{"PEM Files" ".pem"} {"All Files" "*"}}]
    if {$file_path ne ""} {
        .nb.ecdh_tab.main.keys_frame.content.publicKeyInput delete 0 end
        .nb.ecdh_tab.main.keys_frame.content.publicKeyInput insert 0 $file_path
    }
}

# Function to open file selection dialog for peer key
proc openPeerKey {} {
    set peer_key_path [tk_getOpenFile -defaultextension ".pem" -filetypes {{"PEM Files" ".pem"} {"All Files" "*"}}]
    if {$peer_key_path ne ""} {
        .nb.ecdh_tab.main.keys_frame.content.peerKeyInput delete 0 end
        .nb.ecdh_tab.main.keys_frame.content.peerKeyInput insert 0 $peer_key_path
    }
}

# Function to generate key
proc generateECDHKey {} {
    set algorithm [.nb.ecdh_tab.main.algo_frame.content.algorithmCombo get]
    set bits [.nb.ecdh_tab.main.algo_frame.content.bitsCombo get]
    set paramset [.nb.ecdh_tab.main.algo_frame.content.paramsetCombo get]
    set passphrase [.nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passEntry get]
    set cipher [.nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.cipherCombo get]

    # If passphrase is empty, use "nil"
    if {$passphrase eq ""} {
        set passphrase "nil"
    }
    
    # Get current directory
    set current_dir [pwd]
    
    # Generate unique filenames
    set algo_upper [string toupper $algorithm]
    
    # Base names
    set base_private_name "${algo_upper}_Private"
    set base_public_name "${algo_upper}_Public"
    
    # Default paths without suffix
    set default_private_path [file join $current_dir "${base_private_name}.pem"]
    set default_public_path [file join $current_dir "${base_public_name}.pem"]
    
    # Get current values from input fields (if any)
    set current_private [.nb.ecdh_tab.main.keys_frame.content.privateKeyInput get]
    set current_public [.nb.ecdh_tab.main.keys_frame.content.publicKeyInput get]
    
    # Check if input fields already have values with numeric suffix
    set has_numeric_suffix 0
    set private_key_path $default_private_path
    set public_key_path $default_public_path
    
    if {$current_private ne "" && [file exists $current_private]} {
        # User already selected a specific file, check if it has numeric suffix
        set filename [file tail $current_private]
        if {[regexp {_(\d+)\.pem$} $filename]} {
            # File has numeric suffix, use it
            set private_key_path $current_private
            set has_numeric_suffix 1
            
            # Check if corresponding public key exists with same suffix
            if {[regexp {^(.*)_(\d+)\.pem$} $filename -> base suffix]} {
                set public_candidate [file join $current_dir "${base_public_name}_${suffix}.pem"]
                if {[file exists $public_candidate] && $current_public eq ""} {
                    set public_key_path $public_candidate
                }
            }
        }
    }
    
    # If user manually entered public key, use it
    if {$current_public ne "" && [file exists $current_public]} {
        set public_key_path $current_public
    }
    
    # Check if the selected files already exist
    set private_exists [file exists $private_key_path]
    set public_exists [file exists $public_key_path]
    
    if {$private_exists || $public_exists} {
        # Show dialog window
        set files_message ""
        if {$private_exists && $public_exists} {
            set files_message "Both private and public key files already exist."
        } elseif {$private_exists} {
            set files_message "Private key file already exists."
        } else {
            set files_message "Public key file already exists."
        }
        
        set choice [tk_messageBox \
            -title "Keys Already Exist" \
            -message "Files already exist:\n\nPrivate: [file tail $private_key_path]\nPublic: [file tail $public_key_path]\n\nWhat do you want to do?" \
            -type yesnocancel \
            -icon warning \
            -detail "Yes: Overwrite existing files\nNo: Generate with NEW numeric suffix (rename)\nCancel: Abort operation" \
            -default cancel]
        
        if {$choice eq "cancel"} {
            # User canceled
            .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Key generation cancelled."
            return
        } elseif {$choice eq "no"} {
            # User wants to rename with NEW numeric suffix
            # Find NEXT available name for private key
            set counter 1
            set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
            
            # Start from 1 and find the first available number
            while {[file exists $new_private_path]} {
                incr counter
                set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
            }
            
            # Use the same counter for public key
            set new_public_path [file join $current_dir "${base_public_name}_${counter}.pem"]
            
            # If public key with that number already exists, find next available
            while {[file exists $new_public_path]} {
                incr counter
                set new_private_path [file join $current_dir "${base_private_name}_${counter}.pem"]
                set new_public_path [file join $current_dir "${base_public_name}_${counter}.pem"]
            }
            
            set private_key_path $new_private_path
            set public_key_path $new_public_path
        }
        # If choice is "yes", keep the existing paths (will be overwritten)
    } else {
        # Files don't exist, check if we should use the current input values
        if {$current_private ne "" && [file dirname $current_private] eq $current_dir} {
            # User has entered a specific path, use it
            set private_key_path $current_private
        }
        
        if {$current_public ne "" && [file dirname $current_public] eq $current_dir} {
            # User has entered a specific path, use it
            set public_key_path $current_public
        }
    }
    
    if {[catch {
        exec edgetk -pkey keygen -algorithm $algorithm -bits $bits -paramset $paramset -pass $passphrase -cipher $cipher -prv $private_key_path -pub $public_key_path 2>@1
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Error generating keys: $error"
        return
    }

    .nb.ecdh_tab.main.keys_frame.content.privateKeyInput delete 0 end
    .nb.ecdh_tab.main.keys_frame.content.privateKeyInput insert 0 $private_key_path
    
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput configure -state normal
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput delete 0 end
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput insert 0 $public_key_path
    .nb.ecdh_tab.main.keys_frame.content.publicKeyInput configure -state disabled
    
    .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
    .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Keys generated successfully!\nPrivate key saved as: [file tail $private_key_path]\nPublic key saved as: [file tail $public_key_path]"
}

# Function to derive key
proc deriveECDHKey {} {
    set private_key_path [.nb.ecdh_tab.main.keys_frame.content.privateKeyInput get]
    set peer_key_path [.nb.ecdh_tab.main.keys_frame.content.peerKeyInput get]
    set algorithm [.nb.ecdh_tab.main.algo_frame.content.algorithmCombo get]
    set outputKeySize [.nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo get]
    set passphrase [.nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passEntry get]

    # If passphrase is empty, use "nil"
    if {$passphrase eq ""} {
        set passphrase "nil"
    }
    
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
        set result [exec edgetk -pkey derive -algorithm $algorithm -key $private_key_path -pass $passphrase -pub $peer_key_path 2>@1]
        
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "Shared Secret Derived Successfully:\n\n$result"
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR deriving key: $error"
    }
}

# Function to execute HKDF - MODIFIED TO USE ADDITIONAL INFO
proc executeECDHHKDF {} {
    set salt [.nb.ecdh_tab.main.kdf_frame.content.saltInput get]
    set info [.nb.ecdh_tab.main.kdf_frame.content.infoInput get]
    set hashAlgorithm [.nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo get]
    set outputKeySize [.nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo get]
    set outputSize [expr {$outputKeySize * 8}]
    
    # Get text from output area
    set full_text [string trim [.nb.ecdh_tab.main.output_frame.textframe.outputArea get 1.0 end]]
    
    # Extract hexadecimal (same logic as Copy button)
    set hexValue ""
    set lines [split $full_text "\n"]
    
    # Find last non-empty line
    set last_line ""
    foreach line [lreverse $lines] {
        if {[string trim $line] ne ""} {
            set last_line [string trim $line]
            break
        }
    }
    
    # Check if it's hexadecimal
    if {[regexp {^[0-9a-fA-F]+$} $last_line]} {
        set hexValue $last_line
    } else {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR: No valid hexadecimal found in last line.\nPlease derive a shared secret first."
        return
    }
    
    if {$hexValue eq ""} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR: No input key found. Please derive a shared secret first."
        return
    }
    
    # Build HKDF command
    set cmd "edgetk -kdf hkdf -md $hashAlgorithm -key $hexValue -bits $outputSize"
    
    # Add salt if provided
    if {$salt ne ""} {
        append cmd " -salt $salt"
    }
    
    # Add info if provided
    if {$info ne ""} {
        append cmd " -info $info"
    }
    
    if {[catch {
        set hkdfResult [exec {*}$cmd 2>@1]
        
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "HKDF Applied Successfully:\n\n$hkdfResult"
    } error]} {
        .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.ecdh_tab.main.output_frame.textframe.outputArea insert end "ERROR applying HKDF: $error"
    }
}

# ===== END OF ECDH FUNCTIONS =====

# ===== ENCRYPTION FUNCTIONS (from second code) =====

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
        .nb.text_tab.main.keys_frame.keyBox configure -show "*"
    } else {
        .nb.text_tab.main.keys_frame.keyBox configure -show ""
    }
}

# Function to update key display (Files)
proc updateKeyEntryDisplayFiles {} {
    global useKDFAlgorithmFiles
    if {$useKDFAlgorithmFiles == 1} {
        .nb.file_tab.main.keys_frame.keyBox configure -show "*"
    } else {
        .nb.file_tab.main.keys_frame.keyBox configure -show ""
    }
}

# Function to calculate IV size
proc calculateIVSize {algorithm mode} {
    set ivSize 32
    switch $algorithm {
        "3des" - "blowfish" - "cast5" - "gost89" - "idea" - "magma" - "misty1" - "rc2" - "rc5" - "twine" - "present" { set ivSize 16 }
        "curupira" { set ivSize 24 }
        "aes" - "serpent" - "aria" - "lea" - "anubis" - "twofish" - "sm4" - "camellia" - "kuznechik" - "seed" - "hc128" - "zuc128" { set ivSize 32 }
        "zuc256" { set ivSize 46 }
        "hc256" - "skein" - "threefish" - "kalyna256_256" - "shacal2" { set ivSize 64 }
        "kalyna512_512" - "threefish512" { set ivSize 128 }
        "rc4" - "chacha20poly1305" { set ivSize 0 }
        "salsa20" - "chacha20" { set ivSize 48 }
    }
    switch $mode {
        "ecb" - "gcm" - "ocb1" - "ocb3" - "mgm" - "ccm" - "eax" - "siv" - "lettersoup" { set ivSize 0 }
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
    set encoding [.nb.text_tab.main.algo_frame.row1.encodingCombo get]
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

    # Clear output area
    .nb.text_tab.main.cipher_frame.textframe.text delete 1.0 end
    
    # Use catch to capture errors
    if {[catch {
        # Execute encryption and encode with edgetk -baseNN enc
        if {$encoding eq "base64"} {
            set encryptedMsg [exec edgetk -crypt enc -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash << $plaintext | edgetk -base64 enc]
        } elseif {$encoding eq "base32"} {
            set encryptedMsg [exec edgetk -crypt enc -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash << $plaintext | edgetk -base32 enc]
        } else {
            # base85
            set encryptedMsg [exec edgetk -crypt enc -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash << $plaintext | edgetk -base85 enc]
        }
        .nb.text_tab.main.cipher_frame.textframe.text insert 1.0 $encryptedMsg
    } errorMsg]} {
        # If error occurs, show in output area (ciphertext)
        .nb.text_tab.main.cipher_frame.textframe.text insert 1.0 "Error: $errorMsg"
    }
}

proc decrypt {} {
    set ciphertext [.nb.text_tab.main.cipher_frame.textframe.text get 1.0 end]
    set key [.nb.text_tab.main.keys_frame.keyBox get]
    set iv [.nb.text_tab.main.keys_frame.ivBox get]
    set salt [.nb.text_tab.main.algo_frame.row2.saltBox get]
    set iter [.nb.text_tab.main.algo_frame.row2.iterBox get]
    set algorithm [.nb.text_tab.main.algo_frame.row1.algorithmCombo get]
    set mode [.nb.text_tab.main.algo_frame.row1.modeCombo get]
    set encoding [.nb.text_tab.main.algo_frame.row1.encodingCombo get]
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

    # Clear output area
    .nb.text_tab.main.plain_frame.textframe.text delete 1.0 end
    
    # Use catch to capture errors
    if {[catch {
        # Decode with edgetk -baseNN dec before decrypting
        if {$encoding eq "base64"} {
            set decryptedMsg [exec edgetk -base64 dec << $ciphertext | edgetk -crypt dec -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash]
        } elseif {$encoding eq "base32"} {
            set decryptedMsg [exec edgetk -base32 dec << $ciphertext | edgetk -crypt dec -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash]
        } else {
            # base85
            set decryptedMsg [exec edgetk -base85 dec << $ciphertext | edgetk -crypt dec -key $key -iv $iv -cipher $algorithm -mode $mode -kdf $kdfOptionAlgorithm -salt $salt -iter $iter -md $pbkdf2Hash]
        }
        .nb.text_tab.main.plain_frame.textframe.text insert 1.0 $decryptedMsg
    } errorMsg]} {
        # If error occurs, show in output area (plaintext)
        .nb.text_tab.main.plain_frame.textframe.text insert 1.0 "Error: $errorMsg"
    }
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
    
    # Build edgetk command
    set cmd "edgetk -crypt enc -key \"$key\" -iv \"$iv\" -cipher \"$algorithm\" -mode \"$mode\""
    
    if {$kdfOptionAlgorithm ne ""} {
        append cmd " -kdf \"$kdfOptionAlgorithm\" -salt \"$salt\" -iter \"$iter\" -md \"$pbkdf2Hash\""
    }
    
    # Add input file and redirect stdout to output file
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
    
    # Build edgetk command
    set cmd "edgetk -crypt dec -key \"$key\" -iv \"$iv\" -cipher \"$algorithm\" -mode \"$mode\""
    
    if {$kdfOptionAlgorithm ne ""} {
        append cmd " -kdf \"$kdfOptionAlgorithm\" -salt \"$salt\" -iter \"$iter\" -md \"$pbkdf2Hash\""
    }
    
    # Add input file and redirect stdout to output file
    append cmd " \"$inputFile\" > \"$outputFile\""
    
    if {[catch {
        exec {*}$cmd
    } errorMsg]} {
        updateStatus "ERROR: Decryption failed!\n$errorMsg"
        return
    }
    
    updateStatus "SUCCESS: File decrypted!\nInput: [file tail $inputFile]\nOutput: [file tail $outputFile]\nSize: [formatSize [file size $outputFile]]"
}

# ===== END OF ENCRYPTION FUNCTIONS =====

# Main window configuration
wm title . "EDGE Crypto Suite - Professional Cryptographic Toolkit"
wm geometry . 850x665
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
label .header.subtitle -text "Encrypted Data Gateway Engine - Professional Cryptographic Toolkit" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .header.subtitle -pady 0

# Notebook for tabs (Text, Files, ECDH, MAC, and Signatures)
ttk::notebook .nb
pack .nb -fill both -expand yes -padx 8 -pady 5

# Configuração BASE (funciona em todos)
ttk::style configure TNotebook.Tab -padding {10 5}

# Aplicar cores personalizadas APENAS se NÃO for Windows
if {$tcl_platform(platform) ne "windows"} {
    # Estas linhas só executam no Linux/Mac
    ttk::style configure TNotebook -background $bg_color
    ttk::style map TNotebook.Tab \
        -background [list selected $accent_color !selected $frame_color] \
        -foreground [list selected white !selected $accent_color]
}



# ========== SIGNATURES TAB (from first code) ==========
frame .nb.signatures_tab -bg $bg_color
.nb add .nb.signatures_tab -text " Signatures "

# Main frame for content (Signatures)
frame .nb.signatures_tab.main -bg $bg_color
pack .nb.signatures_tab.main -fill both -expand yes -padx 8 -pady 5

# Algorithm settings frame - SINGLE LINE
frame .nb.signatures_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.signatures_tab.main.algo_frame.title -text "CRYPTOGRAPHIC SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.signatures_tab.main.algo_frame.content -bg $frame_color
pack .nb.signatures_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Create Algorithm ComboBox
set ::algorithmComboData {"ecdsa" "ecsdsa" "eckcdsa" "ecgdsa" "sm2" "sm2ph" "gost2012" "rsa" "ed25519" "ed25519ph" "ed448" "ed448ph" "ed521" "ed521ph" "bign" "bip0340"}
label .nb.signatures_tab.main.algo_frame.content.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.algo_frame.content.algorithmCombo -values $::algorithmComboData -state readonly -width 10
.nb.signatures_tab.main.algo_frame.content.algorithmCombo set "ecdsa"

# Create Bits ComboBox
set ::bitsComboData {"224" "256" "384" "512" "521" "1024" "2048" "3072" "4096"}
label .nb.signatures_tab.main.algo_frame.content.bitsLabel -text "Bits:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.algo_frame.content.bitsCombo -values $::bitsComboData -state readonly -width 8
.nb.signatures_tab.main.algo_frame.content.bitsCombo set "256"

# Create Paramset ComboBox
set ::paramsetComboData {"A" "B" "C" "D"}
label .nb.signatures_tab.main.algo_frame.content.paramsetLabel -text "Paramset:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.algo_frame.content.paramsetCombo -values $::paramsetComboData -state readonly -width 5
.nb.signatures_tab.main.algo_frame.content.paramsetCombo set "A"

# Create Hash Algorithm ComboBox
set ::hashAlgorithmComboData {
    bash224 bash256 bash384 bash512
    belt
    blake2b256 blake2b512
    blake2s256
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
label .nb.signatures_tab.main.algo_frame.content.hashAlgorithmLabel -text "Digest:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo -values $::hashAlgorithmComboData -state readonly -width 12
.nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo set "sha3-256"

# Create Curve ComboBox
set ::curveComboData {
    secp224r1
    secp256r1
    secp384r1
    secp521r1
    sect283r1
    sect409r1
    sect571r1
    sect283k1
    sect409k1
    sect571k1
    brainpoolp256r1
    brainpoolp384r1
    brainpoolp512r1
    brainpoolp256t1
    brainpoolp384t1
    brainpoolp512t1
    numsp256d1
    numsp384d1
    numsp512d1
    numsp256t1
    numsp384t1
    numsp512t1
    tom256
    tom384
    kg256r1
    kg384r1
    frp256v1
    secp256k1
}
label .nb.signatures_tab.main.algo_frame.content.curveLabel -text "Curve:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.algo_frame.content.curveCombo -values $::curveComboData -state readonly -width 14
.nb.signatures_tab.main.algo_frame.content.curveCombo set "secp256r1"

# Grid for algorithm settings - ALL IN ONE LINE
grid .nb.signatures_tab.main.algo_frame.content.algorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.algorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.bitsLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.bitsCombo -row 0 -column 3 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.curveLabel -row 0 -column 4 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.curveCombo -row 0 -column 5 -sticky we -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.paramsetLabel -row 0 -column 6 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.paramsetCombo -row 0 -column 7 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.hashAlgorithmLabel -row 0 -column 8 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.algo_frame.content.hashAlgorithmCombo -row 0 -column 9 -sticky we -padx 3 -pady 3

# Key management frame
frame .nb.signatures_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.keys_frame -fill x -padx 8 -pady 5

# Title and passphrase in same line
frame .nb.signatures_tab.main.keys_frame.title_frame -bg $frame_color
pack .nb.signatures_tab.main.keys_frame.title_frame -fill x -padx 8 -pady 3

# Title aligned left
label .nb.signatures_tab.main.keys_frame.title_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.signatures_tab.main.keys_frame.title_frame.title -side left -anchor w

# Frame for passphrase aligned right
frame .nb.signatures_tab.main.keys_frame.title_frame.pass_frame -bg $frame_color
pack .nb.signatures_tab.main.keys_frame.title_frame.pass_frame -side right -anchor e -pady 0

# Cipher combobox (after passphrase box)
ttk::combobox .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.cipherCombo \
    -values {"aes" "anubis" "belt" "curupira" "kuznechik" "sm4" "serpent" "twofish" "camellia" "cast256" "mars" "noekeon" "crypton"} \
    -width 8 -state readonly
.nb.signatures_tab.main.keys_frame.title_frame.pass_frame.cipherCombo set "aes"

# Passphrase entry (box)
entry .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passEntry -width 15 -font {Consolas 9} -show "*"

# Passphrase label
label .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passLabel -text "Passphrase:" -font {Arial 9 bold} -bg $frame_color

# Pack in order: combo, entry, label (right to left)
pack .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.cipherCombo \
     .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passEntry \
     .nb.signatures_tab.main.keys_frame.title_frame.pass_frame.passLabel \
     -side right -padx 3

frame .nb.signatures_tab.main.keys_frame.content -bg $frame_color
pack .nb.signatures_tab.main.keys_frame.content -fill x -padx 8 -pady 3

# Private Key
label .nb.signatures_tab.main.keys_frame.content.privateKeyLabel -text "Private Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.privateKeyInput -width 50 -font {Consolas 9}
button .nb.signatures_tab.main.keys_frame.content.openPrivateButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.keys_frame.content.privateKeyInput
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.keys_frame.content.privateKeyLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.keys_frame.content.privateKeyInput -row 0 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.signatures_tab.main.keys_frame.content.openPrivateButton -row 0 -column 2 -sticky w -padx 3 -pady 3

# Public Key
label .nb.signatures_tab.main.keys_frame.content.publicKeyLabel -text "Public Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.publicKeyInput -width 50 -font {Consolas 9}
button .nb.signatures_tab.main.keys_frame.content.openPublicButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.keys_frame.content.publicKeyInput
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.keys_frame.content.publicKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.keys_frame.content.publicKeyInput -row 1 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.signatures_tab.main.keys_frame.content.openPublicButton -row 1 -column 2 -sticky w -padx 3 -pady 3

# Generate Keys button
button .nb.signatures_tab.main.keys_frame.content.generateButton -text "Generate Keys" -command generateKey \
    -bg "#27ae60" -fg white -font {Arial 10 bold} -pady 3 -width 20
grid .nb.signatures_tab.main.keys_frame.content.generateButton -row 2 -column 0 -columnspan 3 -sticky ew -padx 3 -pady 8

# Configure column weights
grid columnconfigure .nb.signatures_tab.main.keys_frame.content 1 -weight 1

# Input data frame - SAME STRUCTURE AS OUTPUT
frame .nb.signatures_tab.main.input_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.input_frame -fill x -padx 8 -pady 5

label .nb.signatures_tab.main.input_frame.title -text "INPUT DATA" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.input_frame.title -anchor w -padx 8 -pady 3

frame .nb.signatures_tab.main.input_frame.content -bg $frame_color
pack .nb.signatures_tab.main.input_frame.content -fill x -padx 8 -pady 3

# Input type
label .nb.signatures_tab.main.input_frame.content.inputTypeLabel -text "Input Type:" -font {Arial 9 bold} -bg $frame_color
set ::inputTypeComboData {"Text" "File"}
ttk::combobox .nb.signatures_tab.main.input_frame.content.inputTypeCombo -values $::inputTypeComboData -state readonly -width 8
.nb.signatures_tab.main.input_frame.content.inputTypeCombo set "Text"

# Bind combobox selection
bind .nb.signatures_tab.main.input_frame.content.inputTypeCombo <<ComboboxSelected>> selectInputType

# File input
label .nb.signatures_tab.main.input_frame.content.fileLabel -text "File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.input_frame.content.inputFile -width 50 -font {Consolas 9}
button .nb.signatures_tab.main.input_frame.content.openFileButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.input_frame.content.inputFile
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.input_frame.content.inputTypeLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.input_frame.content.inputTypeCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.input_frame.content.fileLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.signatures_tab.main.input_frame.content.inputFile -row 0 -column 3 -sticky ew -padx 3 -pady 3
grid .nb.signatures_tab.main.input_frame.content.openFileButton -row 0 -column 4 -sticky w -padx 3 -pady 3

# Frame for text area - SAME STRUCTURE AS OUTPUT
frame .nb.signatures_tab.main.input_frame.content.textframe -bg $frame_color
grid .nb.signatures_tab.main.input_frame.content.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 3 -pady 3

# Text area for text input - 4 LINES, SAME STRUCTURE AS OUTPUT
text .nb.signatures_tab.main.input_frame.content.textframe.inputText -width 70 -height 2 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.signatures_tab.main.input_frame.content.textframe.yscroll -orient vertical \
    -command {.nb.signatures_tab.main.input_frame.content.textframe.inputText yview}
.nb.signatures_tab.main.input_frame.content.textframe.inputText configure \
    -yscrollcommand {.nb.signatures_tab.main.input_frame.content.textframe.yscroll set}

grid .nb.signatures_tab.main.input_frame.content.textframe.inputText -row 0 -column 0 -sticky "nsew"
grid .nb.signatures_tab.main.input_frame.content.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.signatures_tab.main.input_frame.content.textframe 0 -weight 1
grid columnconfigure .nb.signatures_tab.main.input_frame.content.textframe 0 -weight 1

grid columnconfigure .nb.signatures_tab.main.input_frame.content 3 -weight 1
grid rowconfigure .nb.signatures_tab.main.input_frame.content 1 -weight 1

# Initially disable file input
selectInputType

# Output frame
frame .nb.signatures_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.output_frame -fill both -expand true -padx 8 -pady 5

label .nb.signatures_tab.main.output_frame.title -text "SIGNATURE" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.output_frame.title -anchor w -padx 8 -pady 3

# Create output text area - 2 LINES FOR SIGNATURE
frame .nb.signatures_tab.main.output_frame.textframe -bg $frame_color
pack .nb.signatures_tab.main.output_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.signatures_tab.main.output_frame.textframe.outputArea -width 70 -height 4 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.signatures_tab.main.output_frame.textframe.yscroll -orient vertical \
    -command {.nb.signatures_tab.main.output_frame.textframe.outputArea yview}
.nb.signatures_tab.main.output_frame.textframe.outputArea configure \
    -yscrollcommand {.nb.signatures_tab.main.output_frame.textframe.yscroll set}

grid .nb.signatures_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.signatures_tab.main.output_frame.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.signatures_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.signatures_tab.main.output_frame.textframe 0 -weight 1

# Utility buttons - MORE COMPACT
frame .nb.signatures_tab.main.output_frame.utility_buttons -bg $frame_color
pack .nb.signatures_tab.main.output_frame.utility_buttons -fill x -padx 8 -pady 3

button .nb.signatures_tab.main.output_frame.utility_buttons.copyButton -text "Copy" -command {
    copyText [.nb.signatures_tab.main.output_frame.textframe.outputArea get 1.0 end]
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.copyButton -side left -padx 2

button .nb.signatures_tab.main.output_frame.utility_buttons.pasteButton -text "Paste" -command {
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
    .nb.signatures_tab.main.output_frame.textframe.outputArea insert end [clipboard get]
} -bg "#e67e22" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.pasteButton -side left -padx 2

button .nb.signatures_tab.main.output_frame.utility_buttons.clearOutputButton -text "Clear" -command {
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
    set ::signature_data ""
} -bg "#e74c3c" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.clearOutputButton -side left -padx 2

button .nb.signatures_tab.main.output_frame.utility_buttons.clearInputButton -text "Clear Input" -command {
    .nb.signatures_tab.main.input_frame.content.textframe.inputText delete 1.0 end
    .nb.signatures_tab.main.input_frame.content.inputFile delete 0 end
} -bg "#f39c12" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.clearInputButton -side left -padx 2

# Sign/Verify buttons (outside SIGNATURE OUTPUT section)
frame .nb.signatures_tab.main.sign_verify_frame -bg $bg_color
pack .nb.signatures_tab.main.sign_verify_frame -fill x -padx 8 -pady 10

# Pack Verify first (rightmost)
button .nb.signatures_tab.main.sign_verify_frame.verifyButton -text "Verify" -command verifySignature \
    -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 20 -pady 3 -relief raised -bd 2
pack .nb.signatures_tab.main.sign_verify_frame.verifyButton -side right -padx 3

# Then pack Sign (left of Verify)
button .nb.signatures_tab.main.sign_verify_frame.signButton -text "Sign" -command createSignature \
    -bg "#9b59b6" -fg white -font {Arial 10 bold} \
    -padx 20 -pady 3 -relief raised -bd 2
pack .nb.signatures_tab.main.sign_verify_frame.signButton -side right -padx 3

# ========== END OF SIGNATURES TAB ==========

# ========== TEXT TAB (ORIGINAL LAYOUT) ==========
frame .nb.text_tab -bg $bg_color
.nb add .nb.text_tab -text " Encrypt Text "

# Main frame for content (Text)
frame .nb.text_tab.main -bg $bg_color
pack .nb.text_tab.main -fill both -expand yes

# Grid configuration for expansion (Text)
grid columnconfigure .nb.text_tab.main 0 -weight 1
grid rowconfigure .nb.text_tab.main {1 2} -weight 1

# Algorithm configuration frame (Text)
frame .nb.text_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.algo_frame -row 0 -column 0 -columnspan 6 -sticky "ew" -padx 8 -pady 5

# ALGORITHM SETTINGS title
label .nb.text_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" \
    -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.text_tab.main.algo_frame.title -anchor w -padx 8 -pady 5

# Row 1: Algorithm and Mode (Text)
frame .nb.text_tab.main.algo_frame.row1 -bg $frame_color
pack .nb.text_tab.main.algo_frame.row1 -fill x -padx 8 -pady 3

label .nb.text_tab.main.algo_frame.row1.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.text_tab.main.algo_frame.row1.algorithmCombo \
    -values {"3des" "aes" "anubis" "aria" "ascon" "belt" "blowfish" "camellia" "cast5" "chacha20" "chacha20poly1305" "curupira" "gost89" "grain128a" "grain" "hc128" "hc256" "idea" "kalyna128_128" "kalyna128_256" "kalyna256_256" "kalyna512_512" "kcipher2" "kuznechik" "lea" "magma" "misty1" "present" "rc2" "rc4" "rc5" "salsa20" "seed" "serpent" "shacal2" "skein" "sm4" "threefish" "threefish512" "twine" "twofish" "xoodyak" "zuc128" "zuc256"} \
    -width 18 -state readonly
.nb.text_tab.main.algo_frame.row1.algorithmCombo set "aes"

label .nb.text_tab.main.algo_frame.row1.modeLabel -text "Mode:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.text_tab.main.algo_frame.row1.modeCombo \
    -values {"eax" "siv" "gcm" "ocb1" "ocb3" "mgm" "ccm" "lettersoup" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"} \
    -width 18 -state readonly
.nb.text_tab.main.algo_frame.row1.modeCombo set "ctr"

# NEW: Add combobox for Encoding
label .nb.text_tab.main.algo_frame.row1.encodingLabel -text "Encoding:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.text_tab.main.algo_frame.row1.encodingCombo \
    -values {"base32" "base64" "base85"} \
    -width 10 -state readonly
.nb.text_tab.main.algo_frame.row1.encodingCombo set "base64"

pack .nb.text_tab.main.algo_frame.row1.algorithmLabel .nb.text_tab.main.algo_frame.row1.algorithmCombo \
     .nb.text_tab.main.algo_frame.row1.modeLabel .nb.text_tab.main.algo_frame.row1.modeCombo \
     .nb.text_tab.main.algo_frame.row1.encodingLabel .nb.text_tab.main.algo_frame.row1.encodingCombo \
     -side left -padx 5

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
    blake2s256
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

# Plaintext frame (shorter) - MODIFICADO para permitir expansão
frame .nb.text_tab.main.plain_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.plain_frame -row 1 -column 0 -columnspan 6 -sticky "nsew" -padx 8 -pady 5
grid rowconfigure .nb.text_tab.main.plain_frame 1 -weight 1  ;# Linha do text widget com peso 1
grid columnconfigure .nb.text_tab.main.plain_frame 0 -weight 1

label .nb.text_tab.main.plain_frame.label -text "PLAINTEXT" -font {Arial 10 bold} -bg $frame_color
grid .nb.text_tab.main.plain_frame.label -row 0 -column 0 -sticky w -padx 8 -pady 3

# Create plaintext text box with scrollbar (shorter) - MODIFICADO para expansão
frame .nb.text_tab.main.plain_frame.textframe -bg $frame_color
grid .nb.text_tab.main.plain_frame.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 8 -pady 3
grid rowconfigure .nb.text_tab.main.plain_frame.textframe 0 -weight 1  ;# Text widget com peso 1
grid columnconfigure .nb.text_tab.main.plain_frame.textframe 0 -weight 1

text .nb.text_tab.main.plain_frame.textframe.text -width 60 -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.text_tab.main.plain_frame.textframe.scroll -command {.nb.text_tab.main.plain_frame.textframe.text yview}
.nb.text_tab.main.plain_frame.textframe.text configure -yscrollcommand {.nb.text_tab.main.plain_frame.textframe.scroll set}
grid .nb.text_tab.main.plain_frame.textframe.text -row 0 -column 0 -sticky "nsew"
grid .nb.text_tab.main.plain_frame.textframe.scroll -row 0 -column 1 -sticky "ns"

# Ciphertext frame (shorter) - MODIFICADO para permitir expansão
frame .nb.text_tab.main.cipher_frame -bg $frame_color -relief solid -bd 1
grid .nb.text_tab.main.cipher_frame -row 2 -column 0 -columnspan 6 -sticky "nsew" -padx 8 -pady 5
grid rowconfigure .nb.text_tab.main.cipher_frame 1 -weight 1  ;# Linha do text widget com peso 1
grid columnconfigure .nb.text_tab.main.cipher_frame 0 -weight 1

label .nb.text_tab.main.cipher_frame.label -text "CIPHERTEXT" -font {Arial 10 bold} -bg $frame_color
grid .nb.text_tab.main.cipher_frame.label -row 0 -column 0 -sticky w -padx 8 -pady 3

# Create ciphertext text box with scrollbar (shorter) - MODIFICADO para expansão
frame .nb.text_tab.main.cipher_frame.textframe -bg $frame_color
grid .nb.text_tab.main.cipher_frame.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 8 -pady 3
grid rowconfigure .nb.text_tab.main.cipher_frame.textframe 0 -weight 1  ;# Text widget com peso 1
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

button .nb.text_tab.main.cipher_frame.buttons.copy -text "Copy" -command {
    clipboard clear; clipboard append [.nb.text_tab.main.cipher_frame.textframe.text get 1.0 end]
} -bg "#27ae60" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.cipher_frame.buttons.copy -side left -padx 3

button .nb.text_tab.main.cipher_frame.buttons.paste -text "Paste" -command {
    .nb.text_tab.main.cipher_frame.textframe.text delete 1.0 end
    .nb.text_tab.main.cipher_frame.textframe.text insert 1.0 [clipboard get]
} -bg "#e67e22" -fg white -font {Arial 9 bold}
pack .nb.text_tab.main.cipher_frame.buttons.paste -side left -padx 3

button .nb.text_tab.main.cipher_frame.buttons.clear -text "Clear" -command {
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
button .nb.text_tab.main.action_frame.encryptButton -text "Encrypt" \
    -command {encrypt} -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.text_tab.main.action_frame.encryptButton -side left -padx 8

# Create Decrypt button
button .nb.text_tab.main.action_frame.decryptButton -text "Decrypt" \
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

# ALGORITHM SETTINGS title
label .nb.file_tab.main.algo_frame.title -text "ALGORITHM SETTINGS" \
    -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.file_tab.main.algo_frame.title -anchor w -padx 8 -pady 5

# Row 1: Algorithm and Mode (Files)
frame .nb.file_tab.main.algo_frame.row1 -bg $frame_color
pack .nb.file_tab.main.algo_frame.row1 -fill x -padx 8 -pady 3

label .nb.file_tab.main.algo_frame.row1.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.file_tab.main.algo_frame.row1.algorithmCombo \
    -values {"3des" "aes" "anubis" "aria" "ascon" "belt" "blowfish" "camellia" "cast5" "chacha20" "chacha20poly1305" "curupira" "gost89" "grain128a" "grain" "hc128" "hc256" "idea" "kalyna128_128" "kalyna128_256" "kalyna256_256" "kalyna512_512" "kcipher2" "kuznechik" "lea" "magma" "misty1" "present" "rc2" "rc4" "rc5" "salsa20" "seed" "serpent" "shacal2" "skein" "sm4" "threefish" "threefish512" "twine" "twofish" "xoodyak" "zuc128" "zuc256"} \
    -width 18 -state readonly
.nb.file_tab.main.algo_frame.row1.algorithmCombo set "aes"

label .nb.file_tab.main.algo_frame.row1.modeLabel -text "Mode:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.file_tab.main.algo_frame.row1.modeCombo \
    -values {"eax" "siv" "gcm" "ocb1" "ocb3" "mgm" "ccm" "lettersoup" "cbc" "cfb" "cfb8" "ctr" "ecb" "ige" "ofb"} \
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
    blake2s256
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

button .nb.file_tab.main.file_selection.input_frame.browse -text "Browse" \
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

button .nb.file_tab.main.file_selection.output_frame.browse -text "Browse" \
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
button .nb.file_tab.main.action_frame.encryptButton -text "Encrypt File" \
    -command {encryptFile} -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.file_tab.main.action_frame.encryptButton -side left -padx 8

button .nb.file_tab.main.action_frame.decryptButton -text "Decrypt File" \
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

# Frame for algorithm settings
frame .nb.ecdh_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.ecdh_tab.main.algo_frame.title -text "CRYPTOGRAPHIC SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.ecdh_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.ecdh_tab.main.algo_frame.content -bg $frame_color
pack .nb.ecdh_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Create Algorithm ComboBox
set ::algorithmComboData {"ec" "anssi" "koblitz" "nums" "kg" "tom" "sm2" "gost2012" "x25519" "x448"}
label .nb.ecdh_tab.main.algo_frame.content.algorithmLabel -text "Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.ecdh_tab.main.algo_frame.content.algorithmCombo -values $::algorithmComboData -state readonly -width 12
.nb.ecdh_tab.main.algo_frame.content.algorithmCombo set "ec"

# Create Bits ComboBox
set ::bitsComboData {"256" "384" "512"}
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

# Grid for algorithm settings
grid .nb.ecdh_tab.main.algo_frame.content.algorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.algorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.bitsLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.bitsCombo -row 0 -column 3 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.paramsetLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.paramsetCombo -row 1 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.outputKeySizeLabel -row 1 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.algo_frame.content.outputKeySizeCombo -row 1 -column 3 -sticky w -padx 3 -pady 3

# Frame for key management
frame .nb.ecdh_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.ecdh_tab.main.keys_frame -fill x -padx 8 -pady 5

# Title and passphrase in same line
frame .nb.ecdh_tab.main.keys_frame.title_frame -bg $frame_color
pack .nb.ecdh_tab.main.keys_frame.title_frame -fill x -padx 8 -pady 3

# Title aligned left
label .nb.ecdh_tab.main.keys_frame.title_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color -fg $accent_color
pack .nb.ecdh_tab.main.keys_frame.title_frame.title -side left -anchor w

# Frame for passphrase aligned right
frame .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame -bg $frame_color
pack .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame -side right -anchor e -pady 0

# Cipher combobox (after passphrase box)
ttk::combobox .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.cipherCombo \
    -values {"aes" "anubis" "belt" "curupira" "kuznechik" "sm4" "serpent" "twofish" "camellia" "cast256" "mars" "noekeon" "crypton"} \
    -width 8 -state readonly
.nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.cipherCombo set "aes"

# Passphrase entry (box)
entry .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passEntry -width 15 -font {Consolas 9} -show "*"

# Passphrase label
label .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passLabel -text "Passphrase:" -font {Arial 9 bold} -bg $frame_color

# Pack in order: combo, entry, label (right to left)
pack .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.cipherCombo \
     .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passEntry \
     .nb.ecdh_tab.main.keys_frame.title_frame.pass_frame.passLabel \
     -side right -padx 3

frame .nb.ecdh_tab.main.keys_frame.content -bg $frame_color
pack .nb.ecdh_tab.main.keys_frame.content -fill x -padx 8 -pady 3

# Private Key
label .nb.ecdh_tab.main.keys_frame.content.privateKeyLabel -text "Private Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.privateKeyInput -width 40 -font {Consolas 9}
button .nb.ecdh_tab.main.keys_frame.content.openPrivateButton -text "Open" -command openPrivateKeyECDH \
    -bg "#3498db" -fg white -font {Arial 9 bold}

grid .nb.ecdh_tab.main.keys_frame.content.privateKeyLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.privateKeyInput -row 0 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.openPrivateButton -row 0 -column 2 -sticky w -padx 3 -pady 3

# Public Key
label .nb.ecdh_tab.main.keys_frame.content.publicKeyLabel -text "Public Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.publicKeyInput -width 50 -font {Consolas 9} \
    -bg "#f0f0f0" -state readonly -readonlybackground "#f0f0f0"

grid .nb.ecdh_tab.main.keys_frame.content.publicKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.publicKeyInput -row 1 -column 1 -sticky ew -padx 3 -pady 3

# Peer Key
label .nb.ecdh_tab.main.keys_frame.content.peerKeyLabel -text "Peer Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.keys_frame.content.peerKeyInput -width 40 -font {Consolas 9}
button .nb.ecdh_tab.main.keys_frame.content.openPeerKeyButton -text "Open" -command openPeerKey \
    -bg "#3498db" -fg white -font {Arial 9 bold}

grid .nb.ecdh_tab.main.keys_frame.content.peerKeyLabel -row 2 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.peerKeyInput -row 2 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.openPeerKeyButton -row 2 -column 2 -sticky w -padx 3 -pady 3

# Generate Keys button
button .nb.ecdh_tab.main.keys_frame.content.generateButton -text "Generate Keys" -command generateECDHKey \
    -bg "#27ae60" -fg white -font {Arial 10 bold} -pady 3
grid .nb.ecdh_tab.main.keys_frame.content.generateButton -row 3 -column 0 -columnspan 3 -sticky ew -padx 3 -pady 8

# Configure column weights
grid columnconfigure .nb.ecdh_tab.main.keys_frame.content 1 -weight 1

# Frame for KDF - MODIFIED TO INCLUDE ADDITIONAL INFO
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
    blake2s256
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

# NEW: Additional Info Input
label .nb.ecdh_tab.main.kdf_frame.content.infoLabel -text "Additional Info:" -font {Arial 9 bold} -bg $frame_color
entry .nb.ecdh_tab.main.kdf_frame.content.infoInput -width 25 -font {Consolas 9}

# First row: Hash and Salt
grid .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.hashAlgorithmCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.saltLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.saltInput -row 0 -column 3 -sticky ew -padx 3 -pady 3

# Second row: Additional Info
grid .nb.ecdh_tab.main.kdf_frame.content.infoLabel -row 1 -column 0 -sticky w -padx 3 -pady 3
grid .nb.ecdh_tab.main.kdf_frame.content.infoInput -row 1 -column 1 -columnspan 3 -sticky ew -padx 3 -pady 3

grid columnconfigure .nb.ecdh_tab.main.kdf_frame.content 3 -weight 1

# Frame for output
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

# Buttons for output
frame .nb.ecdh_tab.main.output_frame.buttons -bg $frame_color
pack .nb.ecdh_tab.main.output_frame.buttons -fill x -padx 8 -pady 3

button .nb.ecdh_tab.main.output_frame.buttons.deriveButton -text "Derive" -command deriveECDHKey \
    -bg "#9b59b6" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.deriveButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.hkdfButton -text "HKDF" -command executeECDHHKDF \
    -bg "#e67e22" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.hkdfButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.copyButton -text "Copy" -command {
    set full_text [.nb.ecdh_tab.main.output_frame.textframe.outputArea get 1.0 end]
    set lines [split [string trim $full_text] "\n"]
    
    # Get last non-empty line
    set last_line ""
    foreach line [lreverse $lines] {
        if {[string trim $line] ne ""} {
            set last_line [string trim $line]
            break
        }
    }
    
    clipboard clear
    clipboard append $last_line
} -bg "#27ae60" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.copyButton -side left -padx 3

button .nb.ecdh_tab.main.output_frame.buttons.clearButton -text "Clear" -command {
    .nb.ecdh_tab.main.output_frame.textframe.outputArea delete 1.0 end
} -bg "#e74c3c" -fg white -font {Arial 9 bold} -padx 12
pack .nb.ecdh_tab.main.output_frame.buttons.clearButton -side left -padx 3

# ========== MAC TEXT TAB ==========
frame .nb.mac_tab -bg $bg_color
.nb add .nb.mac_tab -text " Authentication "

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
    blake2s256
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

# Out Size ComboBox for VMAC (Text)
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

# Input data frame - SAME STRUCTURE AS OUTPUT
frame .nb.mac_tab.main.input_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.input_frame -fill x -padx 8 -pady 5

label .nb.mac_tab.main.input_frame.title -text "INPUT DATA" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.input_frame.title -anchor w -padx 8 -pady 3

frame .nb.mac_tab.main.input_frame.content -bg $frame_color
pack .nb.mac_tab.main.input_frame.content -fill x -padx 8 -pady 3

# Input type
label .nb.mac_tab.main.input_frame.content.inputTypeLabel -text "Input Type:" -font {Arial 9 bold} -bg $frame_color
set ::macInputTypeComboData {"Text" "File"}
ttk::combobox .nb.mac_tab.main.input_frame.content.inputTypeCombo -values $::macInputTypeComboData -state readonly -width 8
.nb.mac_tab.main.input_frame.content.inputTypeCombo set "Text"

# Bind combobox selection
bind .nb.mac_tab.main.input_frame.content.inputTypeCombo <<ComboboxSelected>> selectMACInputType

# File input
label .nb.mac_tab.main.input_frame.content.fileLabel -text "File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.mac_tab.main.input_frame.content.inputFile -width 50 -font {Consolas 9}
button .nb.mac_tab.main.input_frame.content.openFileButton -text "Open" -command {
    openFileDialog .nb.mac_tab.main.input_frame.content.inputFile
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 8

grid .nb.mac_tab.main.input_frame.content.inputTypeLabel -row 0 -column 0 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.input_frame.content.inputTypeCombo -row 0 -column 1 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.input_frame.content.fileLabel -row 0 -column 2 -sticky w -padx 3 -pady 3
grid .nb.mac_tab.main.input_frame.content.inputFile -row 0 -column 3 -sticky ew -padx 3 -pady 3
grid .nb.mac_tab.main.input_frame.content.openFileButton -row 0 -column 4 -sticky w -padx 3 -pady 3

# Frame for text area - SAME STRUCTURE AS OUTPUT
frame .nb.mac_tab.main.input_frame.content.textframe -bg $frame_color
grid .nb.mac_tab.main.input_frame.content.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 3 -pady 3

# Text area for text input - 4 LINES, SAME STRUCTURE AS OUTPUT
text .nb.mac_tab.main.input_frame.content.textframe.inputText -width 70 -height 6 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.mac_tab.main.input_frame.content.textframe.yscroll -orient vertical \
    -command {.nb.mac_tab.main.input_frame.content.textframe.inputText yview}
.nb.mac_tab.main.input_frame.content.textframe.inputText configure \
    -yscrollcommand {.nb.mac_tab.main.input_frame.content.textframe.yscroll set}

grid .nb.mac_tab.main.input_frame.content.textframe.inputText -row 0 -column 0 -sticky "nsew"
grid .nb.mac_tab.main.input_frame.content.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.mac_tab.main.input_frame.content.textframe 0 -weight 1
grid columnconfigure .nb.mac_tab.main.input_frame.content.textframe 0 -weight 1

grid columnconfigure .nb.mac_tab.main.input_frame.content 3 -weight 1
grid rowconfigure .nb.mac_tab.main.input_frame.content 1 -weight 1

# Frame for output
frame .nb.mac_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.mac_tab.main.output_frame -fill both -expand true -padx 8 -pady 5

label .nb.mac_tab.main.output_frame.title -text "MAC RESULT" -font {Arial 10 bold} -bg $frame_color
pack .nb.mac_tab.main.output_frame.title -anchor w -padx 8 -pady 3

# Create Result text area with scrollbar
frame .nb.mac_tab.main.output_frame.textframe -bg $frame_color
pack .nb.mac_tab.main.output_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.mac_tab.main.output_frame.textframe.resultBox -width 60 -height 3 -wrap word \
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

button .nb.mac_tab.main.action_frame.calculateButton -text "Calculate MAC" -command calculateMAC \
    -bg "#27ae60" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_tab.main.action_frame.calculateButton -side left -padx 5

button .nb.mac_tab.main.action_frame.copyButton -text "Copy Result" -command copyResult \
    -bg "#3498db" -fg white -font {Arial 10 bold} -padx 15 -pady 6
pack .nb.mac_tab.main.action_frame.copyButton -side left -padx 5

button .nb.mac_tab.main.action_frame.clearButton -text "Clear All" -command {
    .nb.mac_tab.main.keys_frame.content.keyEntry delete 0 end
    .nb.mac_tab.main.keys_frame.content.ivEntry delete 0 end
    .nb.mac_tab.main.input_frame.content.textframe.inputText delete 1.0 end
    .nb.mac_tab.main.input_frame.content.inputFile delete 0 end
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state normal
    .nb.mac_tab.main.output_frame.textframe.resultBox delete 1.0 end
    .nb.mac_tab.main.output_frame.textframe.resultBox configure -state disabled
} -bg "#e74c3c" -fg white -font {Arial 10 bold} -padx 15 -pady 6

# Execute Menu
menu .menubar -tearoff 0 -bg $accent_color -fg white -activebackground $button_hover
. configure -menu .menubar

# ========== DIGEST TAB ==========
frame .nb.digest_tab -bg $bg_color
.nb add .nb.digest_tab -text " Digest "

# Main frame for content (Digest)
frame .nb.digest_tab.main -bg $bg_color
pack .nb.digest_tab.main -fill both -expand yes -padx 8 -pady 5

# Algorithm settings frame
frame .nb.digest_tab.main.algo_frame -bg $frame_color -relief solid -bd 1
pack .nb.digest_tab.main.algo_frame -fill x -padx 8 -pady 5

label .nb.digest_tab.main.algo_frame.title -text "DIGEST SETTINGS" -font {Arial 10 bold} -bg $frame_color
pack .nb.digest_tab.main.algo_frame.title -anchor w -padx 8 -pady 3

frame .nb.digest_tab.main.algo_frame.content -bg $frame_color
pack .nb.digest_tab.main.algo_frame.content -fill x -padx 8 -pady 3

# Hash Algorithm ComboBox
set ::digestHashComboData {
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

label .nb.digest_tab.main.algo_frame.content.hashLabel -text "Hash Algorithm:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.digest_tab.main.algo_frame.content.hashCombo -values $::digestHashComboData -state readonly -width 20
.nb.digest_tab.main.algo_frame.content.hashCombo set "sha3-256"

# Recursive checkbox
checkbutton .nb.digest_tab.main.algo_frame.content.recursiveCheck -text "Recursive" \
    -variable ::recursiveFlag -bg $frame_color -font {Arial 9} -anchor w
set ::recursiveFlag 0  ;# Default value: unchecked

# Key entry frame (initially disabled)
frame .nb.digest_tab.main.algo_frame.content.keyFrame -bg $frame_color
label .nb.digest_tab.main.algo_frame.content.keyFrame.keyLabel -text "Key:" -font {Arial 9 bold} -bg $frame_color -state disabled
entry .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry -width 50 -font {Consolas 9} -state disabled -background "#f0f0f0"

pack .nb.digest_tab.main.algo_frame.content.keyFrame.keyLabel .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry -side left -padx 3

pack .nb.digest_tab.main.algo_frame.content.hashLabel .nb.digest_tab.main.algo_frame.content.hashCombo .nb.digest_tab.main.algo_frame.content.recursiveCheck .nb.digest_tab.main.algo_frame.content.keyFrame -side left -padx 5 -pady 3

# File selection frame
frame .nb.digest_tab.main.file_frame -bg $frame_color -relief solid -bd 1
pack .nb.digest_tab.main.file_frame -fill x -padx 8 -pady 5

label .nb.digest_tab.main.file_frame.title -text "FILE SELECTION" -font {Arial 10 bold} -bg $frame_color
pack .nb.digest_tab.main.file_frame.title -anchor w -padx 8 -pady 3

frame .nb.digest_tab.main.file_frame.content -bg $frame_color
pack .nb.digest_tab.main.file_frame.content -fill x -padx 8 -pady 3

# Directory path
label .nb.digest_tab.main.file_frame.content.dirLabel -text "Directory:" -font {Arial 9 bold} -bg $frame_color -width 10 -anchor e
entry .nb.digest_tab.main.file_frame.content.dirEntry -width 50 -font {Consolas 9}
# Set default value as "." (current directory)
.nb.digest_tab.main.file_frame.content.dirEntry insert 0 "."
button .nb.digest_tab.main.file_frame.content.dirButton -text "Open" -command {
    set dir_path [tk_chooseDirectory -title "Select Directory" -mustexist 1]
    if {$dir_path ne ""} {
        .nb.digest_tab.main.file_frame.content.dirEntry delete 0 end
        .nb.digest_tab.main.file_frame.content.dirEntry insert 0 $dir_path
    }
} -bg "#3498db" -fg white -font {Arial 9 bold} -padx 8

grid .nb.digest_tab.main.file_frame.content.dirLabel -row 0 -column 0 -sticky e -padx 3 -pady 3
grid .nb.digest_tab.main.file_frame.content.dirEntry -row 0 -column 1 -sticky ew -padx 3 -pady 3
grid .nb.digest_tab.main.file_frame.content.dirButton -row 0 -column 2 -sticky w -padx 3 -pady 3

# File pattern/wildcard
label .nb.digest_tab.main.file_frame.content.patternLabel -text "Pattern:" -font {Arial 9 bold} -bg $frame_color -width 10 -anchor e
entry .nb.digest_tab.main.file_frame.content.patternEntry -width 50 -font {Consolas 9}
.nb.digest_tab.main.file_frame.content.patternEntry insert 0 "*"

grid .nb.digest_tab.main.file_frame.content.patternLabel -row 1 -column 0 -sticky e -padx 3 -pady 3
grid .nb.digest_tab.main.file_frame.content.patternEntry -row 1 -column 1 -sticky ew -padx 3 -pady 3

# Add current directory button
button .nb.digest_tab.main.file_frame.content.currentDirButton -text "Current Dir" -command {
    .nb.digest_tab.main.file_frame.content.dirEntry delete 0 end
    .nb.digest_tab.main.file_frame.content.dirEntry insert 0 "."
} -bg "#95a5a6" -fg white -font {Arial 9 bold} -padx 8
grid .nb.digest_tab.main.file_frame.content.currentDirButton -row 1 -column 2 -sticky w -padx 3 -pady 3

grid columnconfigure .nb.digest_tab.main.file_frame.content 1 -weight 1

# Output frame
frame .nb.digest_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.digest_tab.main.output_frame -fill both -expand true -padx 8 -pady 5

label .nb.digest_tab.main.output_frame.title -text "DIGEST" -font {Arial 10 bold} -bg $frame_color
pack .nb.digest_tab.main.output_frame.title -anchor w -padx 8 -pady 3

# Create output text area with ONLY vertical scrollbar
frame .nb.digest_tab.main.output_frame.textframe -bg $frame_color
pack .nb.digest_tab.main.output_frame.textframe -fill both -expand true -padx 8 -pady 3

text .nb.digest_tab.main.output_frame.textframe.outputArea -width 70 -height 15 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1

# Configure tags for formatting (must be done AFTER creating Text widget)
.nb.digest_tab.main.output_frame.textframe.outputArea tag configure bold -font {Consolas 9 bold}
.nb.digest_tab.main.output_frame.textframe.outputArea tag configure error -foreground red
.nb.digest_tab.main.output_frame.textframe.outputArea tag configure success -foreground "#27ae60"
.nb.digest_tab.main.output_frame.textframe.outputArea tag configure warning -foreground "#f39c12"

scrollbar .nb.digest_tab.main.output_frame.textframe.yscroll -orient vertical \
    -command {.nb.digest_tab.main.output_frame.textframe.outputArea yview}
.nb.digest_tab.main.output_frame.textframe.outputArea configure \
    -yscrollcommand {.nb.digest_tab.main.output_frame.textframe.yscroll set}

grid .nb.digest_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.digest_tab.main.output_frame.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.digest_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.digest_tab.main.output_frame.textframe 0 -weight 1

# Action buttons frame
frame .nb.digest_tab.main.action_frame -bg $bg_color
pack .nb.digest_tab.main.action_frame -fill x -padx 8 -pady 8

# Open button (auxiliary button - blue) - LEFT
button .nb.digest_tab.main.action_frame.openButton -text "Open" \
    -command openHashFile -bg "#3498db" -fg white -font {Arial 9 bold} \
    -padx 12 -pady 4
pack .nb.digest_tab.main.action_frame.openButton -side left -padx 3

# Save button (auxiliary button - orange) - LEFT
button .nb.digest_tab.main.action_frame.saveButton -text "Save" \
    -command saveDigests -bg "#f39c12" -fg white -font {Arial 9 bold} \
    -padx 12 -pady 4
pack .nb.digest_tab.main.action_frame.saveButton -side left -padx 3

# Copy button (auxiliary button - green) - LEFT
button .nb.digest_tab.main.action_frame.copyButton -text "Copy" \
    -command {
        set text [.nb.digest_tab.main.output_frame.textframe.outputArea get 1.0 end-1c]
        clipboard clear
        clipboard append $text
    } -bg "#27ae60" -fg white -font {Arial 9 bold} \
    -padx 12 -pady 4
pack .nb.digest_tab.main.action_frame.copyButton -side left -padx 3

# Paste button (auxiliary button - dark orange) - LEFT
button .nb.digest_tab.main.action_frame.pasteButton -text "Paste" \
    -command {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end [clipboard get]
    } -bg "#e67e22" -fg white -font {Arial 9 bold} \
    -padx 12 -pady 4
pack .nb.digest_tab.main.action_frame.pasteButton -side left -padx 3

# Clear button (auxiliary button - red) - LEFT
button .nb.digest_tab.main.action_frame.clearButton -text "Clear" \
    -command {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
    } -bg "#e74c3c" -fg white -font {Arial 9 bold} \
    -padx 12 -pady 4
pack .nb.digest_tab.main.action_frame.clearButton -side left -padx 3

# Frame for main buttons (right)
frame .nb.digest_tab.main.action_frame.main_buttons -bg $bg_color
pack .nb.digest_tab.main.action_frame.main_buttons -side right

# Digest button (main button - green) - LEFT inside main frame
button .nb.digest_tab.main.action_frame.main_buttons.digestButton -text "Compute" \
    -command calculateDigests -bg "#27ae60" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.digest_tab.main.action_frame.main_buttons.digestButton -side left -padx 5

# Check button (main button - blue) - RIGHT of Calculate
button .nb.digest_tab.main.action_frame.main_buttons.checkButton -text "Check" \
    -command verifyDigests -bg "#3498db" -fg white -font {Arial 10 bold} \
    -padx 15 -pady 6 -relief raised -bd 2
pack .nb.digest_tab.main.action_frame.main_buttons.checkButton -side left -padx 5

# ===== DIGEST FUNCTIONS =====

# Function to update UI based on selected algorithm
proc updateDigestUI {} {
    set algorithm [.nb.digest_tab.main.algo_frame.content.hashCombo get]
    
    # List of algorithms that support key (keyed hash functions)
    set keyed_algorithms {
        blake2b256 blake2b512
        blake2s128 blake2s256
        siphash64 siphash
        skein256 skein512
    }
    
    # Check if algorithm supports key
    if {$algorithm in $keyed_algorithms} {
        # Enable key field
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyLabel configure -state normal
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry configure -state normal
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry configure -background "white"
        switch -- $algorithm {
        "blake2s128" {
            .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry delete 0 end
            .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry insert 0 "0000000000000000"
        }
    }
    } else {
        # Disable key field
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyLabel configure -state disabled
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry configure -state disabled
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry configure -background "#f0f0f0"
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry configure -fg "black"
        .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry delete 0 end
        
        # Remove binds
        bind .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry <FocusIn> {}
        bind .nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry <FocusOut> {}
    }
}

# Function to open hash file
proc openHashFile {} {
    # Supported file types
    set filetypes {
        {"Text files" {.txt}}
        {"Hash files" {.hash .md5 .sha1 .sha256 .sha512}}
        {"All files" *}
    }
    
    # Open file selection dialog
    set filepath [tk_getOpenFile \
        -title "Open Hash File" \
        -filetypes $filetypes]
    
    if {$filepath ne ""} {
        if {[catch {
            # Read file content
            set fd [open $filepath r]
            set content [read $fd]
            close $fd
            
            # Update output area
            .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end $content
            
            # Add informational header
            set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "\n\n# File loaded: [file tail $filepath]\n"
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Loaded on: $timestamp\n"
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Full path: $filepath\n"
            
        } errorMsg]} {
            tk_messageBox -icon error -title "Error" \
                -message "Failed to open file:\n$errorMsg"
        }
    }
}

# Function to save digests to file
proc saveDigests {} {
    set text [.nb.digest_tab.main.output_frame.textframe.outputArea get 1.0 end-1c]
    
    if {$text eq ""} {
        tk_messageBox -icon warning -title "No Data" -message "No data to save!" \
            -type ok
        return
    }
    
    # Suggest filename based on algorithm and date
    set hash_algorithm [.nb.digest_tab.main.algo_frame.content.hashCombo get]
    set timestamp [clock format [clock seconds] -format "%Y%m%d_%H%M%S"]
    set default_filename "digests_${hash_algorithm}_${timestamp}.txt"
    
    # Ask where to save
    set filepath [tk_getSaveFile \
        -title "Save Digests As" \
        -initialfile $default_filename \
        -defaultextension ".txt" \
        -filetypes {
            {"Text files" {.txt}}
            {"All files" *}
        }]
    
    if {$filepath ne ""} {
        if {[catch {
            set fd [open $filepath w]
            puts $fd $text
            close $fd
            tk_messageBox -icon info -title "Saved" \
                -message "Digests saved to:\n$filepath"
        } errorMsg]} {
            tk_messageBox -icon error -title "Error" \
                -message "Failed to save file:\n$errorMsg"
        }
    }
}

# Function to calculate file digests
proc calculateDigests {} {
    set hash_algorithm [.nb.digest_tab.main.algo_frame.content.hashCombo get]
    set directory [.nb.digest_tab.main.file_frame.content.dirEntry get]
    set pattern [.nb.digest_tab.main.file_frame.content.patternEntry get]
    set key [.nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry get]
    
    # Validate directory - "." will always be valid
    if {$directory eq ""} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a directory!"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error 1.0 "1.end"
        return
    }
    
    # Don't need to check if "." exists - it always exists
    # But if it's another path, check
    if {$directory ne "." && (![file exists $directory] || ![file isdirectory $directory])} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: Directory not found: $directory"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error 1.0 "1.end"
        return
    }
    
    # Clear output area
    .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
    
    # Add header with information
    set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Digests generated on: $timestamp\n"
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Algorithm: $hash_algorithm\n"
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Directory: $directory\n"
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Pattern: $pattern\n"
    if {$::recursiveFlag} {
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Recursive: Yes\n"
    }
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "#\n"
    
    # Change to selected directory
    set original_dir [pwd]
    if {$directory ne "."} {
        cd $directory
    }
    
    # Build base command
    set cmd [list edgetk -digest -md $hash_algorithm -key $key]
    
    # Add -recursive flag if checkbox is checked
    if {$::recursiveFlag} {
        lappend cmd -recursive
    }
    
    # For non-recursive mode: get and sort files before
    if {!$::recursiveFlag} {
        # Get file list
        set files [glob -nocomplain -- $pattern]
        
        # If no files, show message
        if {[llength $files] == 0} {
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "No files found matching pattern: $pattern\n"
            .nb.digest_tab.main.output_frame.textframe.outputArea tag add error "end-1l linestart" "end-1l lineend"
            
            # Return to original directory
            if {$directory ne "."} {
                cd $original_dir
            }
            return
        }
        
        # Sort files alphabetically (ASCII - uppercase first)
        set files [lsort -ascii $files]
        
        # Add sorted files to command
        lappend cmd {*}$files
    } else {
        # For recursive mode: add pattern directly
        lappend cmd {*}[glob -nocomplain -- $pattern]
    }
    
    # Execute edgetk -digest command
    if {[catch {
        set result [exec {*}$cmd 2>@1]
        
        # Sort lines alphabetically by filename
        set lines [split $result "\n"]
        set sorted_lines {}
        
        foreach line $lines {
            # Lines that start with hash (hex + space + asterisk + filename)
            if {[regexp {^([0-9a-fA-F]+)\s+\*(.+)$} $line -> hash filename]} {
                lappend sorted_lines [list $filename $line]
            } elseif {[string trim $line] ne ""} {
                # Lines that aren't hashes but aren't empty - keep in original order
                lappend sorted_lines [list "" $line]
            }
        }
        
        # Sort by filename (first element of each list)
        # Use ASCII order (uppercase first)
        set sorted_lines [lsort -index 0 -ascii $sorted_lines]
        
        # Rebuild sorted result
        set sorted_result ""
        foreach item $sorted_lines {
            append sorted_result [lindex $item 1]\n
        }
        
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end $sorted_result
        
    } errorMsg]} {
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: $errorMsg"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error "end-1l linestart" "end-1l lineend"
    }
    
    # Return to original directory
    if {$directory ne "."} {
        cd $original_dir
    }
}

# Function to verify file digests
proc verifyDigests {} {
    # First, try to detect algorithm from header
    set all_content [.nb.digest_tab.main.output_frame.textframe.outputArea get 1.0 end-1c]
    set detected_algorithm ""
    
    # Look for line starting with "# Algorithm:"
    foreach line [split $all_content "\n"] {
        if {[regexp {^#\s*Algorithm:\s*(.+)$} $line -> algo]} {
            set detected_algorithm [string trim $algo]
            break
        }
    }
    
    # If found algorithm in header, update combobox
    if {$detected_algorithm ne ""} {
        # Check if algorithm is in value list
        if {$detected_algorithm in $::digestHashComboData} {
            .nb.digest_tab.main.algo_frame.content.hashCombo set $detected_algorithm
            # Update UI to reflect new algorithm
            updateDigestUI
        } else {
            # If not in list, keep current but show warning
            set hash_algorithm [.nb.digest_tab.main.algo_frame.content.hashCombo get]
            .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Warning: Algorithm '$detected_algorithm' not found in list.\n"
            .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Using current algorithm: $hash_algorithm\n\n"
            .nb.digest_tab.main.output_frame.textframe.outputArea tag add warning 1.0 "2.end"
        }
    }
    
    # Now continue with normal verification
    set hash_algorithm [.nb.digest_tab.main.algo_frame.content.hashCombo get]
    set directory [.nb.digest_tab.main.file_frame.content.dirEntry get]
    set key [.nb.digest_tab.main.algo_frame.content.keyFrame.keyEntry get]
    
    # Validate directory
    if {$directory eq ""} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a directory!"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error 1.0 "1.end"
        return
    }
    
    # Don't need to check if "." exists - it always exists
    # But if it's another path, check
    if {$directory ne "." && (![file exists $directory] || ![file isdirectory $directory])} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: Directory not found: $directory"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error 1.0 "1.end"
        return
    }
    
    # Get all content and filter only lines that are hashes
    set hash_lines ""
    
    foreach line [split $all_content "\n"] {
        # Keep only lines that look like hashes (hex + space + asterisk + filename)
        if {[regexp {^[0-9a-fA-F]+\s+\*} $line]} {
            append hash_lines "$line\n"
        }
    }
    
    if {[string trim $hash_lines] eq ""} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Error: No valid hash data found!\nPlease calculate digests first."
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error 1.0 "2.end"
        return
    }
    
    # Clear output area (if not already cleared by warning)
    if {$detected_algorithm eq "" || $detected_algorithm in $::digestHashComboData} {
        .nb.digest_tab.main.output_frame.textframe.outputArea delete 1.0 end
    }
    
    # Add header
    set timestamp [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Verification started on: $timestamp\n"
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Algorithm: $hash_algorithm\n"
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Directory: $directory\n"
    if {$::recursiveFlag} {
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "# Recursive: Yes\n"
    }
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "#\n"
    
    # Change to selected directory
    set original_dir [pwd]
    if {$directory ne "."} {
        cd $directory
    }
    
    # Variable to capture exit code
    set exit_code 0
    set result_text ""
    
    # Build base command
    set cmd [list edgetk -check -md $hash_algorithm -key $key]
    
    # Add -recursive flag if checkbox is checked
    if {$::recursiveFlag} {
        lappend cmd -recursive
    }
    
    # Execute edgetk -check and capture exit code
    if {[catch {
        # Use exec with redirect to capture stderr and exit code
        set result [exec {*}$cmd << $hash_lines 2>@1]
        set result_text $result
    } errorMsg error_options]} {
        # If error occurred, capture exit code from options
        set exit_code [dict get $error_options -errorcode]
        
        # Extract exit code number (usually in format CHILDSTATUS pid code)
        if {[lindex $exit_code 0] eq "CHILDSTATUS"} {
            set exit_code [lindex $exit_code 2]
        } else {
            set exit_code 1  # Generic error code
        }
        
        set result_text $errorMsg
    }
    
    # Process result to add formatting
    set output_start [.nb.digest_tab.main.output_frame.textframe.outputArea index "end-1c linestart"]
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end $result_text
    
    # Look for specific words and apply tags
    set text_content [.nb.digest_tab.main.output_frame.textframe.outputArea get $output_start "end-1c"]
    
    # Patterns to look for (with regular expressions)
    set patterns {
        {FAILED}
        {Not found!}
    }
    
    # For each pattern, apply bold tag
    foreach pattern $patterns {
        set idx [.nb.digest_tab.main.output_frame.textframe.outputArea search -regexp -- $pattern $output_start "end-1c"]
        
        while {$idx ne ""} {
            # Find end of word
            set end_idx [.nb.digest_tab.main.output_frame.textframe.outputArea index "$idx + [string length [.nb.digest_tab.main.output_frame.textframe.outputArea get $idx "$idx lineend"]]c"]
            
            # Apply bold tag
            .nb.digest_tab.main.output_frame.textframe.outputArea tag add bold $idx $end_idx
            
            # If it's "FAILED" or "Not found!", also apply error tag (red)
            if {[regexp {(FAILED|Not found!)} [.nb.digest_tab.main.output_frame.textframe.outputArea get $idx $end_idx]]} {
                .nb.digest_tab.main.output_frame.textframe.outputArea tag add error $idx $end_idx
            }
            
            # Continue searching from end of this occurrence
            set idx [.nb.digest_tab.main.output_frame.textframe.outputArea search -regexp -- $pattern $end_idx "end-1c"]
        }
    }
    
    # Also look for "OK" and apply success tag (green)
    set idx [.nb.digest_tab.main.output_frame.textframe.outputArea search -regexp -- {OK} $output_start "end-1c"]
    while {$idx ne ""} {
        set end_idx [.nb.digest_tab.main.output_frame.textframe.outputArea index "$idx + 2c"] ;# "OK" has 2 characters
        
        # Apply success tag (green)
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add success $idx $end_idx
        
        # Continue searching from end of this occurrence
        set idx [.nb.digest_tab.main.output_frame.textframe.outputArea search -regexp -- {OK} $end_idx "end-1c"]
    }
    
    # Return to original directory
    if {$directory ne "."} {
        cd $original_dir
    }
    
    # Show result based on exit code
    .nb.digest_tab.main.output_frame.textframe.outputArea insert end "\n"
    
    if {$exit_code == 0} {
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "All checks passed successfully! (exit code: 0)\n"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add success "end-2l linestart" "end-1l lineend"
    } else {
        .nb.digest_tab.main.output_frame.textframe.outputArea insert end "Some checks failed! (exit code: $exit_code)\n"
        .nb.digest_tab.main.output_frame.textframe.outputArea tag add error "end-2l linestart" "end-1l lineend"
    }
}

# ===== END OF DIGEST FUNCTIONS =====

.menubar add command -label "About" -command showAbout -background $accent_color

# Add to menu
.menubar add command -label "Debug" -command {
    toplevel .debug_win
    wm title .debug_win "Debug Information"
    wm geometry .debug_win 600x450
    
    # Set main window background
    .debug_win configure -bg $bg_color
    
    # Main frame with correct background
    frame .debug_win.main -bg $bg_color
    pack .debug_win.main -fill both -expand true -padx 10 -pady 10
    
    # Frame for text area with scrollbar
    frame .debug_win.main.textframe -bg $bg_color
    pack .debug_win.main.textframe -fill both -expand true
    
    # Text area with white background for contrast
    text .debug_win.main.textframe.text -width 80 -height 25 -wrap word \
        -font {Consolas 9} -bg white -relief solid -bd 1
    scrollbar .debug_win.main.textframe.scroll -command {.debug_win.main.textframe.text yview}
    .debug_win.main.textframe.text configure -yscrollcommand {.debug_win.main.textframe.scroll set}
    
    # Use grid for better layout
    grid .debug_win.main.textframe.text -row 0 -column 0 -sticky "nsew"
    grid .debug_win.main.textframe.scroll -row 0 -column 1 -sticky "ns"
    grid rowconfigure .debug_win.main.textframe 0 -weight 1
    grid columnconfigure .debug_win.main.textframe 0 -weight 1
    
    # Capture all debug output
    .debug_win.main.textframe.text insert end "=== DEBUG INFO ===\n\n"
    .debug_win.main.textframe.text insert end "Platform: $::tcl_platform(platform)\n"
    .debug_win.main.textframe.text insert end "OS: $::tcl_platform(os)\n"
    if {[info exists ::tcl_platform(osVersion)]} {
        .debug_win.main.textframe.text insert end "OS Version: $::tcl_platform(osVersion)\n"
    }
    
    # Fix: mostrar diretório atual de forma segura
    set current_dir [pwd]
    .debug_win.main.textframe.text insert end "Current dir: $current_dir\n"
    
    .debug_win.main.textframe.text insert end "Tcl Version: [info patchlevel]\n"
    
    # Get Tk version in compatible way
    if {[catch {package require Tk} tk_version]} {
        .debug_win.main.textframe.text insert end "Tk Version: Not available\n"
    } else {
        if {[catch {tk version} tk_ver]} {
            .debug_win.main.textframe.text insert end "Tk Version: $tk_version (loaded)\n"
        } else {
            .debug_win.main.textframe.text insert end "Tk Version: $tk_ver\n"
        }
    }
    .debug_win.main.textframe.text insert end "\n"
    
    # Test edgetk
    .debug_win.main.textframe.text insert end "=== EDGETK INFO ===\n"
    
    # Verificar se estamos no Windows
    if {$::tcl_platform(platform) eq "windows"} {
        # No Windows, verificar edgetk de forma diferente
        set found 0
        set edgetk_path ""
        
        # Verificar no PATH do Windows
        if {[info exists ::env(PATH)]} {
            set path_dirs [split $::env(PATH) ";"]
            foreach dir $path_dirs {
                set edgetk_exe [file join $dir "edgetk.exe"]
                if {[file exists $edgetk_exe]} {
                    set edgetk_path $edgetk_exe
                    set found 1
                    break
                }
            }
        }
        
        # Se não encontrou no PATH, tentar encontrar de outras formas
        if {!$found} {
            # Tentar 'where' no Windows
            if {[catch {exec where edgetk} result]} {
                # Tentar 'where edgetk.exe'
                catch {exec where edgetk.exe} result2
                if {[info exists result2] && $result2 ne ""} {
                    set edgetk_path $result2
                    set found 1
                }
            } else {
                set edgetk_path $result
                set found 1
            }
        }
        
        if {$found} {
            .debug_win.main.textframe.text insert end "edgetk found at: $edgetk_path\n\n"
            
            # Tentar obter a versão
            .debug_win.main.textframe.text insert end "Trying to get edgetk version...\n"
            set version_found 0
            
            # Tentar diferentes opções de versão
            foreach version_flag {--version -version -v -V version} {
                # CORREÇÃO AQUI: no Windows, usar 2>NUL em vez de 2>&1
                if {[catch {exec cmd /c "\"$edgetk_path\" $version_flag" 2>NUL} version_result]} {
                    continue
                } else {
                    if {[string trim $version_result] ne ""} {
                        .debug_win.main.textframe.text insert end "Version (using '$version_flag'):\n$version_result\n"
                        set version_found 1
                        break
                    }
                }
            }
            
            if {!$version_found} {
                .debug_win.main.textframe.text insert end "Could not determine edgetk version\n"
            }
        } else {
            .debug_win.main.textframe.text insert end "edgetk not found\n"
        }
    } else {
        # Para Linux/Mac
        if {[catch {exec which edgetk} result]} {
            .debug_win.main.textframe.text insert end "edgetk not found in PATH\n"
        } else {
            .debug_win.main.textframe.text insert end "edgetk found at: $result\n\n"
            
            # Try to get edgetk version
            .debug_win.main.textframe.text insert end "Trying to get edgetk version...\n"
            if {[catch {exec edgetk -version} version_result]} {
                # If -version fails, try --version or other options
                .debug_win.main.textframe.text insert end "Error with 'edgetk -version': $version_result\n"
                
                # Try other common version options
                set version_found 0
                foreach version_flag {--version -v -V version} {
                    if {[catch {exec edgetk $version_flag 2>&1} alt_result]} {
                        continue
                    } else {
                        .debug_win.main.textframe.text insert end "Version (using '$version_flag'):\n$alt_result\n"
                        set version_found 1
                        break
                    }
                }
                if {!$version_found} {
                    .debug_win.main.textframe.text insert end "Could not determine edgetk version\n"
                }
            } else {
                .debug_win.main.textframe.text insert end "Version:\n$version_result\n"
            }
        }
    }
    
    # System information
    .debug_win.main.textframe.text insert end "\n=== SYSTEM INFO ===\n"
    
    if {$::tcl_platform(platform) eq "windows"} {
        # Informações do sistema para Windows
        
        # CPU
        if {![catch {exec wmic cpu get name /value 2>NUL} cpu_info]} {
            # Processar saída do wmic
            foreach line [split $cpu_info \n] {
                if {[string match "Name=*" $line]} {
                    set cpu_name [string range $line 5 end]
                    .debug_win.main.textframe.text insert end "CPU: $cpu_name\n"
                    break
                }
            }
        }
        
        # Número de cores
        if {![catch {exec wmic cpu get NumberOfCores /value 2>NUL} cpu_cores_info]} {
            foreach line [split $cpu_cores_info \n] {
                if {[string match "NumberOfCores=*" $line]} {
                    set cores [string range $line 14 end]
                    .debug_win.main.textframe.text insert end "CPU Cores: $cores\n"
                    break
                }
            }
        }
        
        # Memória - CORREÇÃO AQUI
        if {![catch {exec wmic ComputerSystem get TotalPhysicalMemory /value 2>NUL} mem_info]} {
            foreach line [split $mem_info \n] {
                if {[string match "TotalPhysicalMemory=*" $line]} {
                    set mem_bytes_str [string range $line 22 end]
                    # Remover caracteres não numéricos (espaços, CR, LF, etc.)
                    set mem_bytes [string trim $mem_bytes_str]
                    # Verificar se é um número válido
                    if {[string is integer $mem_bytes]} {
                        # Converter bytes para GB
                        set mem_gb [expr {$mem_bytes / 1024.0 / 1024.0 / 1024.0}]
                        .debug_win.main.textframe.text insert end "Memory Total: [format "%.2f" $mem_gb] GB\n"
                    } else {
                        .debug_win.main.textframe.text insert end "Memory Total: Could not parse memory value\n"
                    }
                    break
                }
            }
        } else {
            .debug_win.main.textframe.text insert end "Memory Total: Could not retrieve memory information\n"
        }
        
    } else {
        # Informações do sistema para Linux/Mac
        if {[file exists "/proc/cpuinfo"]} {
            if {![catch {exec grep -m 1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2} cpu_info]} {
                .debug_win.main.textframe.text insert end "CPU: [string trim $cpu_info]\n"
            }
            if {![catch {exec grep -c ^processor /proc/cpuinfo 2>/dev/null} cpu_cores]} {
                .debug_win.main.textframe.text insert end "CPU Cores: [string trim $cpu_cores]\n"
            }
        }
        
        if {![catch {exec free -h 2>/dev/null | grep Mem: | awk '{print $2}'} mem_total]} {
            .debug_win.main.textframe.text insert end "Memory Total: [string trim $mem_total]\n"
        }
    }
    
    # Environment information
    .debug_win.main.textframe.text insert end "\n=== ENVIRONMENT ===\n"
    if {[info exists ::env(PATH)]} {
        if {$::tcl_platform(platform) eq "windows"} {
            # No Windows, mostrar PATH formatado
            set path_dirs [split $::env(PATH) ";"]
            .debug_win.main.textframe.text insert end "PATH (first 10 entries):\n"
            set count 0
            foreach dir $path_dirs {
                if {$count < 10 && [string trim $dir] ne ""} {
                    .debug_win.main.textframe.text insert end "  $dir\n"
                    incr count
                }
            }
            if {[llength $path_dirs] > 10} {
                .debug_win.main.textframe.text insert end "  ... and [expr {[llength $path_dirs] - 10}] more\n"
            }
        } else {
            # No Linux/Mac
            .debug_win.main.textframe.text insert end "PATH: $::env(PATH)\n"
        }
    } else {
        .debug_win.main.textframe.text insert end "PATH: Not set\n"
    }
    
    # Frame for buttons with correct background
    frame .debug_win.main.buttons -bg $bg_color
    pack .debug_win.main.buttons -fill x -pady 10
    
    button .debug_win.main.buttons.copy -text "Copy Debug Info" -command {
        set debug_text [.debug_win.main.textframe.text get 1.0 end]
        clipboard clear
        clipboard append $debug_text
    } -bg "#3498db" -fg white -font {Arial 9 bold} -padx 15 -pady 5
    pack .debug_win.main.buttons.copy -side left -padx 5
    
    button .debug_win.main.buttons.close -text "Close" -command {destroy .debug_win} \
        -bg "#e74c3c" -fg white -font {Arial 9 bold} -padx 15 -pady 5
    pack .debug_win.main.buttons.close -side right -padx 5
    
    # Scroll to top
    .debug_win.main.textframe.text see 1.0
    
    # Make text area read-only after inserting content
    .debug_win.main.textframe.text configure -state disabled
}

# Footer
frame .footer -bg $accent_color -height 25
pack .footer -fill x
label .footer.text -text "ALBANESE Research Lab \u00a9 2025 | Secure Cryptographic Operations" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .footer.text -pady 3

# Configure resizing
grid columnconfigure .nb.text_tab.main.keys_frame 1 -weight 1
grid columnconfigure .nb.file_tab.main.keys_frame 1 -weight 1
grid columnconfigure .nb.mac_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.signatures_tab.main.keys_frame.content 1 -weight 1

# Bind the combobox to update UI when algorithm changes
bind .nb.mac_tab.main.algo_frame.content.algorithmCombo <<ComboboxSelected>> {updateAlgorithmUI}
bind .nb.signatures_tab.main.algo_frame.content.algorithmCombo <<ComboboxSelected>> {updateSignatureUI}
bind .nb.ecdh_tab.main.algo_frame.content.algorithmCombo <<ComboboxSelected>> {updateECDHUI}

# For Text tab (look for this line):
.nb.text_tab.main.algo_frame.row2.kdfAlgorithmCheckbox configure -command updateKDFText

# For Files tab (look for this line):
.nb.file_tab.main.algo_frame.row2.kdfAlgorithmCheckbox configure -command updateKDFFiles

bind .nb.text_tab.main.algo_frame.row1.algorithmCombo <<ComboboxSelected>> {updateTextUI}
bind .nb.text_tab.main.algo_frame.row1.modeCombo <<ComboboxSelected>> {updateTextUI}
bind .nb.file_tab.main.algo_frame.row1.algorithmCombo <<ComboboxSelected>> {updateFilesUI}
bind .nb.file_tab.main.algo_frame.row1.modeCombo <<ComboboxSelected>> {updateFilesUI}
bind .nb.digest_tab.main.algo_frame.content.hashCombo <<ComboboxSelected>> {updateDigestUI}

# Initialize key displays
updateKeyEntryDisplay
updateKeyEntryDisplayFiles
updateAlgorithmUI
updateSignatureUI
updateECDHUI
updateTextUI
updateFilesUI
updateDigestUI

selectMACInputType

# Start the event loop
tkwait visibility .
