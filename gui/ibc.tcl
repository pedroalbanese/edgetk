#!/usr/bin/wish
###############################################################################
#   EDGE Crypto Suite - IBE/IBS Module                                        #
#   Identity-Based Encryption and Signature Toolkit                           #
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

# Style settings - Cores Neutras (mesmo tema do código original)
set bg_color "#f5f5f5"
set accent_color "#4a4a4a"
set button_color "#6c757d"
set button_hover "#5a6268"
set frame_color "#ecf0f1"
set text_bg "#ffffff"

# Global variables
set signature_data ""

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

# Function to generate HID values list (1-255)
proc generateHIDValues {} {
    set hid_values {}
    for {set i 1} {$i <= 255} {incr i} {
        lappend hid_values $i
    }
    return $hid_values
}

# About window for EDGE Crypto Suite IBE
proc showAboutIBE {} {
    toplevel .about_window
    wm title .about_window "About EDGE IBE/IBS Module"
    wm geometry .about_window 460x500
    wm resizable .about_window 0 0

    set x [expr {[winfo screenwidth .] / 2 - 230}]
    set y [expr {[winfo screenheight .] / 2 - 180}]
    wm geometry .about_window +$x+$y

    frame .about_window.main -bg white -relief solid -bd 1
    pack .about_window.main -fill both -expand true -padx 12 -pady 12

    # Logo
    if {$::tcl_platform(os) ne "Windows NT"} {
        label .about_window.main.logo -text "🔐" -font {"Segoe UI Emoji" 28} -bg white
        pack .about_window.main.logo -pady 10
    } else {
        label .about_window.main.logo -text "\uF023" -font {"Segoe UI Emoji" 40} -bg white
        pack .about_window.main.logo -pady 6
    }

    # Title
    label .about_window.main.title -text "EDGE IBE/IBS Module" \
        -font {Arial 15 bold} -bg white
    pack .about_window.main.title -pady 4

    # Version
    label .about_window.main.version -text "Version 1.0" \
        -font {Arial 10} -bg white
    pack .about_window.main.version -pady 2

    # Description
    label .about_window.main.desc -text \
"Identity-Based Encryption and Signatures Module

This module provides Identity-Based Cryptography (IBC) capabilities
using BLS12-381 curves. It allows for master key generation, user
key derivation based on identity, encryption/decryption, and
digital signatures without requiring certificates.

Features:
- Master key pair generation
- User private key derivation based on ID/HID
- Identity-Based Encryption (IBE) - Boneh-Franklin
- Identity-Based Signatures (IBS) - Hess
- Support for Threshold IBE" \
        -font {Arial 9} -bg white -justify center -wraplength 480
    pack .about_window.main.desc -pady 10

    # Author / Lab
    label .about_window.main.lab -text "ALBANESE Research Lab" \
        -font {Arial 9 bold} -bg white
    pack .about_window.main.lab -pady 10

    # OK Button
    button .about_window.main.ok -text "OK" -command {destroy .about_window} \
        -bg "#4a4a4a" -fg white -font {Arial 10 bold} -relief flat \
        -padx 22 -pady 6
    pack .about_window.main.ok -pady 14

    bind .about_window <Key-Escape> {destroy .about_window}
    bind .about_window <Return> {destroy .about_window}
    focus .about_window
}

# ===== KEY GENERATION TAB FUNCTIONS =====

# Function to generate master key pair
proc generateMasterKey {} {
    set master_pass [.nb.keys_tab.main.keys_frame.title_frame.right_frame.passEntry get]
    set master_cipher [.nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherCombo get]
    
    # If passphrase is empty, use "nil"
    if {$master_pass eq ""} {
        set master_pass "nil"
    }
    
    # Get current directory
    set current_dir [pwd]
    
    # Generate unique filenames
    set master_name "Master"
    set master_public_name "MasterPublic"
    
    # Default paths
    set master_path [file join $current_dir "${master_name}.pem"]
    set master_public_path [file join $current_dir "${master_public_name}.pem"]
    
    # Get current values from input fields (if any)
    set current_master [.nb.keys_tab.main.keys_frame.content.masterKeyInput get]
    set current_master_public [.nb.keys_tab.main.keys_frame.content.masterPublicInput get]
    
    # Check if files already exist
    set master_exists [file exists $master_path]
    set master_public_exists [file exists $master_public_path]
    
    if {$master_exists || $master_public_exists} {
        # Show dialog window
        set choice [tk_messageBox \
            -title "Files Already Exist" \
            -message "Files already exist:\n\nMaster: [file tail $master_path]\nMaster Public: [file tail $master_public_path]\n\nWhat do you want to do?" \
            -type yesnocancel \
            -icon warning \
            -detail "Yes: Overwrite existing files\nNo: Generate with NEW numeric suffix (rename)\nCancel: Abort operation" \
            -default cancel]
        
        if {$choice eq "cancel"} {
            .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Key generation cancelled."
            return
        } elseif {$choice eq "no"} {
            # Find next available name
            set counter 1
            set new_master_path [file join $current_dir "${master_name}_${counter}.pem"]
            set new_master_public_path [file join $current_dir "${master_public_name}_${counter}.pem"]
            
            while {[file exists $new_master_path] || [file exists $new_master_public_path]} {
                incr counter
                set new_master_path [file join $current_dir "${master_name}_${counter}.pem"]
                set new_master_public_path [file join $current_dir "${master_public_name}_${counter}.pem"]
            }
            
            set master_path $new_master_path
            set master_public_path $new_master_public_path
        }
    } else {
        # Use custom paths if provided
        if {$current_master ne ""} {
            set master_path $current_master
        }
        if {$current_master_public ne ""} {
            set master_public_path $current_master_public
        }
    }
    
    # Update entry fields
    .nb.keys_tab.main.keys_frame.content.masterKeyInput delete 0 end
    .nb.keys_tab.main.keys_frame.content.masterKeyInput insert 0 $master_path
    
    .nb.keys_tab.main.keys_frame.content.masterPublicInput delete 0 end
    .nb.keys_tab.main.keys_frame.content.masterPublicInput insert 0 $master_public_path
    
    # Execute key generation command (boneh-franklin for IBE)
    if {[catch {
        exec edgetk -pkey setup -algorithm bls12381 -master $master_path -pass $master_pass -cipher $master_cipher -pub $master_public_path 2>@1
    } result]} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error generating master keys:\n$result"
    } else {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Master key pair generated successfully!\n\n"
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Master key: [file tail $master_path]\n"
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Master public key: [file tail $master_public_path]"
    }
}

# Function to generate user key
proc generateUserKey {} {
    set user_id [.nb.keys_tab.main.user_frame.content.userIdEntry get]
    set hid [.nb.keys_tab.main.user_frame.content.hidCombo get]
    set master_pass [.nb.keys_tab.main.keys_frame.title_frame.right_frame.passEntry get]
    set user_pass [.nb.keys_tab.main.user_frame.title_frame.right_frame.passEntry get]
    set user_cipher [.nb.keys_tab.main.user_frame.title_frame.right_frame.cipherCombo get]
    
    # Validate inputs
    if {$user_id eq ""} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error: User ID cannot be empty!"
        return
    }
    
    set master_key_path [.nb.keys_tab.main.keys_frame.content.masterKeyInput get]
    if {$master_key_path eq "" || ![file exists $master_key_path]} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error: Master key file not found!"
        return
    }
    
    # If passphrases are empty, use "nil"
    if {$master_pass eq ""} {
        set master_pass "nil"
    }
    if {$user_pass eq ""} {
        set user_pass "nil"
    }
    
    # Get user-specified key path from the input field
    set user_key_path [.nb.keys_tab.main.user_frame.content.userKeyInput get]
    
    # If no user-specified path, generate a default one
    if {$user_key_path eq ""} {
        # Get current directory
        set current_dir [pwd]
        
        # Generate unique filename based on user ID
        set clean_id [string map {":" "_" "/" "_" "\\" "_" "*" "_" "?" "_" "\"" "_" "<" "_" ">" "_" "|" "_"} $user_id]
        set user_key_name "Private_${clean_id}"
        
        # Default path
        set user_key_path [file join $current_dir "${user_key_name}.pem"]
    } else {
        # User has specified a path, check if it's a directory or file
        if {[file isdirectory $user_key_path]} {
            # User entered a directory, generate filename inside it
            set clean_id [string map {":" "_" "/" "_" "\\" "_" "*" "_" "?" "_" "\"" "_" "<" "_" ">" "_" "|" "_"} $user_id]
            set user_key_name "Private_${clean_id}"
            set user_key_path [file join $user_key_path "${user_key_name}.pem"]
        } elseif {![string match "*.pem" $user_key_path]} {
            # User entered a filename without extension, add .pem
            set user_key_path "${user_key_path}.pem"
        }
    }
    
    # Extract directory from the final path
    set user_key_dir [file dirname $user_key_path]
    
    # Check if directory exists, if not, ask user
    if {![file exists $user_key_dir]} {
        set choice [tk_messageBox \
            -title "Directory Not Found" \
            -message "Directory does not exist:\n\n$user_key_dir\n\nCreate it?" \
            -type yesno \
            -icon warning \
            -default yes]
        
        if {$choice eq "no"} {
            .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.keys_tab.main.output_frame.textframe.outputArea insert end "User key generation cancelled."
            return
        }
        
        # Try to create directory
        if {[catch {file mkdir $user_key_dir} errorMsg]} {
            .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error creating directory:\n$errorMsg"
            return
        }
    }
    
    # Check if file already exists
    if {[file exists $user_key_path]} {
        set choice [tk_messageBox \
            -title "File Already Exists" \
            -message "User key file already exists:\n\n[file tail $user_key_path]\n\nWhat do you want to do?" \
            -type yesnocancel \
            -icon warning \
            -detail "Yes: Overwrite existing file\nNo: Generate with NEW numeric suffix (rename)\nCancel: Abort operation" \
            -default cancel]
        
        if {$choice eq "cancel"} {
            .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.keys_tab.main.output_frame.textframe.outputArea insert end "User key generation cancelled."
            return
        } elseif {$choice eq "no"} {
            # Find next available name
            set counter 1
            set dir [file dirname $user_key_path]
            set base_name [file rootname [file tail $user_key_path]]
            set ext [file extension $user_key_path]
            
            set new_user_key_path [file join $dir "${base_name}_${counter}${ext}"]
            
            while {[file exists $new_user_key_path]} {
                incr counter
                set new_user_key_path [file join $dir "${base_name}_${counter}${ext}"]
            }
            
            set user_key_path $new_user_key_path
        }
    }
    
    # Update entry field with the final path
    .nb.keys_tab.main.user_frame.content.userKeyInput delete 0 end
    .nb.keys_tab.main.user_frame.content.userKeyInput insert 0 $user_key_path
    
    # IBE key generation (boneh-franklin)
    set cmd "edgetk -pkey keygen -algorithm bls12381 -master \"$master_key_path\" -pass \"$master_pass\" -prv \"$user_key_path\" -passout \"$user_pass\" -cipher \"$user_cipher\" -id \"$user_id\" -hid $hid"
    
    # Execute command
    if {[catch {
        exec {*}$cmd 2>@1
    } result]} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error generating user key:\n$result"
    } else {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "User key generated successfully!\n\n"
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "User ID: $user_id\n"
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "HID: $hid\n"
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "User key saved to: $user_key_path"
    }
}

# Function to parse key file
proc parseKeyFile {} {
    set key_path [.nb.keys_tab.main.parse_frame.content.keyInput get]
    set passphrase [.nb.keys_tab.main.parse_frame.title_frame.right_frame.passEntry get]
    
    if {$key_path eq "" || ![file exists $key_path]} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error: Key file not found!"
        return
    }
    
    # Verificar se o arquivo contém cabeçalho DEK-Info
    set is_encrypted 0
    if {[catch {
        set fd [open $key_path r]
        set content [read $fd]
        close $fd
        
        # Procurar por DEK-Info no conteúdo
        if {[string match "*DEK-Info*" $content] || [string match "*ENCRYPTED*" $content]} {
            set is_encrypted 1
        }
    }]} {
        # Se houver erro na leitura, assumimos que não está criptografado
        set is_encrypted 0
    }
    
    # Construir o comando dinamicamente
    set cmd "edgetk -pkey text -key \"$key_path\""
    
    # Adicionar a flag -pass apenas se:
    # 1. A chave está criptografada (tem DEK-Info) OU
    # 2. O usuário forneceu uma passphrase (mesmo que a chave não esteja criptografada)
    if {$is_encrypted || $passphrase ne ""} {
        # Se a chave está criptografada mas o passphrase está vazio, usar "nil"
        if {$passphrase eq ""} {
            set passphrase "nil"
        }
        append cmd " -pass \"$passphrase\""
    }
    
    # Execute parse command
    if {[catch {
        exec {*}$cmd 2>@1
    } result]} {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Error parsing key:\n$result"
    } else {
        .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.keys_tab.main.output_frame.textframe.outputArea insert end "Key information:\n\n$result"
    }
}

# Function to update UI based on tab selection
proc updateKeyTabUI {} {
    set tab_index [.nb index current]
    
    if {$tab_index eq "keys_tab"} {
        # Enable key generation fields
        .nb.keys_tab.main.keys_frame.title_frame.right_frame.passEntry configure -state normal
        .nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherCombo configure -state normal
    }
}

# ===== SIGNATURE TAB FUNCTIONS =====

# Function to select input type (text or file)
proc selectSignatureInputType {} {
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

# Function to create signature
proc createIBSSignature {} {
    global signature_data
    
    set user_key_path [.nb.signatures_tab.main.keys_frame.content.userKeyInput get]
    set passphrase [.nb.signatures_tab.main.keys_frame.content.passEntry get]
    
    # Validate user key
    if {$user_key_path eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a user private key!"
        return
    }
    
    if {![file exists $user_key_path]} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: User private key file not found!"
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
        
        # Create signature from text (hess for IBS)
        if {[catch {
            set result [exec edgetk -pkey sign -algorithm bls12381sign -scheme hess -key $user_key_path -pass $passphrase << $input_text 2>@1]
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
        
        # Create signature from file (hess for IBS)
        if {[catch {
            set result [exec edgetk -pkey sign -algorithm bls12381sign -scheme hess -key $user_key_path -pass $passphrase $input_file 2>@1]
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

# Function to extract signature from output
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

# Function to verify signature
proc verifyIBSSignature {} {
    global signature_data
    
    set master_public_path [.nb.signatures_tab.main.keys_frame.content.masterPublicInput get]
    set user_id [.nb.signatures_tab.main.keys_frame.content.userIdEntry get]
    set hid [.nb.signatures_tab.main.keys_frame.content.hidCombo get]
    
    # Validate inputs
    if {$master_public_path eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a master public key!"
        return
    }
    
    if {![file exists $master_public_path]} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: Master public key file not found!"
        return
    }
    
    if {$user_id eq ""} {
        .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Error: User ID cannot be empty!"
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
        
        # Verify signature from text (hess for IBS)
        if {[catch {
            set result [exec edgetk -pkey verify -algorithm bls12381sign -scheme hess -key $master_public_path -id $user_id -hid $hid -signature $signature << $input_text 2>@1]
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
        
        # Verify signature from file (hess for IBS)
        if {[catch {
            set result [exec edgetk -pkey verify -algorithm bls12381sign -scheme hess -key $master_public_path -id $user_id -hid $hid -signature $signature $input_file 2>@1]
        } result]} {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature INVALID!\n\n$result"
        } else {
            .nb.signatures_tab.main.output_frame.textframe.outputArea insert end "Signature VALID!\n\n$result"
        }
    }
}

# ===== ENCRYPTION TAB FUNCTIONS =====

# Function to select input type (text or file) for encryption
proc selectEncryptionInputType {} {
    set input_type [.nb.encryption_tab.main.input_frame.content.inputTypeCombo get]
    if {$input_type eq "Text"} {
        # Enable text area, disable file entry
        .nb.encryption_tab.main.input_frame.content.textframe.inputText configure -state normal
        .nb.encryption_tab.main.input_frame.content.inputFile configure -state disabled
        .nb.encryption_tab.main.input_frame.content.openFileButton configure -state disabled
        .nb.encryption_tab.main.input_frame.content.inputFile configure -background "#f0f0f0"
        .nb.encryption_tab.main.input_frame.content.textframe.inputText configure -background "white"
        # Clear file entry when switching to text mode
        .nb.encryption_tab.main.input_frame.content.inputFile delete 0 end
    } else {
        # Enable file entry, disable text area
        .nb.encryption_tab.main.input_frame.content.textframe.inputText configure -state disabled
        .nb.encryption_tab.main.input_frame.content.inputFile configure -state normal
        .nb.encryption_tab.main.input_frame.content.openFileButton configure -state normal
        .nb.encryption_tab.main.input_frame.content.inputFile configure -background "white"
        .nb.encryption_tab.main.input_frame.content.textframe.inputText configure -background "#f0f0f0"
        # Clear text area when switching to file mode
        .nb.encryption_tab.main.input_frame.content.textframe.inputText delete 1.0 end
    }
}

# Function to select output type (text or file) for encryption
proc selectEncryptionOutputType {} {
    set output_type [.nb.encryption_tab.main.output_frame.content.outputTypeCombo get]
    if {$output_type eq "Text"} {
        # Enable text area, disable file entry
        .nb.encryption_tab.main.output_frame.content.textframe.outputText configure -state normal
        .nb.encryption_tab.main.output_frame.content.outputFile configure -state disabled
        .nb.encryption_tab.main.output_frame.content.saveFileButton configure -state disabled
        .nb.encryption_tab.main.output_frame.content.outputFile configure -background "#f0f0f0"
        .nb.encryption_tab.main.output_frame.content.textframe.outputText configure -background "white"
    } else {
        # Enable file entry, disable text area
        .nb.encryption_tab.main.output_frame.content.textframe.outputText configure -state disabled
        .nb.encryption_tab.main.output_frame.content.outputFile configure -state normal
        .nb.encryption_tab.main.output_frame.content.saveFileButton configure -state normal
        .nb.encryption_tab.main.output_frame.content.outputFile configure -background "white"
        .nb.encryption_tab.main.output_frame.content.textframe.outputText configure -background "#f0f0f0"
    }
}

# Function to encrypt data  
proc encryptIBE {} {
    set master_public_path [.nb.encryption_tab.main.keys_frame.content.masterPublicInput get]
    set user_id [.nb.encryption_tab.main.keys_frame.content.userIdEntry get]
    set hid [.nb.encryption_tab.main.keys_frame.content.hidCombo get]
    
    # Validate inputs
    if {$master_public_path eq ""} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
        .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please select a master public key!"
        return
    }
    
    if {![file exists $master_public_path]} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
        .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Master public key file not found!"
        return
    }
    
    if {$user_id eq ""} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
        .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: User ID cannot be empty!"
        return
    }
    
    set input_type [.nb.encryption_tab.main.input_frame.content.inputTypeCombo get]
    set output_type [.nb.encryption_tab.main.output_frame.content.outputTypeCombo get]
    
    # Clear output area
    if {$output_type eq "Text"} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
    }
    
    if {$input_type eq "Text"} {
        # Get text input
        set input_text [.nb.encryption_tab.main.input_frame.content.textframe.inputText get 1.0 end-1c]
        
        if {[string trim $input_text] eq ""} {
            if {$output_type eq "Text"} {
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please enter text to encrypt!"
            }
            return
        }
        
        # Encrypt text (boneh-franklin for IBE) e converter para base64
        if {[catch {
            set result [exec edgetk -pkey encrypt -algorithm bls12381 -key $master_public_path -id $user_id -hid $hid << $input_text | edgetk -base64 enc 2>@1]
        } result]} {
            if {$output_type eq "Text"} {
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error encrypting text:\n$result"
            }
            return
        }
        
        # Handle output
        if {$output_type eq "Text"} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end $result
        } else {
            # Save to file
            set output_file [.nb.encryption_tab.main.output_frame.content.outputFile get]
            if {$output_file ne ""} {
                set fd [open $output_file w]
                puts $fd $result
                close $fd
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Encrypted data saved to: $output_file\n"
            }
        }
        
    } else {
        # Get file input
        set input_file [.nb.encryption_tab.main.input_frame.content.inputFile get]
        
        if {$input_file eq "" || ![file exists $input_file]} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please select a valid input file!"
            return
        }
        
        set output_file [.nb.encryption_tab.main.output_frame.content.outputFile get]
        if {$output_type eq "File" && $output_file eq ""} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please specify an output file!"
            return
        }
        
        # Encrypt file (boneh-franklin for IBE)
        if {[catch {
            if {$output_type eq "Text"} {
                # Output to text area
                set result [exec edgetk -pkey encrypt -algorithm bls12381 -key $master_public_path -id $user_id -hid $hid $input_file | edgetk -base64 enc 2>@1]
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end $result
            } else {
                # Output to file
                set result [exec edgetk -pkey encrypt -algorithm bls12381 -key $master_public_path -id $user_id -hid $hid $input_file | edgetk -base64 enc > $output_file 2>@1]
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "File encrypted successfully!\n"
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Output: $output_file\n"
            }
        } result]} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error encrypting file:\n$result"
        }
    }
}

proc decryptIBE {} {
    set user_key_path [.nb.encryption_tab.main.keys_frame.content.userKeyInput get]
    set passphrase [.nb.encryption_tab.main.keys_frame.content.passEntry get]

    # Validação de inputs
    if {$user_key_path eq ""} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
        .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please select a user private key!\n"
        return
    }
    if {![file exists $user_key_path]} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
        .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: User private key file not found!\n"
        return
    }

    set input_type [.nb.encryption_tab.main.input_frame.content.inputTypeCombo get]
    set output_type [.nb.encryption_tab.main.output_frame.content.outputTypeCombo get]

    # Limpa saída se for modo texto
    if {$output_type eq "Text"} {
        .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
    }

    if {$input_type eq "Text"} {
        # Entrada de texto
        set input_text [.nb.encryption_tab.main.input_frame.content.textframe.inputText get 1.0 end-1c]
        if {[string trim $input_text] eq ""} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please enter ciphertext to decrypt!\n"
            return
        }

        # Arquivo temporário para base64 decode
        set temp_input [file tempfile]
        set fd [open $temp_input w]
        puts -nonewline $fd $input_text
        close $fd

        # Arquivo temporário para binário decodificado
        set temp_dec [file tempfile]

        if {[catch {
            # Base64 decode
            exec edgetk -base64 dec $temp_input > $temp_dec 2>@1
            file delete $temp_input

            if {$output_type eq "Text"} {
                # Decrypt para variável
                set decrypted [exec edgetk -pkey decrypt -algorithm bls12381 -key $user_key_path -pass $passphrase $temp_dec 2>@1]
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end $decrypted
            } else {
                # Decrypt para arquivo de saída
                set output_file [.nb.encryption_tab.main.output_frame.content.outputFile get]
                if {$output_file eq ""} {
                    file delete $temp_dec
                    .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please specify an output file!\n"
                    return
                }
                exec edgetk -pkey decrypt -algorithm bls12381 -key $user_key_path -pass $passphrase $temp_dec > $output_file 2>@1
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "File decrypted successfully!\nOutput: $output_file\n"
            }

            file delete $temp_dec
        } err]} {
            file delete $temp_input
            file delete $temp_dec
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error decrypting text:\n$err\n"
            return
        }

    } else {
        # Entrada por arquivo
        set input_file [.nb.encryption_tab.main.input_frame.content.inputFile get]
        if {$input_file eq "" || ![file exists $input_file]} {
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please select a valid input file!\n"
            return
        }

        set output_file [.nb.encryption_tab.main.output_frame.content.outputFile get]

        # Arquivo temporário para base64 decode
        set temp_dec [file tempfile]

        if {[catch {
            # Base64 decode
            exec edgetk -base64 dec $input_file > $temp_dec 2>@1

            if {$output_type eq "Text"} {
                # Decrypt para variável e mostrar na área de texto
                set decrypted [exec edgetk -pkey decrypt -algorithm bls12381 -key $user_key_path -pass $passphrase $temp_dec 2>@1]
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end $decrypted
            } else {
                # Decrypt para arquivo de saída
                if {$output_file eq ""} {
                    file delete $temp_dec
                    .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error: Please specify an output file!\n"
                    return
                }
                exec edgetk -pkey decrypt -algorithm bls12381 -key $user_key_path -pass $passphrase $temp_dec > $output_file 2>@1
                .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "File decrypted successfully!\nOutput: $output_file\n"
            }

            file delete $temp_dec
        } err]} {
            file delete $temp_dec
            .nb.encryption_tab.main.output_frame.content.textframe.outputText insert end "Error decrypting file:\n$err\n"
            return
        }
    }
}

# Function to save output file
proc saveOutputFile {} {
    set file_path [tk_getSaveFile -defaultextension ".txt" -filetypes {{"Text files" ".txt"} {"All files" "*"}}]
    if {$file_path ne ""} {
        .nb.encryption_tab.main.output_frame.content.outputFile delete 0 end
        .nb.encryption_tab.main.output_frame.content.outputFile insert 0 $file_path
    }
}

# ===== THRESHOLD IBE TAB FUNCTIONS =====

# Function to generate threshold master key
proc generateThresholdMasterKey {} {
    set master_public_path [.nb.threshold_tab.main.master_frame.content.masterPublicInput get]
    
    # Get current directory
    set current_dir [pwd]
    
    # Default names
    set master_name "MasterTH"
    set master_public_name "MasterPublicTH"
    
    # Default paths
    set master_path [file join $current_dir "${master_name}.pem"]
    set master_public_path [file join $current_dir "${master_public_name}.pem"]
    
    # Check if files already exist
    set master_exists [file exists $master_path]
    set master_public_exists [file exists $master_public_path]
    
    if {$master_exists || $master_public_exists} {
        set choice [tk_messageBox \
            -title "Files Already Exist" \
            -message "Threshold key files already exist:\n\nMaster: [file tail $master_path]\nMaster Public: [file tail $master_public_path]\n\nOverwrite?" \
            -type yesno \
            -icon warning \
            -default no]
        
        if {$choice eq "no"} {
            .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
            .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Threshold key generation cancelled."
            return
        }
    }
    
    # Update entry fields
    .nb.threshold_tab.main.master_frame.content.masterPublicInput delete 0 end
    .nb.threshold_tab.main.master_frame.content.masterPublicInput insert 0 $master_public_path
    
    # Execute threshold master key generation
    if {[catch {
        exec edgetk -pkey setup-threshold -master $master_path -pub $master_public_path 2>@1
    } result]} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error generating threshold master keys:\n$result"
    } else {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Threshold master key pair generated successfully!\n\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Threshold master shares saved as: MasterTH_01.pem ... MasterTH_05.pem\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Master public key: [file tail $master_public_path]\n\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Shares generated:\n"
        for {set i 1} {$i <= 5} {incr i} {
            .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "  Share $i: ${master_name}_[format "%02d" $i].pem\n"
        }
    }
}

# Function to generate partial key from threshold share
proc generatePartialKey {} {
    set share_path [.nb.threshold_tab.main.partial_frame.content.shareInput get]
    set user_id [.nb.threshold_tab.main.partial_frame.content.userIdEntry get]
    set hid [.nb.threshold_tab.main.partial_frame.content.hidCombo get]
    set output_path [.nb.threshold_tab.main.partial_frame.content.partialOutputInput get]
    
    # Validate inputs
    if {$share_path eq ""} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error: Please select a master share file!"
        return
    }
    
    if {![file exists $share_path]} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error: Master share file not found!"
        return
    }
    
    if {$user_id eq ""} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error: User ID cannot be empty!"
        return
    }
    
    # Determine output filename
    if {$output_path eq ""} {
        # Extract share number from filename
        set share_number ""
        if {[regexp {_(\d+)\.pem$} $share_path -> share_number]} {
            set clean_id [string map {":" "_" "/" "_" "\\" "_" "*" "_" "?" "_" "\"" "_" "<" "_" ">" "_" "|" "_"} $user_id]
            set output_path "${clean_id}.pem"
        } else {
            set output_path "partial_key_${user_id}.pem"
        }
    }
    
    set final_filename "partial_key_${user_id}_[format "%02d" $share_number].pem"
    
    # Execute partial key generation
    if {[catch {
        exec edgetk -pkey keygen-threshold -key $share_path -prv $output_path -id $user_id -hid $hid 2>@1
    } result]} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error generating partial key:\n$result"
    } else {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Partial key generated successfully!\n\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "User ID: $user_id\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "HID: $hid\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Share used: [file tail $share_path]\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Partial key saved to: [file tail $final_filename]\n"
    }
}

# Function to combine partial keys
proc combinePartialKeys {} {
    set output_path [.nb.threshold_tab.main.combine_frame.content.outputKeyInput get]
    set passphrase [.nb.threshold_tab.main.combine_frame.title_frame.right_frame.passEntry get]
    set cipher [.nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherCombo get]
    
    # Get partial key paths from the 3 entry fields
    set partial_key1 [.nb.threshold_tab.main.combine_frame.content.partialKey1Input get]
    set partial_key2 [.nb.threshold_tab.main.combine_frame.content.partialKey2Input get]
    set partial_key3 [.nb.threshold_tab.main.combine_frame.content.partialKey3Input get]
    
    # Validate inputs
    set partial_keys {}
    if {$partial_key1 ne "" && [file exists $partial_key1]} {
        lappend partial_keys $partial_key1
    }
    if {$partial_key2 ne "" && [file exists $partial_key2]} {
        lappend partial_keys $partial_key2
    }
    if {$partial_key3 ne "" && [file exists $partial_key3]} {
        lappend partial_keys $partial_key3
    }
    
    if {[llength $partial_keys] < 3} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error: Need at least 3 valid partial key files!"
        return
    }
    
    if {$output_path eq ""} {
        set output_path "ReconstructedKey.pem"
    }
    
    # If passphrase is empty, use "nil"
    if {$passphrase eq ""} {
        set passphrase "nil"
    }
    
    # Build the command with multiple -keys parameters
    set cmd "edgetk -pkey combine-threshold -prv \"$output_path\" -pass \"$passphrase\" -cipher \"$cipher\""
    foreach key $partial_keys {
        append cmd " -keys \"$key\""
    }
    
    # Execute combine command
    if {[catch {
        exec {*}$cmd 2>@1
    } result]} {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Error combining partial keys:\n$result"
    } else {
        .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Partial keys combined successfully!\n\n"
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "Combined keys:\n"
        foreach key $partial_keys {
            .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "  - [file tail $key]\n"
        }
        .nb.threshold_tab.main.output_frame.textframe.outputArea insert end "\nFull private key saved to: $output_path"
    }
}

# Main window configuration
wm title . "EDGE IBE/IBS Module - Identity-Based Cryptography"
wm geometry . 850x665  ;# Mais reduzida para caber melhor na tela
wm minsize . 800 550

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
frame .header -bg $accent_color -height 50  ;# Reduzido de 60 para 50
pack .header -fill x

# Title in header
label .header.title -text "EDGE IBE/IBS MODULE v1.0" \
    -bg $accent_color -fg white -font {Arial 14 bold}
pack .header.title -pady 2

# Subtitle
label .header.subtitle -text "Identity-Based Encryption (Boneh-Franklin) and Signatures (Hess) - BLS12-381" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .header.subtitle -pady 0

# Notebook for tabs (Keys, Signatures, Encryption, Threshold)
ttk::notebook .nb
pack .nb -fill both -expand yes -padx 6 -pady 3  ;# Reduzido padding

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

# ========== KEY GENERATION TAB ==========
frame .nb.keys_tab -bg $bg_color
.nb add .nb.keys_tab -text " Key Management "

# Main frame for content
frame .nb.keys_tab.main -bg $bg_color
pack .nb.keys_tab.main -fill both -expand yes -padx 6 -pady 3  ;# Reduzido padding

# Master key frame
frame .nb.keys_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.keys_tab.main.keys_frame -fill x -padx 6 -pady 3  ;# Reduzido padding

# Title frame with passphrase and cipher aligned to the right
frame .nb.keys_tab.main.keys_frame.title_frame -bg $frame_color
pack .nb.keys_tab.main.keys_frame.title_frame -fill x -padx 6 -pady 2

label .nb.keys_tab.main.keys_frame.title_frame.title -text "MASTER KEY GENERATION" \
    -font {Arial 10 bold} -bg $frame_color
pack .nb.keys_tab.main.keys_frame.title_frame.title -side left -anchor w

# Frame to hold passphrase and cipher aligned to the right
frame .nb.keys_tab.main.keys_frame.title_frame.right_frame -bg $frame_color
pack .nb.keys_tab.main.keys_frame.title_frame.right_frame -side right -padx 10

# PRIMEIRO: Cipher (vai para a direita extrema)
ttk::combobox .nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherCombo \
    -values {"aes" "anubis" "belt" "curupira" "kuznechik" "sm4" "serpent" "twofish" "camellia" "cast256" "mars" "noekeon" "crypton"} \
    -width 10 -state readonly
.nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherCombo set "aes"
pack .nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherCombo -side right -padx {0 5}

# SEGUNDO: Cipher label (vai à esquerda do combo)
label .nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherLabel -text "Cipher:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.keys_tab.main.keys_frame.title_frame.right_frame.cipherLabel -side right -padx {3 0}

# TERCEIRO: Passphrase entry (vai à esquerda do cipher label)
entry .nb.keys_tab.main.keys_frame.title_frame.right_frame.passEntry -width 12 \
    -font {Consolas 9} -show "*"
pack .nb.keys_tab.main.keys_frame.title_frame.right_frame.passEntry -side right -padx {0 10}

# QUARTO: Passphrase label (vai à esquerda do passphrase entry)
label .nb.keys_tab.main.keys_frame.title_frame.right_frame.passLabel -text "Passphrase:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.keys_tab.main.keys_frame.title_frame.right_frame.passLabel -side right -padx {10 3}

frame .nb.keys_tab.main.keys_frame.content -bg $frame_color
pack .nb.keys_tab.main.keys_frame.content -fill x -padx 6 -pady 2  ;# Reduzido padding

# Master key file
label .nb.keys_tab.main.keys_frame.content.masterKeyLabel -text "Master Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.keys_tab.main.keys_frame.content.masterKeyInput -width 40 -font {Consolas 9}
button .nb.keys_tab.main.keys_frame.content.openMasterButton -text "Open" -command {
    openFileDialog .nb.keys_tab.main.keys_frame.content.masterKeyInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.keys_tab.main.keys_frame.content.masterKeyLabel -row 0 -column 0 -sticky w -padx 3 -pady 2  ;# Reduzido pady
grid .nb.keys_tab.main.keys_frame.content.masterKeyInput -row 0 -column 1 -sticky ew -padx 3 -pady 2
grid .nb.keys_tab.main.keys_frame.content.openMasterButton -row 0 -column 2 -sticky w -padx 3 -pady 2

# Master public key file
label .nb.keys_tab.main.keys_frame.content.masterPublicLabel -text "Master Public:" -font {Arial 9 bold} -bg $frame_color
entry .nb.keys_tab.main.keys_frame.content.masterPublicInput -width 40 -font {Consolas 9}
button .nb.keys_tab.main.keys_frame.content.openMasterPublicButton -text "Open" -command {
    openFileDialog .nb.keys_tab.main.keys_frame.content.masterPublicInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.keys_tab.main.keys_frame.content.masterPublicLabel -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.keys_tab.main.keys_frame.content.masterPublicInput -row 1 -column 1 -sticky ew -padx 3 -pady 2
grid .nb.keys_tab.main.keys_frame.content.openMasterPublicButton -row 1 -column 2 -sticky w -padx 3 -pady 2

# Generate master key button
button .nb.keys_tab.main.keys_frame.content.generateMasterButton -text "Generate Master Key Pair" -command generateMasterKey \
    -bg "#28a745" -fg white -font {Arial 10 bold} -pady 2  ;# Reduzido pady
grid .nb.keys_tab.main.keys_frame.content.generateMasterButton -row 2 -column 0 -columnspan 3 -sticky ew -padx 3 -pady 5  ;# Reduzido pady

grid columnconfigure .nb.keys_tab.main.keys_frame.content 1 -weight 1

# User key frame
frame .nb.keys_tab.main.user_frame -bg $frame_color -relief solid -bd 1
pack .nb.keys_tab.main.user_frame -fill x -padx 6 -pady 3  ;# Reduzido padding

# Title frame with passphrase and cipher aligned to the right
frame .nb.keys_tab.main.user_frame.title_frame -bg $frame_color
pack .nb.keys_tab.main.user_frame.title_frame -fill x -padx 6 -pady 2

label .nb.keys_tab.main.user_frame.title_frame.title -text "USER KEY DERIVATION" \
    -font {Arial 10 bold} -bg $frame_color
pack .nb.keys_tab.main.user_frame.title_frame.title -side left -anchor w

# Frame to hold passphrase and cipher aligned to the right
frame .nb.keys_tab.main.user_frame.title_frame.right_frame -bg $frame_color
pack .nb.keys_tab.main.user_frame.title_frame.right_frame -side right -padx 10

# *** CORREÇÃO: Ordem inversa para pack com side right ***
# Para ter [Passphrase: campo] [Cipher: combo] usando pack -side right,
# precisamos empacotar na ordem INVERSA

# Primeiro: Cipher combo (vai para a direita extrema)
ttk::combobox .nb.keys_tab.main.user_frame.title_frame.right_frame.cipherCombo \
    -values {"aes" "anubis" "belt" "curupira" "kuznechik" "sm4" "serpent" "twofish" "camellia" "cast256" "mars" "noekeon" "crypton"} \
    -width 10 -state readonly
.nb.keys_tab.main.user_frame.title_frame.right_frame.cipherCombo set "aes"
pack .nb.keys_tab.main.user_frame.title_frame.right_frame.cipherCombo -side right

# Segundo: Cipher label (vai à esquerda do combo)
label .nb.keys_tab.main.user_frame.title_frame.right_frame.cipherLabel -text "Cipher:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.keys_tab.main.user_frame.title_frame.right_frame.cipherLabel -side right -padx {0 3}

# Terceiro: Passphrase entry (vai à esquerda do cipher label)
entry .nb.keys_tab.main.user_frame.title_frame.right_frame.passEntry -width 12 \
    -font {Consolas 9} -show "*"
pack .nb.keys_tab.main.user_frame.title_frame.right_frame.passEntry -side right -padx {0 10}

# Quarto: Passphrase label (vai à esquerda do passphrase entry)
label .nb.keys_tab.main.user_frame.title_frame.right_frame.passLabel -text "Passphrase:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.keys_tab.main.user_frame.title_frame.right_frame.passLabel -side right -padx {0 3}

frame .nb.keys_tab.main.user_frame.content -bg $frame_color
pack .nb.keys_tab.main.user_frame.content -fill x -padx 6 -pady 2

# User ID
label .nb.keys_tab.main.user_frame.content.userIdLabel -text "User ID:" -font {Arial 9 bold} -bg $frame_color
entry .nb.keys_tab.main.user_frame.content.userIdEntry -width 30 -font {Consolas 9}
grid .nb.keys_tab.main.user_frame.content.userIdLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.keys_tab.main.user_frame.content.userIdEntry -row 0 -column 1 -sticky ew -padx 3 -pady 2

# HID - Adicionado na mesma linha
label .nb.keys_tab.main.user_frame.content.hidLabel -text "HID:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.keys_tab.main.user_frame.content.hidCombo -values [generateHIDValues] -state readonly -width 5
.nb.keys_tab.main.user_frame.content.hidCombo set "3"
grid .nb.keys_tab.main.user_frame.content.hidLabel -row 0 -column 2 -sticky w -padx {10 3} -pady 2
grid .nb.keys_tab.main.user_frame.content.hidCombo -row 0 -column 3 -sticky w -padx 3 -pady 2

# User key file
label .nb.keys_tab.main.user_frame.content.userKeyLabel -text "User Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.keys_tab.main.user_frame.content.userKeyInput -width 40 -font {Consolas 9}

button .nb.keys_tab.main.user_frame.content.openUserButton -text "Save" -command {
    set file_path [tk_getSaveFile -defaultextension ".pem" -filetypes {{"PEM files" ".pem"} {"All files" "*"}}]
    if {$file_path ne ""} {
        .nb.keys_tab.main.user_frame.content.userKeyInput delete 0 end
        .nb.keys_tab.main.user_frame.content.userKeyInput insert 0 $file_path
    }
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.keys_tab.main.user_frame.content.userKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.keys_tab.main.user_frame.content.userKeyInput -row 1 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.keys_tab.main.user_frame.content.openUserButton -row 1 -column 3 -sticky e -padx 3 -pady 2

# Generate user key button
button .nb.keys_tab.main.user_frame.content.generateUserButton -text "Generate User Key" -command generateUserKey \
    -bg "#6c757d" -fg white -font {Arial 10 bold} -pady 2
grid .nb.keys_tab.main.user_frame.content.generateUserButton -row 2 -column 0 -columnspan 4 -sticky ew -padx 3 -pady 5

grid columnconfigure .nb.keys_tab.main.user_frame.content 1 -weight 1

# Parse key frame
frame .nb.keys_tab.main.parse_frame -bg $frame_color -relief solid -bd 1
pack .nb.keys_tab.main.parse_frame -fill x -padx 6 -pady 3  ;# Reduzido padding

# Title frame with passphrase aligned to the right
frame .nb.keys_tab.main.parse_frame.title_frame -bg $frame_color
pack .nb.keys_tab.main.parse_frame.title_frame -fill x -padx 6 -pady 2

label .nb.keys_tab.main.parse_frame.title_frame.title -text "KEY PARSING" \
    -font {Arial 10 bold} -bg $frame_color
pack .nb.keys_tab.main.parse_frame.title_frame.title -side left -anchor w

# Frame to hold passphrase aligned to the right
frame .nb.keys_tab.main.parse_frame.title_frame.right_frame -bg $frame_color
pack .nb.keys_tab.main.parse_frame.title_frame.right_frame -side right -padx 10

# CORREÇÃO: Passphrase label and entry (ORDEM INVERSA para pack -side right)
# Primeiro: entry (campo de password) - vai para a direita extrema
entry .nb.keys_tab.main.parse_frame.title_frame.right_frame.passEntry -width 12 \
    -font {Consolas 9} -show "*"
pack .nb.keys_tab.main.parse_frame.title_frame.right_frame.passEntry -side right

# Segundo: label (texto "Passphrase:") - vai à esquerda do campo
label .nb.keys_tab.main.parse_frame.title_frame.right_frame.passLabel -text "Passphrase:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.keys_tab.main.parse_frame.title_frame.right_frame.passLabel -side right -padx {10 3}

frame .nb.keys_tab.main.parse_frame.content -bg $frame_color
pack .nb.keys_tab.main.parse_frame.content -fill x -padx 6 -pady 2

# Key file to parse
label .nb.keys_tab.main.parse_frame.content.keyLabel -text "Key File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.keys_tab.main.parse_frame.content.keyInput -width 40 -font {Consolas 9}
button .nb.keys_tab.main.parse_frame.content.openKeyButton -text "Open" -command {
    openFileDialog .nb.keys_tab.main.parse_frame.content.keyInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.keys_tab.main.parse_frame.content.keyLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.keys_tab.main.parse_frame.content.keyInput -row 0 -column 1 -sticky ew -padx 3 -pady 2
grid .nb.keys_tab.main.parse_frame.content.openKeyButton -row 0 -column 2 -sticky w -padx 3 -pady 2

# Parse button
button .nb.keys_tab.main.parse_frame.content.parseButton -text "Parse Key File" -command parseKeyFile \
    -bg "#fd7e14" -fg white -font {Arial 10 bold} -pady 2
grid .nb.keys_tab.main.parse_frame.content.parseButton -row 1 -column 0 -columnspan 3 -sticky ew -padx 3 -pady 5

grid columnconfigure .nb.keys_tab.main.parse_frame.content 1 -weight 1

# Output frame (reduced height)
frame .nb.keys_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.keys_tab.main.output_frame -fill both -expand true -padx 6 -pady 3  ;# Reduzido padding

label .nb.keys_tab.main.output_frame.title -text "OUTPUT" -font {Arial 10 bold} -bg $frame_color
pack .nb.keys_tab.main.output_frame.title -anchor w -padx 6 -pady 2

# Create output text area (reduced height)
frame .nb.keys_tab.main.output_frame.textframe -bg $frame_color
pack .nb.keys_tab.main.output_frame.textframe -fill both -expand true -padx 6 -pady 2

text .nb.keys_tab.main.output_frame.textframe.outputArea -width 70 -height 6 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.keys_tab.main.output_frame.textframe.yscroll -orient vertical \
    -command {.nb.keys_tab.main.output_frame.textframe.outputArea yview}
.nb.keys_tab.main.output_frame.textframe.outputArea configure \
    -yscrollcommand {.nb.keys_tab.main.output_frame.textframe.yscroll set}

grid .nb.keys_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.keys_tab.main.output_frame.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.keys_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.keys_tab.main.output_frame.textframe 0 -weight 1

# Utility buttons
frame .nb.keys_tab.main.output_frame.utility_buttons -bg $frame_color
pack .nb.keys_tab.main.output_frame.utility_buttons -fill x -padx 6 -pady 2

button .nb.keys_tab.main.output_frame.utility_buttons.copyButton -text "Copy" -command {
    copyText [.nb.keys_tab.main.output_frame.textframe.outputArea get 1.0 end]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.keys_tab.main.output_frame.utility_buttons.copyButton -side left -padx 2

button .nb.keys_tab.main.output_frame.utility_buttons.clearButton -text "Clear" -command {
    .nb.keys_tab.main.output_frame.textframe.outputArea delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 10
pack .nb.keys_tab.main.output_frame.utility_buttons.clearButton -side left -padx 2

# ================= SIGNATURES TAB =================
frame .nb.signatures_tab -bg $bg_color
.nb add .nb.signatures_tab -text " IBS Signatures "

# Main frame for content
frame .nb.signatures_tab.main -bg $bg_color
pack .nb.signatures_tab.main -fill both -expand yes -padx 6 -pady 3

# ========== KEYS FRAME ==========
frame .nb.signatures_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.keys_frame -fill x -padx 6 -pady 3

label .nb.signatures_tab.main.keys_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.keys_frame.title -anchor w -padx 6 -pady 2

frame .nb.signatures_tab.main.keys_frame.content -bg $frame_color
pack .nb.signatures_tab.main.keys_frame.content -fill x -padx 6 -pady 2

# Master public key file
label .nb.signatures_tab.main.keys_frame.content.masterPublicLabel -text "Master Public:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.masterPublicInput -width 40 -font {Consolas 9}
button .nb.signatures_tab.main.keys_frame.content.openMasterPublicButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.keys_frame.content.masterPublicInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.keys_frame.content.masterPublicLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.masterPublicInput -row 0 -column 1 -columnspan 3 -sticky ew -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.openMasterPublicButton -row 0 -column 4 -sticky e -padx 3 -pady 2

# User key file
label .nb.signatures_tab.main.keys_frame.content.userKeyLabel -text "User Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.userKeyInput -width 40 -font {Consolas 9}
button .nb.signatures_tab.main.keys_frame.content.openUserButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.keys_frame.content.userKeyInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.keys_frame.content.userKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.userKeyInput -row 1 -column 1 -columnspan 3 -sticky ew -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.openUserButton -row 1 -column 4 -sticky e -padx 3 -pady 2

# User ID and HID
label .nb.signatures_tab.main.keys_frame.content.userIdLabel -text "User ID:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.userIdEntry -width 30 -font {Consolas 9}

label .nb.signatures_tab.main.keys_frame.content.hidLabel -text "HID:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.keys_frame.content.hidCombo -values [generateHIDValues] -state readonly -width 5
.nb.signatures_tab.main.keys_frame.content.hidCombo set "1"

grid .nb.signatures_tab.main.keys_frame.content.userIdLabel -row 2 -column 0 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.userIdEntry -row 2 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.hidLabel -row 2 -column 3 -sticky e -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.hidCombo -row 2 -column 4 -sticky e -padx 3 -pady 2

# Passphrase
label .nb.signatures_tab.main.keys_frame.content.passLabel -text "Passphrase:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.keys_frame.content.passEntry -width 15 -font {Consolas 9} -show "*"

grid .nb.signatures_tab.main.keys_frame.content.passLabel -row 3 -column 0 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.keys_frame.content.passEntry -row 3 -column 1 -sticky w -padx 3 -pady 2

grid columnconfigure .nb.signatures_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.signatures_tab.main.keys_frame.content 2 -weight 1
grid columnconfigure .nb.signatures_tab.main.keys_frame.content 3 -weight 0
grid columnconfigure .nb.signatures_tab.main.keys_frame.content 4 -weight 0

# ========== INPUT DATA FRAME ==========
frame .nb.signatures_tab.main.input_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.input_frame -fill both -expand yes -padx 6 -pady 3

label .nb.signatures_tab.main.input_frame.title -text "INPUT DATA" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.input_frame.title -anchor w -padx 6 -pady 2

frame .nb.signatures_tab.main.input_frame.content -bg $frame_color
pack .nb.signatures_tab.main.input_frame.content -fill both -expand yes -padx 6 -pady 2

# Input type
label .nb.signatures_tab.main.input_frame.content.inputTypeLabel -text "Input Type:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.signatures_tab.main.input_frame.content.inputTypeCombo -values {"Text" "File"} -state readonly -width 8
.nb.signatures_tab.main.input_frame.content.inputTypeCombo set "Text"
bind .nb.signatures_tab.main.input_frame.content.inputTypeCombo <<ComboboxSelected>> selectSignatureInputType

# File input
label .nb.signatures_tab.main.input_frame.content.fileLabel -text "File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.signatures_tab.main.input_frame.content.inputFile -width 40 -font {Consolas 9}
button .nb.signatures_tab.main.input_frame.content.openFileButton -text "Open" -command {
    openFileDialog .nb.signatures_tab.main.input_frame.content.inputFile
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.signatures_tab.main.input_frame.content.inputTypeLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.input_frame.content.inputTypeCombo -row 0 -column 1 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.input_frame.content.fileLabel -row 0 -column 2 -sticky w -padx 3 -pady 2
grid .nb.signatures_tab.main.input_frame.content.inputFile -row 0 -column 3 -sticky ew -padx 3 -pady 2
grid .nb.signatures_tab.main.input_frame.content.openFileButton -row 0 -column 4 -sticky w -padx 3 -pady 2

# Text area frame
frame .nb.signatures_tab.main.input_frame.content.textframe -bg $frame_color
grid .nb.signatures_tab.main.input_frame.content.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 3 -pady 2

text .nb.signatures_tab.main.input_frame.content.textframe.inputText -width 70 -height 7 -wrap word \
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

# Buttons for input text
frame .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons -bg $frame_color
grid .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons -row 1 -column 0 -columnspan 2 -sticky w -pady 2 -padx 2

button .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.copyButton -text "Copy" -command {
    copyText [.nb.signatures_tab.main.input_frame.content.textframe.inputText get 1.0 end]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8
pack .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.copyButton -side left -padx 2

button .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.pasteButton -text "Paste" -command {
    .nb.signatures_tab.main.input_frame.content.textframe.inputText insert end [clipboard get]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8
pack .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.pasteButton -side left -padx 2

button .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.clearButton -text "Clear" -command {
    .nb.signatures_tab.main.input_frame.content.textframe.inputText delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 8
pack .nb.signatures_tab.main.input_frame.content.textframe.utility_buttons.clearButton -side left -padx 2


# Initially disable file input
selectSignatureInputType

# ========== OUTPUT SIGNATURE ==========
frame .nb.signatures_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.signatures_tab.main.output_frame -fill x -padx 6 -pady 3

label .nb.signatures_tab.main.output_frame.title -text "SIGNATURE" -font {Arial 10 bold} -bg $frame_color
pack .nb.signatures_tab.main.output_frame.title -anchor w -padx 6 -pady 2

frame .nb.signatures_tab.main.output_frame.textframe -bg $frame_color
pack .nb.signatures_tab.main.output_frame.textframe -fill x -padx 6 -pady 2

text .nb.signatures_tab.main.output_frame.textframe.outputArea -width 70 -height 3 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.signatures_tab.main.output_frame.textframe.yscroll -orient vertical \
    -command {.nb.signatures_tab.main.output_frame.textframe.outputArea yview}
.nb.signatures_tab.main.output_frame.textframe.outputArea configure \
    -yscrollcommand {.nb.signatures_tab.main.output_frame.textframe.yscroll set}

grid .nb.signatures_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.signatures_tab.main.output_frame.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.signatures_tab.main.output_frame.textframe 0 -weight 0
grid columnconfigure .nb.signatures_tab.main.output_frame.textframe 0 -weight 1

# Buttons for output signature
frame .nb.signatures_tab.main.output_frame.utility_buttons -bg $frame_color
pack .nb.signatures_tab.main.output_frame.utility_buttons -fill x -padx 6 -pady 2

button .nb.signatures_tab.main.output_frame.utility_buttons.copyButton -text "Copy" -command {
    copyText [.nb.signatures_tab.main.output_frame.textframe.outputArea get 1.0 end]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.copyButton -side left -padx 2

button .nb.signatures_tab.main.output_frame.utility_buttons.pasteButton -text "Paste" -command {
    .nb.signatures_tab.main.output_frame.textframe.outputArea insert end [clipboard get]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.pasteButton -side left -padx 2

button .nb.signatures_tab.main.output_frame.utility_buttons.clearButton -text "Clear" -command {
    .nb.signatures_tab.main.output_frame.textframe.outputArea delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 10
pack .nb.signatures_tab.main.output_frame.utility_buttons.clearButton -side left -padx 2


# ========== ACTION BUTTONS ==========
frame .nb.signatures_tab.main.action_frame -bg $bg_color
pack .nb.signatures_tab.main.action_frame -fill x -padx 6 -pady 8

button .nb.signatures_tab.main.action_frame.verifyButton -text "Verify" -command verifyIBSSignature \
    -bg "#28a745" -fg white -font {Arial 10 bold} -padx 20 -pady 2
pack .nb.signatures_tab.main.action_frame.verifyButton -side right -padx {0 10}

button .nb.signatures_tab.main.action_frame.signButton -text "Sign" -command createIBSSignature \
    -bg "#6c757d" -fg white -font {Arial 10 bold} -padx 20 -pady 2
pack .nb.signatures_tab.main.action_frame.signButton -side right -padx {0 5}


# ========== ENCRYPTION TAB ==========
frame .nb.encryption_tab -bg $bg_color
.nb add .nb.encryption_tab -text " IBE Encryption "

# Main frame for content - configurar para expansão completa
frame .nb.encryption_tab.main -bg $bg_color
pack .nb.encryption_tab.main -fill both -expand yes -padx 6 -pady 3

# Configurar pesos para expansão vertical dos frames principais
grid columnconfigure .nb.encryption_tab.main 0 -weight 1
grid rowconfigure .nb.encryption_tab.main 0 -weight 0    ;# keys_frame - não expande verticalmente
grid rowconfigure .nb.encryption_tab.main 1 -weight 1    ;# input_frame - expande verticalmente
grid rowconfigure .nb.encryption_tab.main 2 -weight 1    ;# output_frame - expande verticalmente
grid rowconfigure .nb.encryption_tab.main 3 -weight 0    ;# action_frame - não expande verticalmente

# Key frame - não expande verticalmente
frame .nb.encryption_tab.main.keys_frame -bg $frame_color -relief solid -bd 1
grid .nb.encryption_tab.main.keys_frame -row 0 -column 0 -sticky "ew" -padx 6 -pady 3

label .nb.encryption_tab.main.keys_frame.title -text "KEY MANAGEMENT" -font {Arial 10 bold} -bg $frame_color
pack .nb.encryption_tab.main.keys_frame.title -anchor w -padx 6 -pady 2

frame .nb.encryption_tab.main.keys_frame.content -bg $frame_color
pack .nb.encryption_tab.main.keys_frame.content -fill x -padx 6 -pady 2

# Master public key file (for encryption)
label .nb.encryption_tab.main.keys_frame.content.masterPublicLabel -text "Master Public:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.keys_frame.content.masterPublicInput -width 40 -font {Consolas 9}
button .nb.encryption_tab.main.keys_frame.content.openMasterPublicButton -text "Open" -command {
    openFileDialog .nb.encryption_tab.main.keys_frame.content.masterPublicInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.encryption_tab.main.keys_frame.content.masterPublicLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.masterPublicInput -row 0 -column 1 -columnspan 3 -sticky ew -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.openMasterPublicButton -row 0 -column 4 -sticky e -padx 3 -pady 2

# User key file (for decryption)
label .nb.encryption_tab.main.keys_frame.content.userKeyLabel -text "User Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.keys_frame.content.userKeyInput -width 40 -font {Consolas 9}
button .nb.encryption_tab.main.keys_frame.content.openUserButton -text "Open" -command {
    openFileDialog .nb.encryption_tab.main.keys_frame.content.userKeyInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.encryption_tab.main.keys_frame.content.userKeyLabel -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.userKeyInput -row 1 -column 1 -columnspan 3 -sticky ew -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.openUserButton -row 1 -column 4 -sticky e -padx 3 -pady 2

# User ID and HID
label .nb.encryption_tab.main.keys_frame.content.userIdLabel -text "User ID:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.keys_frame.content.userIdEntry -width 30 -font {Consolas 9}

label .nb.encryption_tab.main.keys_frame.content.hidLabel -text "HID:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.encryption_tab.main.keys_frame.content.hidCombo -values [generateHIDValues] -state readonly -width 5
.nb.encryption_tab.main.keys_frame.content.hidCombo set "3"

grid .nb.encryption_tab.main.keys_frame.content.userIdLabel -row 2 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.userIdEntry -row 2 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2

# Colocar HID label e combobox nas colunas 3 e 4
grid .nb.encryption_tab.main.keys_frame.content.hidLabel -row 2 -column 3 -sticky e -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.hidCombo -row 2 -column 4 -sticky e -padx 3 -pady 2

# Passphrase (for decryption)
label .nb.encryption_tab.main.keys_frame.content.passLabel -text "Passphrase:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.keys_frame.content.passEntry -width 15 -font {Consolas 9} -show "*"

grid .nb.encryption_tab.main.keys_frame.content.passLabel -row 3 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.keys_frame.content.passEntry -row 3 -column 1 -sticky w -padx 3 -pady 2

# Configurar pesos das colunas para expansão horizontal
grid columnconfigure .nb.encryption_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.encryption_tab.main.keys_frame.content 2 -weight 1
grid columnconfigure .nb.encryption_tab.main.keys_frame.content 3 -weight 0
grid columnconfigure .nb.encryption_tab.main.keys_frame.content 4 -weight 0

# Input data frame - expande vertical e horizontalmente
frame .nb.encryption_tab.main.input_frame -bg $frame_color -relief solid -bd 1
grid .nb.encryption_tab.main.input_frame -row 1 -column 0 -sticky "nsew" -padx 6 -pady 3

# Configurar expansão do input_frame
grid columnconfigure .nb.encryption_tab.main.input_frame 0 -weight 1
grid rowconfigure .nb.encryption_tab.main.input_frame 1 -weight 1

label .nb.encryption_tab.main.input_frame.title -text "INPUT DATA" -font {Arial 10 bold} -bg $frame_color
pack .nb.encryption_tab.main.input_frame.title -anchor w -padx 6 -pady 2

frame .nb.encryption_tab.main.input_frame.content -bg $frame_color
pack .nb.encryption_tab.main.input_frame.content -fill both -expand yes -padx 6 -pady 2

# Configurar expansão do content frame
grid columnconfigure .nb.encryption_tab.main.input_frame.content 3 -weight 1
grid rowconfigure .nb.encryption_tab.main.input_frame.content 1 -weight 1

# Input type
label .nb.encryption_tab.main.input_frame.content.inputTypeLabel -text "Input Type:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.encryption_tab.main.input_frame.content.inputTypeCombo -values {"Text" "File"} -state readonly -width 8
.nb.encryption_tab.main.input_frame.content.inputTypeCombo set "Text"

# Bind combobox selection
bind .nb.encryption_tab.main.input_frame.content.inputTypeCombo <<ComboboxSelected>> selectEncryptionInputType

# File input
label .nb.encryption_tab.main.input_frame.content.fileLabel -text "File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.input_frame.content.inputFile -width 40 -font {Consolas 9}
button .nb.encryption_tab.main.input_frame.content.openFileButton -text "Open" -command {
    openFileDialog .nb.encryption_tab.main.input_frame.content.inputFile
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.encryption_tab.main.input_frame.content.inputTypeLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.input_frame.content.inputTypeCombo -row 0 -column 1 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.input_frame.content.fileLabel -row 0 -column 2 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.input_frame.content.inputFile -row 0 -column 3 -sticky ew -padx 3 -pady 2
grid .nb.encryption_tab.main.input_frame.content.openFileButton -row 0 -column 4 -sticky w -padx 3 -pady 2

# Frame for text area - expande vertical e horizontalmente
frame .nb.encryption_tab.main.input_frame.content.textframe -bg $frame_color
grid .nb.encryption_tab.main.input_frame.content.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 3 -pady 2

# Configurar expansão do textframe
grid columnconfigure .nb.encryption_tab.main.input_frame.content.textframe 0 -weight 1
grid rowconfigure .nb.encryption_tab.main.input_frame.content.textframe 0 -weight 1

# Text area for text input - REMOVER width fixo para permitir expansão
text .nb.encryption_tab.main.input_frame.content.textframe.inputText -height 5 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.encryption_tab.main.input_frame.content.textframe.yscroll -orient vertical \
    -command {.nb.encryption_tab.main.input_frame.content.textframe.inputText yview}
.nb.encryption_tab.main.input_frame.content.textframe.inputText configure \
    -yscrollcommand {.nb.encryption_tab.main.input_frame.content.textframe.yscroll set}

grid .nb.encryption_tab.main.input_frame.content.textframe.inputText -row 0 -column 0 -sticky "nsew"
grid .nb.encryption_tab.main.input_frame.content.textframe.yscroll -row 0 -column 1 -sticky "ns"

# Frame for utility buttons for input text
frame .nb.encryption_tab.main.input_frame.content.textframe.button_frame -bg $frame_color
grid .nb.encryption_tab.main.input_frame.content.textframe.button_frame -row 1 -column 0 -columnspan 2 -sticky "ew" -padx 3 -pady 2

# Copy button (for input)
button .nb.encryption_tab.main.input_frame.content.textframe.button_frame.copyInputButton -text "Copy" -command {
    copyText [.nb.encryption_tab.main.input_frame.content.textframe.inputText get 1.0 end-1c]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.input_frame.content.textframe.button_frame.copyInputButton -side left -padx 2

# Paste button (for input)
button .nb.encryption_tab.main.input_frame.content.textframe.button_frame.pasteButton -text "Paste" -command {
    .nb.encryption_tab.main.input_frame.content.textframe.inputText insert insert [clipboard get]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.input_frame.content.textframe.button_frame.pasteButton -side left -padx 2

# Clear button (for input)
button .nb.encryption_tab.main.input_frame.content.textframe.button_frame.clearInputButton -text "Clear" -command {
    .nb.encryption_tab.main.input_frame.content.textframe.inputText delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.input_frame.content.textframe.button_frame.clearInputButton -side left -padx 2

# Initially disable file input
selectEncryptionInputType

# Output frame - expande vertical e horizontalmente
frame .nb.encryption_tab.main.output_frame -bg $frame_color -relief solid -bd 1
grid .nb.encryption_tab.main.output_frame -row 2 -column 0 -sticky "nsew" -padx 6 -pady 3

# Configurar expansão do output_frame
grid columnconfigure .nb.encryption_tab.main.output_frame 0 -weight 1
grid rowconfigure .nb.encryption_tab.main.output_frame 1 -weight 1

label .nb.encryption_tab.main.output_frame.title -text "OUTPUT" -font {Arial 10 bold} -bg $frame_color
pack .nb.encryption_tab.main.output_frame.title -anchor w -padx 6 -pady 2

frame .nb.encryption_tab.main.output_frame.content -bg $frame_color
pack .nb.encryption_tab.main.output_frame.content -fill both -expand yes -padx 6 -pady 2

# Configurar expansão do content frame
grid columnconfigure .nb.encryption_tab.main.output_frame.content 3 -weight 1
grid rowconfigure .nb.encryption_tab.main.output_frame.content 1 -weight 1

# Output type
label .nb.encryption_tab.main.output_frame.content.outputTypeLabel -text "Output Type:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.encryption_tab.main.output_frame.content.outputTypeCombo -values {"Text" "File"} -state readonly -width 8
.nb.encryption_tab.main.output_frame.content.outputTypeCombo set "Text"

# Bind combobox selection
bind .nb.encryption_tab.main.output_frame.content.outputTypeCombo <<ComboboxSelected>> selectEncryptionOutputType

# File output
label .nb.encryption_tab.main.output_frame.content.fileLabel -text "File:" -font {Arial 9 bold} -bg $frame_color
entry .nb.encryption_tab.main.output_frame.content.outputFile -width 40 -font {Consolas 9}
button .nb.encryption_tab.main.output_frame.content.saveFileButton -text "Save" -command saveOutputFile \
    -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.encryption_tab.main.output_frame.content.outputTypeLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.output_frame.content.outputTypeCombo -row 0 -column 1 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.output_frame.content.fileLabel -row 0 -column 2 -sticky w -padx 3 -pady 2
grid .nb.encryption_tab.main.output_frame.content.outputFile -row 0 -column 3 -sticky ew -padx 3 -pady 2
grid .nb.encryption_tab.main.output_frame.content.saveFileButton -row 0 -column 4 -sticky w -padx 3 -pady 2

# Frame for text output area - expande vertical e horizontalmente
frame .nb.encryption_tab.main.output_frame.content.textframe -bg $frame_color
grid .nb.encryption_tab.main.output_frame.content.textframe -row 1 -column 0 -columnspan 5 -sticky "nsew" -padx 3 -pady 2

# Configurar expansão do textframe
grid columnconfigure .nb.encryption_tab.main.output_frame.content.textframe 0 -weight 1
grid rowconfigure .nb.encryption_tab.main.output_frame.content.textframe 0 -weight 1

# Text area for output - REMOVER width fixo para permitir expansão
text .nb.encryption_tab.main.output_frame.content.textframe.outputText -height 4 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.encryption_tab.main.output_frame.content.textframe.yscroll -orient vertical \
    -command {.nb.encryption_tab.main.output_frame.content.textframe.outputText yview}
.nb.encryption_tab.main.output_frame.content.textframe.outputText configure \
    -yscrollcommand {.nb.encryption_tab.main.output_frame.content.textframe.yscroll set}

grid .nb.encryption_tab.main.output_frame.content.textframe.outputText -row 0 -column 0 -sticky "nsew"
grid .nb.encryption_tab.main.output_frame.content.textframe.yscroll -row 0 -column 1 -sticky "ns"

# Frame para botões de utilidade da área de saída
frame .nb.encryption_tab.main.output_frame.content.textframe.button_frame -bg $frame_color
grid .nb.encryption_tab.main.output_frame.content.textframe.button_frame -row 2 -column 0 -columnspan 2 -sticky "ew" -padx 3 -pady 2

# Copy button (para área de saída)
button .nb.encryption_tab.main.output_frame.content.textframe.button_frame.copyButton -text "Copy" -command {
    copyText [.nb.encryption_tab.main.output_frame.content.textframe.outputText get 1.0 end-1c]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.output_frame.content.textframe.button_frame.copyButton -side left -padx 2

# Paste button (para área de saída)
button .nb.encryption_tab.main.output_frame.content.textframe.button_frame.pasteButton -text "Paste" -command {
    .nb.encryption_tab.main.output_frame.content.textframe.outputText insert insert [clipboard get]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.output_frame.content.textframe.button_frame.pasteButton -side left -padx 2

# Clear button (para área de saída)
button .nb.encryption_tab.main.output_frame.content.textframe.button_frame.clearButton -text "Clear" -command {
    .nb.encryption_tab.main.output_frame.content.textframe.outputText delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 10
pack .nb.encryption_tab.main.output_frame.content.textframe.button_frame.clearButton -side left -padx 2

# Initially disable file output
selectEncryptionOutputType

# Action buttons frame - não expande
frame .nb.encryption_tab.main.action_frame -bg $bg_color
grid .nb.encryption_tab.main.action_frame -row 3 -column 0 -sticky "ew" -padx 6 -pady 12

# Encrypt and Decrypt buttons (alinhados à direita)
button .nb.encryption_tab.main.action_frame.decryptButton -text "Decrypt" -command decryptIBE \
    -bg "#28a745" -fg white -font {Arial 10 bold} -padx 20 -pady 2
pack .nb.encryption_tab.main.action_frame.decryptButton -side right -padx 5

button .nb.encryption_tab.main.action_frame.encryptButton -text "Encrypt" -command encryptIBE \
    -bg "#6c757d" -fg white -font {Arial 10 bold} -padx 20 -pady 2
pack .nb.encryption_tab.main.action_frame.encryptButton -side right -padx 5

# ========== THRESHOLD IBE TAB ==========
frame .nb.threshold_tab -bg $bg_color
.nb add .nb.threshold_tab -text " Threshold IBE "

# Main frame for content
frame .nb.threshold_tab.main -bg $bg_color
pack .nb.threshold_tab.main -fill both -expand yes -padx 6 -pady 3

# Master key setup frame
frame .nb.threshold_tab.main.master_frame -bg $frame_color -relief solid -bd 1
pack .nb.threshold_tab.main.master_frame -fill x -padx 6 -pady 3

label .nb.threshold_tab.main.master_frame.title -text "THRESHOLD MASTER KEY SETUP (5-of-5)" -font {Arial 10 bold} -bg $frame_color
pack .nb.threshold_tab.main.master_frame.title -anchor w -padx 6 -pady 2

frame .nb.threshold_tab.main.master_frame.content -bg $frame_color
pack .nb.threshold_tab.main.master_frame.content -fill x -padx 6 -pady 2

# Master public key file
label .nb.threshold_tab.main.master_frame.content.masterPublicLabel -text "Master Public:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.master_frame.content.masterPublicInput -width 45 -font {Consolas 9}

grid .nb.threshold_tab.main.master_frame.content.masterPublicLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.master_frame.content.masterPublicInput -row 0 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2

# Generate threshold master key button
button .nb.threshold_tab.main.master_frame.content.generateButton -text "Generate Threshold Master Key (5 shares)" -command generateThresholdMasterKey \
    -bg "#28a745" -fg white -font {Arial 10 bold} -pady 2
grid .nb.threshold_tab.main.master_frame.content.generateButton -row 1 -column 0 -columnspan 4 -sticky ew -padx 3 -pady 5

grid columnconfigure .nb.threshold_tab.main.master_frame.content 1 -weight 1

# Partial key generation frame
frame .nb.threshold_tab.main.partial_frame -bg $frame_color -relief solid -bd 1
pack .nb.threshold_tab.main.partial_frame -fill x -padx 6 -pady 3

label .nb.threshold_tab.main.partial_frame.title -text "PARTIAL KEY DERIVATION (from share)" -font {Arial 10 bold} -bg $frame_color
pack .nb.threshold_tab.main.partial_frame.title -anchor w -padx 6 -pady 2

frame .nb.threshold_tab.main.partial_frame.content -bg $frame_color
pack .nb.threshold_tab.main.partial_frame.content -fill x -padx 6 -pady 2

# Share file
label .nb.threshold_tab.main.partial_frame.content.shareLabel -text "Master Share:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.partial_frame.content.shareInput -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.partial_frame.content.openShareButton -text "Open" -command {
    openFileDialog .nb.threshold_tab.main.partial_frame.content.shareInput
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.partial_frame.content.shareLabel -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.shareInput -row 0 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.openShareButton -row 0 -column 3 -sticky e -padx 3 -pady 2

# User ID and HID na mesma linha
label .nb.threshold_tab.main.partial_frame.content.userIdLabel -text "User ID:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.partial_frame.content.userIdEntry -width 30 -font {Consolas 9}

label .nb.threshold_tab.main.partial_frame.content.hidLabel -text "HID:" -font {Arial 9 bold} -bg $frame_color
ttk::combobox .nb.threshold_tab.main.partial_frame.content.hidCombo -values [generateHIDValues] -state readonly -width 5
.nb.threshold_tab.main.partial_frame.content.hidCombo set "3"

grid .nb.threshold_tab.main.partial_frame.content.userIdLabel -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.userIdEntry -row 1 -column 1 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.hidLabel -row 1 -column 2 -sticky w -padx {10 3} -pady 2
grid .nb.threshold_tab.main.partial_frame.content.hidCombo -row 1 -column 3 -sticky e -padx 3 -pady 2

# Partial key output
label .nb.threshold_tab.main.partial_frame.content.partialOutputLabel -text "Partial Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.partial_frame.content.partialOutputInput -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.partial_frame.content.openPartialButton -text "Save" -command {
    set file_path [tk_getSaveFile -defaultextension ".pem" -filetypes {{"PEM files" ".pem"} {"All files" "*"}}]
    if {$file_path ne ""} {
        .nb.threshold_tab.main.partial_frame.content.partialOutputInput delete 0 end
        .nb.threshold_tab.main.partial_frame.content.partialOutputInput insert 0 $file_path
    }
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.partial_frame.content.partialOutputLabel -row 2 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.partialOutputInput -row 2 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.partial_frame.content.openPartialButton -row 2 -column 3 -sticky e -padx 3 -pady 2

# Generate partial key button
button .nb.threshold_tab.main.partial_frame.content.generatePartialButton -text "Generate Partial Key" -command generatePartialKey \
    -bg "#6c757d" -fg white -font {Arial 10 bold} -pady 2
grid .nb.threshold_tab.main.partial_frame.content.generatePartialButton -row 3 -column 0 -columnspan 4 -sticky ew -padx 3 -pady 5

grid columnconfigure .nb.threshold_tab.main.partial_frame.content 1 -weight 1

# Combine partial keys frame
frame .nb.threshold_tab.main.combine_frame -bg $frame_color -relief solid -bd 1
pack .nb.threshold_tab.main.combine_frame -fill x -padx 6 -pady 3

# Title frame with passphrase and cipher aligned to the right
frame .nb.threshold_tab.main.combine_frame.title_frame -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.title_frame -fill x -padx 6 -pady 2

label .nb.threshold_tab.main.combine_frame.title_frame.title -text "COMBINE PARTIAL KEYS (minimum 3)" \
    -font {Arial 10 bold} -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.title_frame.title -side left -anchor w

# Frame to hold passphrase and cipher aligned to the right
frame .nb.threshold_tab.main.combine_frame.title_frame.right_frame -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.title_frame.right_frame -side right -padx 10

# PRIMEIRO: Cipher (vai para a direita extrema)
ttk::combobox .nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherCombo \
    -values {"aes" "anubis" "belt" "curupira" "kuznechik" "sm4" "serpent" "twofish" "camellia" "cast256" "mars" "noekeon" "crypton"} \
    -width 10 -state readonly
.nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherCombo set "aes"
pack .nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherCombo -side right -padx {0 5}

# SEGUNDO: Cipher label (vai à esquerda do combo)
label .nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherLabel -text "Cipher:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.title_frame.right_frame.cipherLabel -side right -padx {3 0}

# TERCEIRO: Passphrase entry (vai à esquerda do cipher label)
entry .nb.threshold_tab.main.combine_frame.title_frame.right_frame.passEntry -width 12 \
    -font {Consolas 9} -show "*"
pack .nb.threshold_tab.main.combine_frame.title_frame.right_frame.passEntry -side right -padx {0 10}

# QUARTO: Passphrase label (vai à esquerda do passphrase entry)
label .nb.threshold_tab.main.combine_frame.title_frame.right_frame.passLabel -text "Passphrase:" \
    -font {Arial 9 bold} -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.title_frame.right_frame.passLabel -side right -padx {10 3}

frame .nb.threshold_tab.main.combine_frame.content -bg $frame_color
pack .nb.threshold_tab.main.combine_frame.content -fill x -padx 6 -pady 2

# Partial key 1
label .nb.threshold_tab.main.combine_frame.content.partialKey1Label -text "Partial Key 1:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.combine_frame.content.partialKey1Input -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.combine_frame.content.openPartial1Button -text "Open" -command {
    openFileDialog .nb.threshold_tab.main.combine_frame.content.partialKey1Input
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.combine_frame.content.partialKey1Label -row 0 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.partialKey1Input -row 0 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.openPartial1Button -row 0 -column 3 -sticky e -padx 3 -pady 2

# Partial key 2
label .nb.threshold_tab.main.combine_frame.content.partialKey2Label -text "Partial Key 2:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.combine_frame.content.partialKey2Input -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.combine_frame.content.openPartial2Button -text "Open" -command {
    openFileDialog .nb.threshold_tab.main.combine_frame.content.partialKey2Input
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.combine_frame.content.partialKey2Label -row 1 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.partialKey2Input -row 1 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.openPartial2Button -row 1 -column 3 -sticky e -padx 3 -pady 2

# Partial key 3
label .nb.threshold_tab.main.combine_frame.content.partialKey3Label -text "Partial Key 3:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.combine_frame.content.partialKey3Input -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.combine_frame.content.openPartial3Button -text "Open" -command {
    openFileDialog .nb.threshold_tab.main.combine_frame.content.partialKey3Input
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.combine_frame.content.partialKey3Label -row 2 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.partialKey3Input -row 2 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.openPartial3Button -row 2 -column 3 -sticky e -padx 3 -pady 2

# Output key
label .nb.threshold_tab.main.combine_frame.content.outputKeyLabel -text "Output Key:" -font {Arial 9 bold} -bg $frame_color
entry .nb.threshold_tab.main.combine_frame.content.outputKeyInput -width 40 -font {Consolas 9}
button .nb.threshold_tab.main.combine_frame.content.openOutputButton -text "Save" -command {
    set file_path [tk_getSaveFile -defaultextension ".pem" -filetypes {{"PEM files" ".pem"} {"All files" "*"}}]
    if {$file_path ne ""} {
        .nb.threshold_tab.main.combine_frame.content.outputKeyInput delete 0 end
        .nb.threshold_tab.main.combine_frame.content.outputKeyInput insert 0 $file_path
    }
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 8

grid .nb.threshold_tab.main.combine_frame.content.outputKeyLabel -row 3 -column 0 -sticky w -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.outputKeyInput -row 3 -column 1 -columnspan 2 -sticky ew -padx 3 -pady 2
grid .nb.threshold_tab.main.combine_frame.content.openOutputButton -row 3 -column 3 -sticky e -padx 3 -pady 2

# Combine button
button .nb.threshold_tab.main.combine_frame.content.combineButton -text "Combine Partial Keys (3-of-5)" -command combinePartialKeys \
    -bg "#fd7e14" -fg white -font {Arial 10 bold} -pady 2
grid .nb.threshold_tab.main.combine_frame.content.combineButton -row 4 -column 0 -columnspan 4 -sticky ew -padx 3 -pady 5

grid columnconfigure .nb.threshold_tab.main.combine_frame.content 1 -weight 1

# Output frame (diminuído)
frame .nb.threshold_tab.main.output_frame -bg $frame_color -relief solid -bd 1
pack .nb.threshold_tab.main.output_frame -fill both -expand true -padx 6 -pady 3

# Create output text area (diminuída)
frame .nb.threshold_tab.main.output_frame.textframe -bg $frame_color
pack .nb.threshold_tab.main.output_frame.textframe -fill both -expand true -padx 6 -pady 2

text .nb.threshold_tab.main.output_frame.textframe.outputArea -width 70 -height 1 -wrap word \
    -font {Consolas 9} -bg $text_bg -relief solid -bd 1
scrollbar .nb.threshold_tab.main.output_frame.textframe.yscroll -orient vertical \
    -command {.nb.threshold_tab.main.output_frame.textframe.outputArea yview}
.nb.threshold_tab.main.output_frame.textframe.outputArea configure \
    -yscrollcommand {.nb.threshold_tab.main.output_frame.textframe.yscroll set}

grid .nb.threshold_tab.main.output_frame.textframe.outputArea -row 0 -column 0 -sticky "nsew"
grid .nb.threshold_tab.main.output_frame.textframe.yscroll -row 0 -column 1 -sticky "ns"

grid rowconfigure .nb.threshold_tab.main.output_frame.textframe 0 -weight 1
grid columnconfigure .nb.threshold_tab.main.output_frame.textframe 0 -weight 1

# Utility buttons
frame .nb.threshold_tab.main.output_frame.utility_buttons -bg $frame_color
pack .nb.threshold_tab.main.output_frame.utility_buttons -fill x -padx 6 -pady 2

button .nb.threshold_tab.main.output_frame.utility_buttons.copyButton -text "Copy" -command {
    copyText [.nb.threshold_tab.main.output_frame.textframe.outputArea get 1.0 end]
} -bg "#6c757d" -fg white -font {Arial 9 bold} -padx 10
pack .nb.threshold_tab.main.output_frame.utility_buttons.copyButton -side left -padx 2

button .nb.threshold_tab.main.output_frame.utility_buttons.clearButton -text "Clear" -command {
    .nb.threshold_tab.main.output_frame.textframe.outputArea delete 1.0 end
} -bg "#dc3545" -fg white -font {Arial 9 bold} -padx 10
pack .nb.threshold_tab.main.output_frame.utility_buttons.clearButton -side left -padx 2

# ===== MENU BAR =====
menu .menubar -tearoff 0 -bg $accent_color -fg white -activebackground $button_hover
. configure -menu .menubar

.menubar add command -label "About" -command showAboutIBE

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

.menubar add command -label "Exit" -command exit

# Footer
frame .footer -bg $accent_color -height 20  ;# Reduzido de 25 para 20
pack .footer -fill x
label .footer.text -text "ALBANESE Research Lab \u00a9 2025 | Identity-Based Cryptography" \
    -bg $accent_color -fg "#bdc3c7" -font {Arial 8}
pack .footer.text -pady 2  ;# Reduzido pady

# Configure resizing
grid columnconfigure .nb.keys_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.keys_tab.main.user_frame.content 1 -weight 1
grid columnconfigure .nb.keys_tab.main.parse_frame.content 1 -weight 1

grid columnconfigure .nb.signatures_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.signatures_tab.main.input_frame.content 3 -weight 1

grid columnconfigure .nb.encryption_tab.main.keys_frame.content 1 -weight 1
grid columnconfigure .nb.encryption_tab.main.input_frame.content 3 -weight 1
grid columnconfigure .nb.encryption_tab.main.output_frame.content 3 -weight 1

grid columnconfigure .nb.threshold_tab.main.master_frame.content 1 -weight 1
grid columnconfigure .nb.threshold_tab.main.partial_frame.content 1 -weight 1
grid columnconfigure .nb.threshold_tab.main.combine_frame.content 1 -weight 1

# Bind tab change to update UI
bind .nb <<NotebookTabChanged>> updateKeyTabUI

# Start the event loop
tkwait visibility .
