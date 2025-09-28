mod kyber;
mod sender;
mod receiver;
pub mod generate_keypair;

use std::io::{self, Write};

fn main() {
    println!("=== Noid Kyber + AES-GCM Interactive Demo ===\n");
    
    // Generate keypair for receiver
    println!("🔑 Generating Kyber1024 keypair...");
    let (pk, sk) = generate_keypair::generate_keypair();
    println!("✓ Keypair generated!");
    println!("  - Public key length: {} bytes", pk.len());
    println!("  - Secret key length: {} bytes\n", sk.len());
    
    loop {
        // Get user input
        print("💬 Enter message to encrypt (or 'quit' to exit): ");
        
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let message = input.trim();
                
                if message.is_empty() {
                    continue;
                }
                
                if message.to_lowercase() == "quit" {
                    println!("👋 Goodbye!");
                    break;
                }
                
                // Encrypt the message
                println!("\n🔒 Encrypting message...");
                let (aes_ciphertext, nonce, kyber_ciphertext) = sender::send_message(message.as_bytes(), &pk);
                
                println!("✓ Encryption complete!");
                println!("  - Original message: \"{}\"", message);
                println!("  - AES ciphertext length: {} bytes", aes_ciphertext.len());
                println!("  - Nonce length: {} bytes", nonce.len());
                println!("  - Kyber ciphertext length: {} bytes", kyber_ciphertext.len());
                
                // Decrypt the message
                println!("\n🔓 Decrypting message...");
                match std::panic::catch_unwind(|| {
                    receiver::receive_message(&aes_ciphertext, &nonce, &kyber_ciphertext, &sk)
                }) {
                    Ok(decrypted) => {
                        let decrypted_text = String::from_utf8_lossy(&decrypted);
                        println!("✓ Decryption successful!");
                        println!("  - Decrypted message: \"{}\"", decrypted_text);
                        
                        // Verify the messages match
                        if message == decrypted_text {
                            println!("✅ Messages match perfectly!\n");
                        } else {
                            println!("❌ Warning: Messages don't match!\n");
                        }
                    }
                    Err(_) => {
                        println!("❌ Decryption failed. Possibly bad keys or corrupted ciphertext.\n");
                    }
                }
                
                println!("{}", "─".repeat(50));
            }
            Err(error) => {
                println!("❌ Error reading input: {}", error);
                break;
            }
        }
    }
}

fn print(msg: &str) {
    print!("{}", msg);
    io::stdout().flush().unwrap();
}
