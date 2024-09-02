use std::io::Write;

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

// a password stored in a database
const PASSWORD: &str = "password";

fn main() {
    // simple inputs reading lines, which is irrelevant with Argon2
    // use actix web, axum, rocket, or other Rust web framework instead
    print!("Enter password: ");
    std::io::stdout().flush().unwrap();
    let mut password = String::new();
    std::io::stdin().read_line(&mut password).expect("Failed to read password");
    let password = password.trim();

    // simple Argon2 logic down below
    // hash passwords
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    println!("Hashed password: {}", password_hash);

    // verify hashed password and see if the password you entered is valid 
    let parsed_hash = PasswordHash::new(&password_hash)
        .expect("Failed to parse hash");
    let is_valid = argon2.verify_password(PASSWORD.as_bytes(), &parsed_hash).is_ok();

    println!("Original password you entered: {}", password);
    println!("You are authorized: {}", is_valid)
}