use std::str::FromStr;

use secp256k1::{Secp256k1, SecretKey};

fn main() {
    let secret =
        SecretKey::from_str("df343190df7ce6c4fa20f5bf6605dea426b1ffc6f4a0ca93c08fdf19c3146ae6")
            .unwrap();
    println!("{secret:?}");
    let secp = Secp256k1::new();
    let pubkey = secret.public_key(&secp);
    println!("{:#2x?}", pubkey.serialize_uncompressed());
}
