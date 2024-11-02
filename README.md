# SEncrypt
SEncrypt is a secure & simple encryption library using SHA-512, AES-256-CBC, and BASE64. It provides easy-to-use methods for encrypting and decrypting data securely.

## Installation
```bash
composer require shiwildy/sencrypt
```

## Example
```php
<?php
    require 'vendor/autoload.php';
    use ShiWildy\SEncrypt;

    $plaintext = "Hello, just testing..";
    $password = "secret";

    try {
        $encrypted = SEncrypt::encrypt($plaintext, $password);
        echo "Encrypted: " . $encrypted . "\n\n";

        $decrypted = SEncrypt::decrypt($encrypted, $password);
        echo "Decrypted: " . $decrypted . "\n\n";

    } catch (Exception $e) {
        echo "An error occurred: " . $e->getMessage() . "\n";
    }
?>
```

## How It Works ?
### Encryption:
- Salt Generation: A random salt generated to enhance security.
- Key Derivation: Encryption key is derived from the provided password and generated salt using PBKDF2 Algoritm with SHA-512
- IV Generation: A random initialization vector [IV] generated for use on AES-256-CBC
- Combining Data: Salt, IV, and encrypted data are concatenated and then encoded using base64 to create final encrypted output.

### Decryption:
- Base64 Decode: Encrypted data is first decoded from Base64.
- Data Extraction: salt, IV, and encrypted text are extracted from decoded data.
- Key Derivation: Decryption key is derived using same method in encryption.
- Decryption: Encrypted data is decrypted using derived key and IV.
- Output: Decrypted text returned.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project licensed under The MIT License

## Credits
- https://www.php.net/manual/en/function.hash-pbkdf2.php
- https://www.tutorialspoint.com/php/php_function_hash_pdkdf2.htm
- https://www.php.net/manual/en/function.openssl-pbkdf2.php
- https://stackoverflow.com/questions/12766852/pbkdf2-password-hashing-for-php
- https://ppgia.pucpr.br/pt/arquivos/techdocs/php/function.hash-pbkdf2.html
- https://nishothan-17.medium.com/pbkdf2-hashing-algorithm-841d5cc9178d
