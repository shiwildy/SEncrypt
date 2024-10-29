# SEncrypt
A secure and simple encryption library using SHA-512, AES-256-CBC, and BASE64.

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

    } catch (RuntimeException $e) {
        echo "An error occurred: " . $e->getMessage() . "\n";
    }
?>
```

## License
This project licensed under The MIT License