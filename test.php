<?php
    require "vendor/autoload.php";
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
