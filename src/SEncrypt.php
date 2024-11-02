<?php

//
// SEncrypt
// A secure and simple encryption library using SHA-512, AES-256-CBC, and BASE64.
//
// Author  : Wildy Sheverando <hai@shiwildy.com>
// Version : 1.0
//
// https://github.com/shiwildy/SEncrypt.git
// 
// This project Licensed under The MIT License.
//

namespace ShiWildy;

class SEncrypt {
    private const CIPHER = 'aes-256-cbc';
    private const PBKDF2_ITERATIONS = 1000;
    private const KEY_LENGTH = 32; // 256-bit key for AES-256
    private const IV_LENGTH = 16; // 128-bit IV Length for AES-256-CBC

    /**
     * Encrypts a plaintext string using AES-256-CBC with a derived key.
     *
     * @param string $plaintext The data to encrypt.
     * @param string $password The password to derive encryption keys.
     * @return string Base64-encoded encrypted data.
     * @throws Exception If encryption fails.
     */
    public static function encrypt(string $plaintext, string $password): string {
        try {
            // Generate a random salt
            $salt = random_bytes(self::KEY_LENGTH);

            // Derive encryption key
            $key = hash_pbkdf2(
                'sha512',
                $password,
                $salt,
                self::PBKDF2_ITERATIONS,
                self::KEY_LENGTH,
                true
            );

            // Generate a random IV key
            $iv = random_bytes(self::IV_LENGTH);

            // Encrypt using openssl_encrypt functions
            $encrypted = openssl_encrypt(
                $plaintext,
                self::CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encrypted === false) {
                throw new \Exception('Encryption failed.');
            }

            // Combine salt, iv, encrypted then base64 encode
            return base64_encode($salt . $iv . $encrypted);

        } catch (Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }
    
    /**
     * Decrypts a Base64-encoded encrypted string using AES-256-CBC with a derived key.
     *
     * @param string $encryptedBase64 The Base64-encoded encrypted data.
     * @param string $password The password to derive decryption keys.
     * @return string The decrypted plaintext.
     * @throws Exception If decryption fails.
     */
    public static function decrypt(string $encryptedBase64, string $password): string {
        try {
            // Decode base64
            $combined = base64_decode($encryptedBase64, true);
            if ($combined === false) {
                throw new \Exception('Cannot decode base64.');
            }

            // Extract salt, iv, encrypted from combined
            $salt = substr($combined, 0, self::KEY_LENGTH);
            $iv = substr($combined, self::KEY_LENGTH, self::IV_LENGTH);
            $ciphertext = substr($combined, self::KEY_LENGTH + self::IV_LENGTH);

            if ($salt === false || $iv === false || $ciphertext === false) {
                throw new \Exception('Encrypted format is invalid.');
            }

            // Derive decryption key
            $key = hash_pbkdf2(
                'sha512',
                $password,
                $salt,
                self::PBKDF2_ITERATIONS,
                self::KEY_LENGTH,
                true
            );
            
            // Decrypt encrypted text
            $decrypted = openssl_decrypt(
                $ciphertext,
                self::CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            
            if ($decrypted === false) {
                throw new \Exception('Decryption failed.');
            }
            
            return $decrypted;
        } catch (Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }
}

?>
