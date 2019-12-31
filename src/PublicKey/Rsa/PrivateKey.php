<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\PublicKey\Rsa;

/**
 * RSA private key
 *
 * @category   Laminas
 * @package    Laminas_Crypt
 * @subpackage PublicKey
 */
class PrivateKey extends AbstractKey
{
    /**
     * Public key
     *
     * @var PublicKey
     */
    protected $publicKey = null;

    /**
     * Create private key instance from PEM formatted key file
     *
     * @param  string      $pemFile
     * @param  string|null $passPhrase
     * @return PrivateKey
     * @throws Exception\InvalidArgumentException
     */
    public static function fromFile($pemFile, $passPhrase = null)
    {
        if (!is_readable($pemFile)) {
            throw new Exception\InvalidArgumentException(
                "PEM file '{$pemFile}' is not readable"
            );
        }

        return new static(file_get_contents($pemFile), $passPhrase);
    }

    /**
     * Constructor
     *
     * @param  string $pemString
     * @param  string $passPhrase
     * @throws Exception\RuntimeException
     */
    public function __construct($pemString, $passPhrase = null)
    {
        $result = openssl_pkey_get_private($pemString, $passPhrase);
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Unable to load private key; openssl ' . openssl_error_string()
            );
        }

        $this->pemString          = $pemString;
        $this->opensslKeyResource = $result;
        $this->details            = openssl_pkey_get_details($this->opensslKeyResource);
    }

    /**
     * Get the public key
     *
     * @return PublicKey
     */
    public function getPublicKey()
    {
        if ($this->publicKey === null) {
            $this->publicKey = new PublicKey($this->details['key']);
        }

        return $this->publicKey;
    }

    /**
     * Encrypt using this key
     *
     * @param  string $data
     * @return string
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function encrypt($data)
    {
        if (empty($data)) {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }

        $encrypted = '';
        $result = openssl_private_encrypt($data, $encrypted, $this->getOpensslKeyResource());
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not encrypt; openssl ' . openssl_error_string()
            );
        }

        return $encrypted;
    }

    /**
     * Decrypt using this key
     *
     * @param  string $data
     * @return string
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function decrypt($data)
    {
        if (!is_string($data)) {
            throw new Exception\InvalidArgumentException('The data to decrypt must be a string');
        }
        if ('' === $data) {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }

        $decrypted = '';
        $result = openssl_private_decrypt($data, $decrypted, $this->getOpensslKeyResource());
        if (false === $result) {
            throw new Exception\RuntimeException(
                'Can not decrypt; openssl ' . openssl_error_string()
            );
        }

        return $decrypted;
    }

    /**
     * @return string
     */
    public function toString()
    {
        return $this->pemString;
    }
}
