<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Symmetric;

use Psr\Container\ContainerInterface;
use Laminas\Stdlib\ArrayUtils;
use Traversable;

use function array_key_exists;
use function array_keys;
use function class_exists;
use function extension_loaded;
use function get_class;
use function gettype;
use function implode;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use function is_subclass_of;
use function mb_strlen;
use function mb_substr;
use function mcrypt_decrypt;
use function mcrypt_encrypt;
use function mcrypt_get_block_size;
use function mcrypt_get_iv_size;
use function mcrypt_get_key_size;
use function mcrypt_module_get_supported_key_sizes;
use function sprintf;
use function strtolower;
use function trigger_error;

use const PHP_VERSION_ID;

/**
 * Symmetric encryption using the Mcrypt extension
 *
 * NOTE: DO NOT USE only this class to encrypt data.
 * This class doesn't provide authentication and integrity check over the data.
 * PLEASE USE Laminas\Crypt\BlockCipher instead!
 */
class Mcrypt implements SymmetricInterface
{
    const DEFAULT_PADDING = 'pkcs7';

    /**
     * Key
     *
     * @var string
     */
    protected $key;

    /**
     * IV
     *
     * @var string
     */
    protected $iv;

    /**
     * Encryption algorithm
     *
     * @var string
     */
    protected $algo = 'aes';

    /**
     * Encryption mode
     *
     * @var string
     */
    protected $mode = 'cbc';

    /**
     * Padding
     *
     * @var Padding\PaddingInterface
     */
    protected $padding;

    /**
     * Padding plugins
     *
     * @var Psr\Container\ContainerInterface
     */
    protected static $paddingPlugins = null;

    /**
     * Supported cipher algorithms
     *
     * @var array
     */
    protected $supportedAlgos = [
        'aes'          => 'rijndael-128',
        'blowfish'     => 'blowfish',
        'des'          => 'des',
        '3des'         => 'tripledes',
        'tripledes'    => 'tripledes',
        'cast-128'     => 'cast-128',
        'cast-256'     => 'cast-256',
        'rijndael-128' => 'rijndael-128',
        'rijndael-192' => 'rijndael-192',
        'rijndael-256' => 'rijndael-256',
        'saferplus'    => 'saferplus',
        'serpent'      => 'serpent',
        'twofish'      => 'twofish'
    ];

    /**
     * Supported encryption modes
     *
     * @var array
     */
    protected $supportedModes = [
        'cbc'  => 'cbc',
        'cfb'  => 'cfb',
        'ctr'  => 'ctr',
        'ofb'  => 'ofb',
        'nofb' => 'nofb',
        'ncfb' => 'ncfb'
    ];

    /**
     * Constructor
     *
     * @param  array|Traversable                  $options
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function __construct($options = [])
    {
        if (PHP_VERSION_ID >= 70100) {
            trigger_error(
                'The Mcrypt extension is deprecated from PHP 7.1+. '
                . 'We suggest to use Laminas\Crypt\Symmetric\Openssl.',
                E_USER_DEPRECATED
            );
        }
        if (! extension_loaded('mcrypt')) {
            throw new Exception\RuntimeException(sprintf(
                'You cannot use %s without the Mcrypt extension',
                __CLASS__
            ));
        }
        $this->setOptions($options);
        $this->setDefaultOptions($options);
    }

    /**
     * Set default options
     *
     * @param  array $options
     * @return void
     */
    public function setOptions($options)
    {
        if (! empty($options)) {
            if ($options instanceof Traversable) {
                $options = ArrayUtils::iteratorToArray($options);
            } elseif (! is_array($options)) {
                throw new Exception\InvalidArgumentException(
                    'The options parameter must be an array or a Traversable'
                );
            }
            foreach ($options as $key => $value) {
                switch (strtolower($key)) {
                    case 'algo':
                    case 'algorithm':
                        $this->setAlgorithm($value);
                        break;
                    case 'mode':
                        $this->setMode($value);
                        break;
                    case 'key':
                        $this->setKey($value);
                        break;
                    case 'iv':
                    case 'salt':
                        $this->setSalt($value);
                        break;
                    case 'padding':
                        $plugins       = static::getPaddingPluginManager();
                        $padding       = $plugins->get($value);
                        $this->padding = $padding;
                        break;
                }
            }
        }
    }

    /**
     * Set default options
     *
     * @param  array $options
     * @return void
     */
    protected function setDefaultOptions($options = [])
    {
        if (! isset($options['padding'])) {
            $plugins       = static::getPaddingPluginManager();
            $padding       = $plugins->get(self::DEFAULT_PADDING);
            $this->padding = $padding;
        }
    }

    /**
     * Returns the padding plugin manager.  If it doesn't exist it's created.
     *
     * @return ContainerInterface
     */
    public static function getPaddingPluginManager()
    {
        if (static::$paddingPlugins === null) {
            self::setPaddingPluginManager(new PaddingPluginManager());
        }

        return static::$paddingPlugins;
    }

    /**
     * Set the padding plugin manager
     *
     * @param  string|ContainerInterface $plugins
     * @throws Exception\InvalidArgumentException
     * @return void
     */
    public static function setPaddingPluginManager($plugins)
    {
        if (is_string($plugins)) {
            if (! class_exists($plugins) || ! is_subclass_of($plugins, ContainerInterface::class)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'Unable to locate padding plugin manager via class "%s"; '
                    . 'class does not exist or does not implement ContainerInterface',
                    $plugins
                ));
            }
            $plugins = new $plugins();
        }
        if (! $plugins instanceof ContainerInterface) {
            throw new Exception\InvalidArgumentException(sprintf(
                'Padding plugins must implement Psr\Container\ContainerInterface; received "%s"',
                is_object($plugins) ? get_class($plugins) : gettype($plugins)
            ));
        }
        static::$paddingPlugins = $plugins;
    }

    /**
     * Get the maximum key size for the selected cipher and mode of operation
     *
     * @return int
     */
    public function getKeySize()
    {
        return mcrypt_get_key_size($this->supportedAlgos[$this->algo], $this->supportedModes[$this->mode]);
    }

    /**
     * Set the encryption key
     * If the key is longer than maximum supported, it will be truncated by getKey().
     *
     * @param  string $key
     * @return Mcrypt Provides a fluent interface
     * @throws Exception\InvalidArgumentException
     */
    public function setKey($key)
    {
        $keyLen = mb_strlen($key, '8bit');

        if (! $keyLen) {
            throw new Exception\InvalidArgumentException('The key cannot be empty');
        }
        $keySizes = mcrypt_module_get_supported_key_sizes($this->supportedAlgos[$this->algo]);
        $maxKey = $this->getKeySize();

        /*
         * blowfish has $keySizes empty, meaning it can have arbitrary key length.
         * the others are more picky.
         */
        if (! empty($keySizes) && $keyLen < $maxKey) {
            if (! in_array($keyLen, $keySizes)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'The size of the key must be %s bytes or longer',
                    implode(', ', $keySizes)
                ));
            }
        }
        $this->key = $key;

        return $this;
    }

    /**
     * Get the encryption key
     *
     * @return string
     */
    public function getKey()
    {
        if (empty($this->key)) {
            return;
        }
        return mb_substr($this->key, 0, $this->getKeySize(), '8bit');
    }

    /**
     * Set the encryption algorithm (cipher)
     *
     * @param  string $algo
     * @return Mcrypt Provides a fluent interface
     * @throws Exception\InvalidArgumentException
     */
    public function setAlgorithm($algo)
    {
        if (! array_key_exists($algo, $this->supportedAlgos)) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The algorithm %s is not supported by %s',
                $algo,
                __CLASS__
            ));
        }
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the encryption algorithm
     *
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algo;
    }

    /**
     * Set the padding object
     *
     * @param  Padding\PaddingInterface $padding
     * @return Mcrypt Provides a fluent interface
     */
    public function setPadding(Padding\PaddingInterface $padding)
    {
        $this->padding = $padding;

        return $this;
    }

    /**
     * Get the padding object
     *
     * @return Padding\PaddingInterface
     */
    public function getPadding()
    {
        return $this->padding;
    }

    /**
     * Encrypt
     *
     * @param  string $data
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public function encrypt($data)
    {
        // Cannot encrypt empty string
        if (! is_string($data) || $data === '') {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }
        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No key specified for the encryption');
        }
        if (null === $this->getSalt()) {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }
        if (null === $this->getPadding()) {
            throw new Exception\InvalidArgumentException('You have to specify a padding method');
        }
        // padding
        $data = $this->padding->pad($data, $this->getBlockSize());
        $iv   = $this->getSalt();
        // encryption
        $result = mcrypt_encrypt(
            $this->supportedAlgos[$this->algo],
            $this->getKey(),
            $data,
            $this->supportedModes[$this->mode],
            $iv
        );

        return $iv . $result;
    }

    /**
     * Decrypt
     *
     * @param  string                             $data
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public function decrypt($data)
    {
        if (empty($data)) {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }
        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No key specified for the decryption');
        }
        if (null === $this->getPadding()) {
            throw new Exception\InvalidArgumentException('You have to specify a padding method');
        }
        $iv         = mb_substr($data, 0, $this->getSaltSize(), '8bit');
        $ciphertext = mb_substr($data, $this->getSaltSize(), null, '8bit');
        $result     = mcrypt_decrypt(
            $this->supportedAlgos[$this->algo],
            $this->getKey(),
            $ciphertext,
            $this->supportedModes[$this->mode],
            $iv
        );
        // unpadding
        return $this->padding->strip($result);
    }

    /**
     * Get the salt (IV) size
     *
     * @return int
     */
    public function getSaltSize()
    {
        return mcrypt_get_iv_size($this->supportedAlgos[$this->algo], $this->supportedModes[$this->mode]);
    }

    /**
     * Get the supported algorithms
     *
     * @return array
     */
    public function getSupportedAlgorithms()
    {
        return array_keys($this->supportedAlgos);
    }

    /**
     * Set the salt (IV)
     *
     * @param  string $salt
     * @return Mcrypt Provides a fluent interface
     * @throws Exception\InvalidArgumentException
     */
    public function setSalt($salt)
    {
        if (empty($salt)) {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }
        if (mb_strlen($salt, '8bit') < $this->getSaltSize()) {
            throw new Exception\InvalidArgumentException(sprintf(
                'The size of the salt (IV) must be at least %d bytes',
                $this->getSaltSize()
            ));
        }
        $this->iv = $salt;

        return $this;
    }

    /**
     * Get the salt (IV) according to the size requested by the algorithm
     *
     * @return string
     */
    public function getSalt()
    {
        if (empty($this->iv)) {
            return;
        }
        if (mb_strlen($this->iv, '8bit') < $this->getSaltSize()) {
            throw new Exception\RuntimeException(sprintf(
                'The size of the salt (IV) must be at least %d bytes',
                $this->getSaltSize()
            ));
        }

        return mb_substr($this->iv, 0, $this->getSaltSize(), '8bit');
    }

    /**
     * Get the original salt value
     *
     * @return string
     */
    public function getOriginalSalt()
    {
        return $this->iv;
    }

    /**
     * Set the cipher mode
     *
     * @param  string $mode
     * @return Mcrypt Provides a fluent interface
     * @throws Exception\InvalidArgumentException
     */
    public function setMode($mode)
    {
        if (! empty($mode)) {
            $mode = strtolower($mode);
            if (! array_key_exists($mode, $this->supportedModes)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'The mode %s is not supported by %s',
                    $mode,
                    $this->algo
                ));
            }
            $this->mode = $mode;
        }

        return $this;
    }

    /**
     * Get the cipher mode
     *
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * Get all supported encryption modes
     *
     * @return array
     */
    public function getSupportedModes()
    {
        return array_keys($this->supportedModes);
    }

    /**
     * Get the block size
     *
     * @return int
     */
    public function getBlockSize()
    {
        return mcrypt_get_block_size($this->supportedAlgos[$this->algo], $this->supportedModes[$this->mode]);
    }
}
