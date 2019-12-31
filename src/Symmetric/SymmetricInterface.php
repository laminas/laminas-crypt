<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Symmetric;

interface SymmetricInterface
{
    /**
     * @param string $data
     */
    public function encrypt($data);

    /**
     * @param string $data
     */
    public function decrypt($data);

    /**
     * @param string $key
     */
    public function setKey($key);

    public function getKey();

    public function getKeySize();

    public function getAlgorithm();

    /**
     * @param  string $algo
     */
    public function setAlgorithm($algo);

    public function getSupportedAlgorithms();

    /**
     * @param string|false $salt
     */
    public function setSalt($salt);

    public function getSalt();

    public function getSaltSize();

    public function getBlockSize();

    /**
     * @param string $mode
     */
    public function setMode($mode);

    public function getMode();

    public function getSupportedModes();
}
