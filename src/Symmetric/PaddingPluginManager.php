<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Symmetric;

use Laminas\ServiceManager\AbstractPluginManager;

/**
 * Plugin manager implementation for the padding adapter instances.
 *
 * Enforces that padding adapters retrieved are instances of
 * Padding\PaddingInterface. Additionally, it registers a number of default
 * padding adapters available.
 *
 * @category   Laminas
 * @package    Laminas_Crypt
 * @subpackage Symmetric
 */
class PaddingPluginManager extends AbstractPluginManager
{
    /**
     * Default set of padding adapters
     *
     * @var array
     */
    protected $invokableClasses = array(
        'pkcs7' => 'Laminas\Crypt\Symmetric\Padding\Pkcs7'
    );

    /**
     * Do not share by default
     *
     * @var bool
     */
    protected $shareByDefault = false;

    /**
     * Validate the plugin
     *
     * Checks that the padding adapter loaded is an instance of Padding\PaddingInterface.
     *
     * @param  mixed $plugin
     * @return void
     * @throws Exception\InvalidArgumentException if invalid
     */
    public function validatePlugin($plugin)
    {
        if ($plugin instanceof Padding\PaddingInterface) {
            // we're okay
            return;
        }

        throw new Exception\InvalidArgumentException(sprintf(
            'Plugin of type %s is invalid; must implement %s\Padding\PaddingInterface',
            (is_object($plugin) ? get_class($plugin) : gettype($plugin)),
            __NAMESPACE__
        ));
    }
}
