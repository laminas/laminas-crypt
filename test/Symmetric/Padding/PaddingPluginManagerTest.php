<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric\Padding;

use Interop\Container\ContainerInterface;
use Laminas\Crypt\Symmetric\Padding\PaddingInterface;
use Laminas\Crypt\Symmetric\PaddingPluginManager;

class PaddingPluginManagerTest extends \PHPUnit_Framework_TestCase
{
    public function getPaddings()
    {
        return [
            [ 'pkcs7' ],
            [ 'nopadding' ],
            [ 'null' ],
        ];
    }

    public function testConstruct()
    {
        $plugin = new PaddingPluginManager();
        $this->assertInstanceof(ContainerInterface::class, $plugin);
    }

    /**
     * @dataProvider getPaddings
     */
    public function testHas($padding)
    {
        $plugin = new PaddingPluginManager();
        $this->assertTrue($plugin->has($padding));
    }

    /**
     * @dataProvider getPaddings
     */
    public function testGet($padding)
    {
        $plugin = new PaddingPluginManager();
        $this->assertInstanceof(PaddingInterface::class, $plugin->get($padding));
    }

    /**
     * @expectedException Laminas\Crypt\Symmetric\Exception\NotFoundException
     */
    public function testGetError()
    {
        $plugin = new PaddingPluginManager();
        $plugin->get('foo');
    }
}
