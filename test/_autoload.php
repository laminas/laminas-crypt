<?php

use PHPUnit\Framework\Error\Deprecated;
use PHPUnit\Framework\Error\Error;

if (class_exists(PHPUnit_Framework_Error::class)) {
    class_alias(PHPUnit_Framework_Error::class, Error::class);
}

if (class_exists(PHPUnit_Framework_Error_Deprecated::class)) {
    class_alias(PHPUnit_Framework_Error_Deprecated::class, Deprecated::class);
}
