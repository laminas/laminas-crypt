<?php

if (class_exists(\PHPUnit_Framework_Error::class)) {
    class_alias(\PHPUnit_Framework_Error::class, \PHPUnit\Framework\Error\Error::class);
}

if (class_exists(\PHPUnit_Framework_Error_Deprecated::class)) {
    class_alias(\PHPUnit_Framework_Error_Deprecated::class, \PHPUnit\Framework\Error\Deprecated::class);
}
