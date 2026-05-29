<?php

use Bitrix\Main\Loader;

if (!defined('B_PROLOG_INCLUDED') || B_PROLOG_INCLUDED !== true) {
    die();
}

if (!defined('DELEMENT_ANTIVIRUS_MODULE_ID')) {
    define('DELEMENT_ANTIVIRUS_MODULE_ID', 'delement.antivirus');
}

Loader::registerAutoLoadClasses(
    DELEMENT_ANTIVIRUS_MODULE_ID,
    []
);
