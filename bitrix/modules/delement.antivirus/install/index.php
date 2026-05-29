<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Localization\Loc;

if (!defined('B_PROLOG_INCLUDED') || B_PROLOG_INCLUDED !== true) {
    die();
}

Loc::loadMessages(__FILE__);

class delement_antivirus extends CModule
{
    public function __construct()
    {
        $arModuleVersion = [];
        include __DIR__ . '/version.php';

        $this->MODULE_ID = 'delement.antivirus';
        $this->MODULE_VERSION = isset($arModuleVersion['VERSION']) ? $arModuleVersion['VERSION'] : '0.0.1';
        $this->MODULE_VERSION_DATE = isset($arModuleVersion['VERSION_DATE']) ? $arModuleVersion['VERSION_DATE'] : '2026-05-29 00:00:00';
        $this->MODULE_NAME = Loc::getMessage('DELEMENT_ANTIVIRUS_MODULE_NAME');
        $this->MODULE_DESCRIPTION = Loc::getMessage('DELEMENT_ANTIVIRUS_MODULE_DESCRIPTION');
        $this->PARTNER_NAME = Loc::getMessage('DELEMENT_ANTIVIRUS_PARTNER_NAME');
        $this->PARTNER_URI = Loc::getMessage('DELEMENT_ANTIVIRUS_PARTNER_URI');
        $this->MODULE_GROUP_RIGHTS = 'Y';
    }

    public function DoInstall()
    {
        global $APPLICATION;

        if (!check_bitrix_sessid()) {
            return false;
        }

        RegisterModule($this->MODULE_ID);
        $this->InstallFiles();

        $APPLICATION->IncludeAdminFile(
            Loc::getMessage('DELEMENT_ANTIVIRUS_INSTALL_TITLE'),
            __DIR__ . '/step.php'
        );

        return true;
    }

    public function DoUninstall()
    {
        global $APPLICATION;

        if (!check_bitrix_sessid()) {
            return false;
        }

        $this->UnInstallFiles();
        Option::delete($this->MODULE_ID);
        UnRegisterModule($this->MODULE_ID);

        $APPLICATION->IncludeAdminFile(
            Loc::getMessage('DELEMENT_ANTIVIRUS_UNINSTALL_TITLE'),
            __DIR__ . '/unstep.php'
        );

        return true;
    }

    public function InstallFiles()
    {
        $documentRoot = $this->getDocumentRoot();

        CopyDirFiles(__DIR__ . '/admin', $documentRoot . '/bitrix/admin', true, true);
        CopyDirFiles(__DIR__ . '/js', $documentRoot . '/bitrix/js/' . $this->MODULE_ID, true, true);
        CopyDirFiles(__DIR__ . '/css', $documentRoot . '/bitrix/css/' . $this->MODULE_ID, true, true);
        CopyDirFiles(__DIR__ . '/tools', $documentRoot . '/bitrix/tools/' . $this->MODULE_ID, true, true);

        return true;
    }

    public function UnInstallFiles()
    {
        $documentRoot = $this->getDocumentRoot();

        DeleteDirFiles(__DIR__ . '/admin', $documentRoot . '/bitrix/admin');
        DeleteDirFilesEx('/bitrix/js/' . $this->MODULE_ID);
        DeleteDirFilesEx('/bitrix/css/' . $this->MODULE_ID);
        DeleteDirFilesEx('/bitrix/tools/' . $this->MODULE_ID);

        return true;
    }

    private function getDocumentRoot()
    {
        return rtrim($_SERVER['DOCUMENT_ROOT'], '/\\');
    }
}
