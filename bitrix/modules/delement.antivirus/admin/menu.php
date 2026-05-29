<?php

use Bitrix\Main\Localization\Loc;

if (!defined('B_PROLOG_INCLUDED') || B_PROLOG_INCLUDED !== true) {
    die();
}

$moduleId = 'delement.antivirus';

if ($APPLICATION->GetGroupRight($moduleId) < 'R') {
    return false;
}

Loc::loadMessages(__FILE__);

return [
    'parent_menu' => 'global_menu_services',
    'section' => 'delement_antivirus',
    'sort' => 900,
    'text' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_TEXT'),
    'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_TITLE'),
    'icon' => 'sys_menu_icon',
    'page_icon' => 'sys_page_icon',
    'items_id' => 'menu_delement_antivirus',
    'items' => [
        [
            'text' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_SCAN'),
            'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_SCAN_TITLE'),
            'url' => 'delement_antivirus_scan.php?lang=' . LANGUAGE_ID,
        ],
        [
            'text' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_RESULTS'),
            'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_RESULTS_TITLE'),
            'url' => 'delement_antivirus_results.php?lang=' . LANGUAGE_ID,
        ],
        [
            'text' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_QUARANTINE'),
            'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_MENU_QUARANTINE_TITLE'),
            'url' => 'delement_antivirus_quarantine.php?lang=' . LANGUAGE_ID,
        ],
    ],
];
