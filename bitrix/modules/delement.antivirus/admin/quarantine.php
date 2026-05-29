<?php

use Bitrix\Main\Localization\Loc;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

if ($APPLICATION->GetGroupRight($moduleId) < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_TITLE'));

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

CAdminMessage::ShowNote(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_SKELETON_NOTE'));

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
