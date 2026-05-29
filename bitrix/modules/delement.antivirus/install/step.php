<?php

use Bitrix\Main\Localization\Loc;

if (!defined('B_PROLOG_INCLUDED') || B_PROLOG_INCLUDED !== true) {
    die();
}

Loc::loadMessages(__FILE__);

CAdminMessage::ShowNote(Loc::getMessage('DELEMENT_ANTIVIRUS_INSTALL_OK'));
?>
<form action="<?php echo $APPLICATION->GetCurPage(); ?>">
    <input type="hidden" name="lang" value="<?php echo LANGUAGE_ID; ?>">
    <input type="submit" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BACK_TO_MODULES'); ?>">
</form>
