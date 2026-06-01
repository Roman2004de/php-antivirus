<?php

use Bitrix\Main\Localization\Loc;
use Bitrix\Main\Page\Asset;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

if ($APPLICATION->GetGroupRight($moduleId) < 'W') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_TITLE'));

Asset::getInstance()->addCss('/bitrix/css/' . $moduleId . '/admin.css');
Asset::getInstance()->addJs('/bitrix/js/' . $moduleId . '/scanner.js');

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

$tabControl = new CAdminTabControl(
    'delement_antivirus_scan',
    [
        [
            'DIV' => 'scan',
            'TAB' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_TAB'),
            'TITLE' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_TAB_TITLE'),
        ],
    ]
);

$tabControl->Begin();
?>
<form id="delement-antivirus-scan-form" method="post" action="/bitrix/admin/delement_antivirus_ajax.php">
    <?php echo bitrix_sessid_post(); ?>
    <?php $tabControl->BeginNextTab(); ?>
    <tr>
        <td colspan="2">
            <div class="delement-antivirus-panel">
                <div class="delement-antivirus-title">
                    <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_MODULE_NAME'); ?>
                </div>
                <div class="delement-antivirus-muted">
                    <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_ENGINE_TEXT'); ?>
                </div>
                <div class="delement-antivirus-actions">
                    <button type="button" class="adm-btn adm-btn-save" id="delement-antivirus-start">
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_START'); ?>
                    </button>
                    <button type="button" class="adm-btn" id="delement-antivirus-cancel" disabled>
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_CANCEL'); ?>
                    </button>
                </div>
                <div class="delement-antivirus-progress">
                    <div class="delement-antivirus-progress-bar" id="delement-antivirus-progress-bar"></div>
                </div>
                <div class="delement-antivirus-stats">
                    <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS'); ?>: <b id="delement-antivirus-status">idle</b></span>
                    <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_PROCESSED'); ?>: <b id="delement-antivirus-processed">0</b>/<b id="delement-antivirus-total">0</b></span>
                    <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_FOUND'); ?>: <b id="delement-antivirus-found">0</b></span>
                    <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_ERRORS'); ?>: <b id="delement-antivirus-errors">0</b></span>
                </div>
                <div class="delement-antivirus-current" id="delement-antivirus-current"></div>
                <pre class="delement-antivirus-output" id="delement-antivirus-output"></pre>
            </div>
        </td>
    </tr>
    <?php $tabControl->Buttons(); ?>
    <a class="adm-btn" href="/bitrix/admin/settings.php?mid=<?php echo urlencode($moduleId); ?>&amp;lang=<?php echo LANGUAGE_ID; ?>">
        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_OPEN_OPTIONS'); ?>
    </a>
    <?php $tabControl->End(); ?>
</form>
<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
