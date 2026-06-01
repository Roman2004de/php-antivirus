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

?>
<style>
    .delement-antivirus-panel {
        max-width: 900px !important;
        padding: 18px 0 10px !important;
        line-height: 1.6 !important;
    }

    .delement-antivirus-title {
        display: block !important;
        margin: 0 0 14px !important;
        font-size: 18px !important;
        font-weight: 600 !important;
        line-height: 1.5 !important;
    }

    .delement-antivirus-muted {
        display: block !important;
        margin: 0 0 22px !important;
        color: #666 !important;
        line-height: 1.65 !important;
    }

    .delement-antivirus-actions {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 10px !important;
        margin: 0 0 22px !important;
        line-height: 1.6 !important;
    }

    .delement-antivirus-progress {
        position: relative !important;
        width: 100% !important;
        height: 14px !important;
        margin: 0 0 18px !important;
        overflow: hidden !important;
        border: 1px solid #b7c4ce !important;
        background: #eef3f6 !important;
    }

    .delement-antivirus-progress-bar {
        width: 0;
        height: 100% !important;
        background: #2f80ed !important;
        transition: width 0.2s ease !important;
    }

    .delement-antivirus-stats {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 12px 24px !important;
        margin: 0 0 16px !important;
        color: #333 !important;
        line-height: 1.7 !important;
    }

    .delement-antivirus-current {
        min-height: 20px !important;
        margin: 0 0 16px !important;
        color: #666 !important;
        line-height: 1.6 !important;
        word-break: break-all !important;
    }

    .delement-antivirus-output {
        display: block !important;
        min-height: 96px !important;
        max-width: 100% !important;
        padding: 12px !important;
        overflow: auto !important;
        border: 1px solid #d8d8d8 !important;
        background: #f7f7f7 !important;
        color: #333 !important;
        line-height: 1.5 !important;
        white-space: pre-wrap !important;
    }
</style>
<?php

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
