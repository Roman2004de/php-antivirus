<?php

use Bitrix\Main\Localization\Loc;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

if ($APPLICATION->GetGroupRight($moduleId) < 'W') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_TITLE'));

$documentRoot = rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\');
$cssPath = '/bitrix/css/' . $moduleId . '/admin.css';
$moduleCssPath = '/bitrix/modules/' . $moduleId . '/install/css/admin.css';
$jsPath = '/bitrix/js/' . $moduleId . '/scanner.js';
$moduleJsPath = '/bitrix/modules/' . $moduleId . '/install/js/scanner.js';
$installedCssPath = $documentRoot . $cssPath;
$installedJsPath = $documentRoot . $jsPath;
$installedCssIsCurrent = is_readable($installedCssPath)
    && strpos((string)file_get_contents($installedCssPath), 'delement-antivirus-progress-value') !== false;
$installedJsIsCurrent = is_readable($installedJsPath)
    && strpos((string)file_get_contents($installedJsPath), 'delement-antivirus-progress-value') !== false;

$cssAssetPath = $installedCssIsCurrent || !is_file($documentRoot . $moduleCssPath) ? $cssPath : $moduleCssPath;
$jsAssetPath = $installedJsIsCurrent || !is_file($documentRoot . $moduleJsPath) ? $jsPath : $moduleJsPath;
$versionAsset = static function (string $path) use ($documentRoot): string {
    $pathWithoutQuery = explode('?', $path, 2)[0];
    $filePath = $documentRoot . $pathWithoutQuery;

    return is_file($filePath) ? $path . '?v=' . filemtime($filePath) : $path;
};

$APPLICATION->SetAdditionalCSS($versionAsset($cssAssetPath));
$APPLICATION->AddHeadScript($versionAsset($jsAssetPath));

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

$scannerMessages = [
    'starting' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_JS_STARTING'),
    'discovering' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_JS_DISCOVERING'),
    'request_failed' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_JS_REQUEST_FAILED'),
    'statuses' => [
        'idle' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_IDLE'),
        'iddle' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_IDLE'),
        'created' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_CREATED'),
        'running' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_RUNNING'),
        'progress' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_RUNNING'),
        'finished' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_FINISHED'),
        'cancelled' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_CANCELLED'),
        'canceled' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_CANCELLED'),
        'failed' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_FAILED'),
        'error' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_FAILED'),
        'skipped' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_SKIPPED'),
        'clean' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_CLEAN'),
        'low_risk' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_LOW_RISK'),
        'suspicious' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_SUSPICIOUS'),
        'malicious' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_MALICIOUS'),
        'unknown' => Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_UNKNOWN'),
    ],
];

?>
<script>
    window.DelementAntivirusScannerMessages = <?php echo json_encode($scannerMessages, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
</script>
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
                <div class="delement-antivirus-header">
                    <div class="delement-antivirus-title">
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_MODULE_NAME'); ?>
                    </div>
                    <div class="delement-antivirus-muted">
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_ENGINE_TEXT'); ?>
                    </div>
                </div>
                <div class="delement-antivirus-actions">
                    <button type="button" class="adm-btn adm-btn-save" id="delement-antivirus-start">
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_START'); ?>
                    </button>
                    <button type="button" class="adm-btn delement-antivirus-disabled" id="delement-antivirus-cancel" disabled aria-disabled="true">
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_CANCEL'); ?>
                    </button>
                </div>
                <div class="delement-antivirus-progress-wrap">
                    <div class="delement-antivirus-progress-head">
                        <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_PROGRESS'); ?></span>
                        <b class="delement-antivirus-progress-value" id="delement-antivirus-progress-value">0%</b>
                    </div>
                    <div class="delement-antivirus-progress" id="delement-antivirus-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                        <div class="delement-antivirus-progress-bar" id="delement-antivirus-progress-bar"></div>
                    </div>
                    <progress class="delement-antivirus-progress-native" id="delement-antivirus-progress-native" value="0" max="100">0%</progress>
                </div>
                <div class="delement-antivirus-stats">
                    <span class="delement-antivirus-stat"><span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS'); ?></span><b id="delement-antivirus-status"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_STATUS_IDLE'); ?></b></span>
                    <span class="delement-antivirus-stat"><span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_PROCESSED'); ?></span><b><span id="delement-antivirus-processed">0</span>/<span id="delement-antivirus-total">0</span></b></span>
                    <span class="delement-antivirus-stat"><span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_FOUND'); ?></span><b id="delement-antivirus-found">0</b></span>
                    <span class="delement-antivirus-stat"><span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_ERRORS'); ?></span><b id="delement-antivirus-errors">0</b></span>
                </div>
                <div class="delement-antivirus-current" id="delement-antivirus-current"></div>
                <div class="delement-antivirus-log-title"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_LOG_TITLE'); ?></div>
                <pre class="delement-antivirus-output" id="delement-antivirus-output"><?php echo htmlspecialcharsbx((string)Loc::getMessage('DELEMENT_ANTIVIRUS_SCAN_LOG_IDLE')); ?></pre>
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
