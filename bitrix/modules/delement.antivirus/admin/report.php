<?php

use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Whitelist\WhitelistManager;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';
$right = $APPLICATION->GetGroupRight($moduleId);

Loc::loadMessages(__DIR__ . '/results.php');

if ($right < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

if (!function_exists('delement_antivirus_results_status_label')) {
    function delement_antivirus_results_status_label($status): string
    {
        $status = trim((string)$status);
        $statusKey = strtolower($status);
        $labels = [
            'idle' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_IDLE'),
            'iddle' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_IDLE'),
            'created' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_CREATED'),
            'running' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_RUNNING'),
            'progress' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_RUNNING'),
            'finished' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_FINISHED'),
            'cancelled' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_CANCELLED'),
            'canceled' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_CANCELLED'),
            'failed' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_FAILED'),
            'error' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_FAILED'),
            'skipped' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_SKIPPED'),
            'clean' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_CLEAN'),
            'low_risk' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_LOW_RISK'),
            'suspicious' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_SUSPICIOUS'),
            'malicious' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_MALICIOUS'),
            'unknown' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS_UNKNOWN'),
        ];

        $label = isset($labels[$statusKey]) ? (string)$labels[$statusKey] : '';
        $unknown = isset($labels['unknown']) ? (string)$labels['unknown'] : 'unknown';

        return $label !== '' ? $label : ($status !== '' ? $status : $unknown);
    }
}

if (!function_exists('delement_antivirus_results_action_label')) {
    function delement_antivirus_results_action_label($action): string
    {
        $action = trim((string)$action);
        $actionKey = strtoupper(str_replace('-', '_', $action));
        $label = $actionKey !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ACTION_' . $actionKey)
            : '';

        return $label ?: $action;
    }
}

$reportManager = new ReportManager();
$whitelistManager = null;
$messages = [];
$errors = [];
$scanId = isset($_GET['scan_id']) ? (string)$_GET['scan_id'] : '';
$report = null;
$reportError = '';

$reportTitle = $scanId !== ''
    ? Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DETAILS_TITLE_WITH_ID', ['#SCAN_ID#' => $scanId])
    : Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DETAILS_TITLE');

$APPLICATION->SetTitle($reportTitle);

try {
    $whitelistManager = new WhitelistManager();
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MANAGER_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['whitelist_action'])) {
    if ($right < 'W') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_ACCESS');
    } elseif (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_SESSID');
    } elseif ($whitelistManager === null) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_MANAGER_NOT_READY');
    } else {
        $type = isset($_POST['whitelist_type']) ? (string)$_POST['whitelist_type'] : '';
        $data = [
            'path' => isset($_POST['file_path']) ? (string)$_POST['file_path'] : '',
            'hash' => isset($_POST['file_hash']) ? (string)$_POST['file_hash'] : '',
            'signature_id' => isset($_POST['signature_id']) ? (string)$_POST['signature_id'] : '',
            'pattern' => isset($_POST['pattern']) ? (string)$_POST['pattern'] : '',
        ];
        $userId = is_object($USER) && method_exists($USER, 'GetID') ? (int)$USER->GetID() : 0;

        try {
            $whitelistManager->addRule($type, $data, $userId);
            $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ADDED');
        } catch (Throwable $exception) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ADD_ERROR', [
                '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
            ]);
        }
    }
}

if ($scanId === '') {
    $reportError = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID_REQUIRED');
} else {
    try {
        $report = $reportManager->load($scanId);
    } catch (Throwable $exception) {
        $reportError = $exception->getMessage();
    }
}

if ($report !== null && isset($_GET['export']) && $_GET['export'] === 'Y') {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    header('Content-Type: application/json; charset=UTF-8');
    header('Content-Disposition: attachment; filename="delement_antivirus_' . preg_replace('/[^a-zA-Z0-9_.-]/', '_', $scanId) . '.json"');
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    die();
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

?>
<style>
    .delement-antivirus-results-summary {
        width: auto !important;
        min-width: 640px !important;
        margin: 0 0 18px !important;
        border-collapse: collapse !important;
    }

    .delement-antivirus-results-summary td {
        text-align: left !important;
        vertical-align: top !important;
        padding: 8px 10px !important;
    }

    .delement-antivirus-results-summary-label {
        width: 220px !important;
        font-weight: bold !important;
        white-space: nowrap !important;
    }
</style>
<?php

if ($reportError !== '') {
    CAdminMessage::ShowMessage([
        'MESSAGE' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_REPORT_LOAD_ERROR'),
        'DETAILS' => htmlspecialcharsbx($reportError),
        'HTML' => true,
        'TYPE' => 'ERROR',
    ]);
}

foreach ($messages as $message) {
    CAdminMessage::ShowNote($message);
}

foreach ($errors as $error) {
    CAdminMessage::ShowMessage([
        'MESSAGE' => $error,
        'TYPE' => 'ERROR',
        'HTML' => true,
    ]);
}

?>
<div class="adm-detail-toolbar">
    <span style="position:absolute;"></span>
    <a href="/bitrix/admin/delement_antivirus_results.php?lang=<?php echo LANGUAGE_ID; ?>" class="adm-detail-toolbar-btn" id="btn_list">
        <span class="adm-detail-toolbar-btn-l"></span>
        <span class="adm-detail-toolbar-btn-text"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_BACK_TO_LIST'); ?></span>
        <span class="adm-detail-toolbar-btn-r"></span>
    </a>
</div>
<?php

if (is_array($report)) {
    $summary = isset($report['summary']) && is_array($report['summary']) ? $report['summary'] : [];
    $results = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];
    ?>
    <h2><?php echo htmlspecialcharsbx($reportTitle); ?></h2>
    <p>
        <a class="adm-btn" href="/bitrix/admin/delement_antivirus_report.php?lang=<?php echo LANGUAGE_ID; ?>&amp;scan_id=<?php echo urlencode((string)($summary['scan_id'] ?? '')); ?>&amp;export=Y">
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EXPORT_JSON'); ?>
        </a>
    </p>
    <table class="internal delement-antivirus-results-summary">
        <tbody>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID'); ?></td>
            <td><?php echo htmlspecialcharsbx((string)($summary['scan_id'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH'); ?></td>
            <td><?php echo htmlspecialcharsbx((string)($summary['path'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ACTION'); ?></td>
            <td><?php echo htmlspecialcharsbx(delement_antivirus_results_action_label($summary['action'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DRY_RUN'); ?></td>
            <td><?php echo !empty($summary['dry_run']) ? 'Y' : 'N'; ?></td>
        </tr>
        </tbody>
    </table>

    <?php if ($right >= 'W' && $whitelistManager !== null): ?>
        <h2><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_TITLE'); ?></h2>
        <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['whitelist_action', 'whitelist_type', 'pattern', 'sessid']); ?>" style="margin:0 0 18px;">
            <?php echo bitrix_sessid_post(); ?>
            <input type="hidden" name="whitelist_action" value="add">
            <input type="hidden" name="whitelist_type" value="<?php echo htmlspecialcharsbx(WhitelistManager::TYPE_PATH_REGEX); ?>">
            <input type="text" name="pattern" size="60" placeholder="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_REGEX_PLACEHOLDER'); ?>">
            <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ADD_REGEX'); ?>">
        </form>
        <?php echo BeginNote(); ?>
        <b><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_TITLE'); ?></b>
        <ul style="margin:8px 0 0 18px;padding:0;">
            <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_FILE_SIGNATURE'); ?></li>
            <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_SIGNATURE'); ?></li>
            <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_HASH'); ?></li>
            <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_PATH'); ?></li>
            <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_LEGEND_REGEX'); ?></li>
        </ul>
        <?php echo EndNote(); ?>
    <?php endif; ?>

    <h2><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINDINGS_TITLE'); ?></h2>
    <table class="adm-list-table">
        <thead>
        <tr class="adm-list-table-header">
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FILE'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_VERDICT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCORE'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SEVERITY'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SIGNATURE'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_CATEGORY'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EXCERPT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ACTIONS'); ?></div></td>
        </tr>
        </thead>
        <tbody>
        <?php
        $hasFindings = false;
        foreach ($results as $result):
            $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];
            foreach ($findings as $finding):
                $hasFindings = true;
                ?>
                <tr class="adm-list-table-row">
                    <?php
                    $filePath = (string)($result['file_path'] ?? '');
                    $fileHash = (string)($result['file_hash'] ?? '');
                    $signatureId = (string)($finding['signature_id'] ?? '');
                    ?>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx($filePath); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_results_status_label($result['status'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo (int)($result['score'] ?? 0); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['severity'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx($signatureId); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['category'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['excerpt'] ?? '')); ?></td>
                    <td class="adm-list-table-cell">
                        <?php if ($right >= 'W' && $whitelistManager !== null): ?>
                            <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['whitelist_action', 'whitelist_type', 'file_path', 'file_hash', 'signature_id', 'pattern', 'sessid']); ?>" style="display:block;margin:0 0 6px;">
                                <?php echo bitrix_sessid_post(); ?>
                                <input type="hidden" name="whitelist_action" value="add">
                                <input type="hidden" name="whitelist_type" value="<?php echo htmlspecialcharsbx(WhitelistManager::TYPE_FILE_SIGNATURE); ?>">
                                <input type="hidden" name="file_path" value="<?php echo htmlspecialcharsbx($filePath); ?>">
                                <input type="hidden" name="file_hash" value="<?php echo htmlspecialcharsbx($fileHash); ?>">
                                <input type="hidden" name="signature_id" value="<?php echo htmlspecialcharsbx($signatureId); ?>">
                                <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_FILE_SIGNATURE'); ?>">
                            </form>
                            <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['whitelist_action', 'whitelist_type', 'file_path', 'file_hash', 'signature_id', 'pattern', 'sessid']); ?>" style="display:block;margin:0 0 6px;">
                                <?php echo bitrix_sessid_post(); ?>
                                <input type="hidden" name="whitelist_action" value="add">
                                <input type="hidden" name="whitelist_type" value="<?php echo htmlspecialcharsbx(WhitelistManager::TYPE_SIGNATURE); ?>">
                                <input type="hidden" name="signature_id" value="<?php echo htmlspecialcharsbx($signatureId); ?>">
                                <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_SIGNATURE'); ?>">
                            </form>
                            <?php if ($fileHash !== ''): ?>
                                <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['whitelist_action', 'whitelist_type', 'file_path', 'file_hash', 'signature_id', 'pattern', 'sessid']); ?>" style="display:block;margin:0 0 6px;">
                                    <?php echo bitrix_sessid_post(); ?>
                                    <input type="hidden" name="whitelist_action" value="add">
                                    <input type="hidden" name="whitelist_type" value="<?php echo htmlspecialcharsbx(WhitelistManager::TYPE_HASH); ?>">
                                    <input type="hidden" name="file_hash" value="<?php echo htmlspecialcharsbx($fileHash); ?>">
                                    <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_HASH'); ?>">
                                </form>
                            <?php endif; ?>
                            <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['whitelist_action', 'whitelist_type', 'file_path', 'file_hash', 'signature_id', 'pattern', 'sessid']); ?>" style="display:block;margin:0;">
                                <?php echo bitrix_sessid_post(); ?>
                                <input type="hidden" name="whitelist_action" value="add">
                                <input type="hidden" name="whitelist_type" value="<?php echo htmlspecialcharsbx(WhitelistManager::TYPE_PATH); ?>">
                                <input type="hidden" name="file_path" value="<?php echo htmlspecialcharsbx($filePath); ?>">
                                <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_PATH'); ?>">
                            </form>
                        <?php else: ?>
                            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_UNAVAILABLE'); ?>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php endforeach; ?>
        <?php if (!$hasFindings): ?>
            <tr class="adm-list-table-row">
                <td class="adm-list-table-cell" colspan="8"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_NO_FINDINGS'); ?></td>
            </tr>
        <?php endif; ?>
        </tbody>
    </table>
    <?php
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
