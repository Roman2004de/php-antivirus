<?php

use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Report\ReportManager;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

if ($APPLICATION->GetGroupRight($moduleId) < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TITLE'));

if (!function_exists('delement_antivirus_results_status_label')) {
    function delement_antivirus_results_status_label($status): string
    {
        $status = trim((string)$status);
        $statusKey = strtolower($status);
        $labels = [
            'idle' => 'Ожидание',
            'iddle' => 'Ожидание',
            'created' => 'Создано',
            'running' => 'Сканирование',
            'progress' => 'Сканирование',
            'finished' => 'Завершено',
            'cancelled' => 'Остановлено',
            'canceled' => 'Остановлено',
            'failed' => 'Ошибка',
            'error' => 'Ошибка',
            'skipped' => 'Пропущено',
            'clean' => 'Чисто',
            'low_risk' => 'Низкий риск',
            'suspicious' => 'Подозрительно',
            'malicious' => 'Опасно',
            'unknown' => 'Неизвестно',
        ];

        return $labels[$statusKey] ?? ($status !== '' ? $status : $labels['unknown']);
    }
}

$reportManager = new ReportManager();
$scanId = isset($_GET['scan_id']) ? (string)$_GET['scan_id'] : '';
$report = null;
$reportError = '';

if ($scanId !== '') {
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

$reports = $reportManager->listReports(100);

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

?>
<style>
    .delement-antivirus-results-summary,
    .delement-antivirus-results-summary td,
    .delement-antivirus-results-summary .adm-detail-content-cell-l,
    .delement-antivirus-results-summary .adm-detail-content-cell-r {
        text-align: left !important;
    }

    .delement-antivirus-results-summary .adm-detail-content-cell-l,
    .delement-antivirus-results-summary .adm-detail-content-cell-r {
        vertical-align: top !important;
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

if (empty($reports)) {
    CAdminMessage::ShowNote(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EMPTY'));
} else {
    ?>
    <table class="adm-list-table">
        <thead>
        <tr class="adm-list-table-header">
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STARTED_AT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINISHED_AT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PROCESSED'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FOUND'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ERRORS'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PROFILE'); ?></div></td>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($reports as $item): ?>
            <?php $rowScanId = isset($item['scan_id']) ? (string)$item['scan_id'] : ''; ?>
            <tr class="adm-list-table-row">
                <td class="adm-list-table-cell">
                    <a href="/bitrix/admin/delement_antivirus_results.php?lang=<?php echo LANGUAGE_ID; ?>&amp;scan_id=<?php echo urlencode($rowScanId); ?>">
                        <?php echo htmlspecialcharsbx($rowScanId); ?>
                    </a>
                </td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['started_at'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_results_status_label($item['status'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['finished_at'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo (int)($item['processed_files'] ?? 0); ?> / <?php echo (int)($item['total_files_estimated'] ?? 0); ?></td>
                <td class="adm-list-table-cell"><?php echo (int)($item['found_total'] ?? 0); ?></td>
                <td class="adm-list-table-cell"><?php echo (int)($item['runtime_errors'] ?? 0); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['profile'] ?? '')); ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

if (is_array($report)) {
    $summary = isset($report['summary']) && is_array($report['summary']) ? $report['summary'] : [];
    $results = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];
    ?>
    <h2><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DETAILS_TITLE'); ?></h2>
    <p>
        <a class="adm-btn" href="/bitrix/admin/delement_antivirus_results.php?lang=<?php echo LANGUAGE_ID; ?>&amp;scan_id=<?php echo urlencode((string)($summary['scan_id'] ?? '')); ?>&amp;export=Y">
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EXPORT_JSON'); ?>
        </a>
    </p>
    <table class="adm-detail-content-table edit-table delement-antivirus-results-summary">
        <tbody>
        <tr>
            <td width="40%" class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID'); ?></td>
            <td width="60%" class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx((string)($summary['scan_id'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH'); ?></td>
            <td class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx((string)($summary['path'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ACTION'); ?></td>
            <td class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx((string)($summary['action'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DRY_RUN'); ?></td>
            <td class="adm-detail-content-cell-r"><?php echo !empty($summary['dry_run']) ? 'Y' : 'N'; ?></td>
        </tr>
        </tbody>
    </table>

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
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($result['file_path'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_results_status_label($result['status'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo (int)($result['score'] ?? 0); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['severity'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['signature_id'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['category'] ?? '')); ?></td>
                    <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($finding['excerpt'] ?? '')); ?></td>
                </tr>
            <?php endforeach; ?>
        <?php endforeach; ?>
        <?php if (!$hasFindings): ?>
            <tr class="adm-list-table-row">
                <td class="adm-list-table-cell" colspan="7"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_NO_FINDINGS'); ?></td>
            </tr>
        <?php endif; ?>
        </tbody>
    </table>
    <?php
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
