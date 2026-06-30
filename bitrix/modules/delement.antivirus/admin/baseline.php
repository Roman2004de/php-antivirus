<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Baseline\BaselineManager;
use Delement\Antivirus\Baseline\BaselineStorage;
use Delement\Antivirus\Config\ScanConfig;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';
$right = $APPLICATION->GetGroupRight($moduleId);

Loc::loadMessages(__FILE__);

if ($right < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

if (!function_exists('delement_antivirus_baseline_options')) {
    function delement_antivirus_baseline_options(string $moduleId, string $moduleRoot): array
    {
        $path = rtrim($moduleRoot, '/\\') . '/default_option.php';
        $delement_antivirus_default_option = [];

        if (is_file($path)) {
            require $path;
        }

        $defaults = is_array($delement_antivirus_default_option) ? $delement_antivirus_default_option : [];
        $options = [];

        foreach ($defaults as $name => $defaultValue) {
            $options[$name] = Option::get($moduleId, $name, (string)$defaultValue);
        }

        return $options;
    }
}

if (!function_exists('delement_antivirus_baseline_config')) {
    function delement_antivirus_baseline_config(array $options, string $path, string $documentRoot): ScanConfig
    {
        $options['scan_path'] = $path;

        return ScanConfig::fromModuleOptions($options, $documentRoot);
    }
}

if (!function_exists('delement_antivirus_baseline_tags_html')) {
    function delement_antivirus_baseline_tags_html($tags): string
    {
        if (!is_array($tags)) {
            return '';
        }

        $html = [];

        foreach ($tags as $tag) {
            $tag = trim((string)$tag);

            if ($tag === '') {
                continue;
            }

            $html[] = '<span class="delement-antivirus-tag">' . htmlspecialcharsbx($tag) . '</span>';
        }

        return implode(' ', $html);
    }
}

if (!function_exists('delement_antivirus_baseline_severity_label')) {
    function delement_antivirus_baseline_severity_label($severity): string
    {
        $key = strtoupper(str_replace('-', '_', trim((string)$severity)));
        $message = $key !== '' ? Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SEVERITY_' . $key) : '';

        return $message ?: (string)$severity;
    }
}

if (!function_exists('delement_antivirus_baseline_signature_label')) {
    function delement_antivirus_baseline_signature_label($signatureId): string
    {
        $key = strtoupper(str_replace('-', '_', trim((string)$signatureId)));
        $message = $key !== '' ? Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SIGNATURE_' . $key) : '';

        return $message ?: (string)$signatureId;
    }
}

if (!function_exists('delement_antivirus_baseline_status_label')) {
    function delement_antivirus_baseline_status_label($status): string
    {
        $key = strtoupper(str_replace('-', '_', trim((string)$status)));
        $message = $key !== '' ? Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_STATUS_' . $key) : '';

        return $message ?: (string)$status;
    }
}

if (!function_exists('delement_antivirus_baseline_rows')) {
    function delement_antivirus_baseline_rows(array $report): array
    {
        $rows = [];

        foreach ((array)($report['results'] ?? []) as $resultIndex => $result) {
            if (!is_array($result)) {
                continue;
            }

            foreach ((array)($result['findings'] ?? []) as $findingIndex => $finding) {
                if (!is_array($finding)) {
                    continue;
                }

                $rows[] = [
                    'ID' => (string)$resultIndex . '_' . (string)$findingIndex,
                    'FILE' => (string)($result['file_path'] ?? $finding['file'] ?? ''),
                    'SIGNATURE' => (string)($finding['signature_id'] ?? ''),
                    'SEVERITY' => (string)($finding['severity'] ?? ''),
                    'SCORE' => (int)($finding['score'] ?? 0),
                    'TAGS' => array_values(array_unique(array_merge(
                        (array)($result['tags'] ?? []),
                        (array)($finding['tags'] ?? [])
                    ))),
                    'EXCERPT' => (string)($finding['excerpt'] ?? ''),
                ];
            }
        }

        return $rows;
    }
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_TITLE'));

$documentRoot = rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\');
$moduleRoot = $documentRoot . '/bitrix/modules/' . $moduleId;
$options = delement_antivirus_baseline_options($moduleId, $moduleRoot);
$baselinePath = trim((string)($_REQUEST['baseline_path'] ?? ($options['scan_path'] ?? '#DOCUMENT_ROOT#')));
$errors = [];
$notes = [];
$manager = new BaselineManager(new BaselineStorage($moduleRoot));

if (isset($_GET['export']) && $_GET['export'] === 'Y') {
    $reportPath = $manager->latestReportPath();

    if ($reportPath === '' || !is_file($reportPath)) {
        require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
        CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_REPORT_NOT_FOUND'));
        require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
        return;
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="delement_antivirus_baseline_report.json"');
    readfile($reportPath);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($right < 'W') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_ACCESS_DENIED');
    } elseif (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SESSID_ERROR');
    } elseif ($baselinePath === '' || strpos($baselinePath, "\0") !== false) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_PATH_ERROR');
    } else {
        try {
            $config = delement_antivirus_baseline_config($options, $baselinePath, $documentRoot);

            if (isset($_POST['baseline_create'])) {
                $report = $manager->createBaseline($config);
                $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_CREATED', [
                    '#COUNT#' => (string)($report['summary']['baseline_records'] ?? 0),
                ]);
            } elseif (isset($_POST['baseline_check'])) {
                $report = $manager->checkBaseline($config);
                $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_CHECKED', [
                    '#COUNT#' => (string)($report['summary']['changed_files'] ?? 0),
                ]);
            } elseif (isset($_POST['baseline_update'])) {
                $report = $manager->updateBaseline($config);
                $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_UPDATED', [
                    '#COUNT#' => (string)($report['summary']['baseline_records'] ?? 0),
                ]);
            }
        } catch (Throwable $exception) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_ACTION_ERROR', [
                '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
            ]);
        }
    }
}

try {
    $latestReport = $manager->latestReport();
} catch (Throwable $exception) {
    $latestReport = [];
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_REPORT_LOAD_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

$summary = isset($latestReport['summary']) && is_array($latestReport['summary']) ? $latestReport['summary'] : [];
$rows = delement_antivirus_baseline_rows($latestReport);
$sTableID = 'tbl_delement_antivirus_baseline';
$oSort = new CAdminSorting($sTableID, 'SEVERITY', 'desc');
$lAdmin = new CAdminList($sTableID, $oSort);

$rsData = new CDBResult();
$rsData->InitFromArray($rows);
$rsData = new CAdminResult($rsData, $sTableID);
$rsData->NavStart();
$lAdmin->NavText($rsData->GetNavPrint(Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_LIST_NAV')));

$lAdmin->AddHeaders([
    ['id' => 'SIGNATURE', 'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_COL_CHANGE'), 'default' => true],
    ['id' => 'SEVERITY', 'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_COL_SEVERITY'), 'default' => true],
    ['id' => 'SCORE', 'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_COL_SCORE'), 'default' => true],
    ['id' => 'FILE', 'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_COL_FILE'), 'default' => true],
    ['id' => 'TAGS', 'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_COL_TAGS'), 'default' => true],
]);

while ($rowData = $rsData->NavNext(true, 'f_')) {
    $row = $lAdmin->AddRow($rowData['ID'], $rowData);
    $row->AddViewField('SIGNATURE', htmlspecialcharsbx(delement_antivirus_baseline_signature_label($rowData['SIGNATURE'])));
    $row->AddViewField('SEVERITY', htmlspecialcharsbx(delement_antivirus_baseline_severity_label($rowData['SEVERITY'])));
    $row->AddViewField('SCORE', (string)(int)$rowData['SCORE']);
    $row->AddViewField('FILE', '<span title="' . htmlspecialcharsbx($rowData['FILE']) . '">' . htmlspecialcharsbx($rowData['FILE']) . '</span>');
    $row->AddViewField('TAGS', delement_antivirus_baseline_tags_html($rowData['TAGS']));
}

$lAdmin->CheckListMode();

$documentRoot = rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\');
$cssPath = '/bitrix/css/' . $moduleId . '/admin.css';
$moduleCssPath = '/bitrix/modules/' . $moduleId . '/install/css/admin.css';
$installedCssPath = $documentRoot . $cssPath;
$installedCssIsCurrent = is_readable($installedCssPath)
    && strpos((string)file_get_contents($installedCssPath), 'delement-antivirus-tag') !== false;
$cssAssetPath = $installedCssIsCurrent || !is_file($documentRoot . $moduleCssPath) ? $cssPath : $moduleCssPath;
$versionAsset = static function (string $path) use ($documentRoot): string {
    $pathWithoutQuery = explode('?', $path, 2)[0];
    $filePath = $documentRoot . $pathWithoutQuery;

    return is_file($filePath) ? $path . '?v=' . filemtime($filePath) : $path;
};

$APPLICATION->SetAdditionalCSS($versionAsset($cssAssetPath));

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

foreach ($errors as $error) {
    CAdminMessage::ShowMessage($error);
}

foreach ($notes as $note) {
    CAdminMessage::ShowNote($note);
}

$tabControl = new CAdminTabControl('delement_antivirus_baseline', [[
    'DIV' => 'baseline',
    'TAB' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_TAB'),
    'TITLE' => Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_TAB_TITLE'),
]]);

$tabControl->Begin();
?>
<form method="post" action="<?php echo $APPLICATION->GetCurPage(); ?>?lang=<?php echo LANGUAGE_ID; ?>">
    <?php echo bitrix_sessid_post(); ?>
    <?php $tabControl->BeginNextTab(); ?>
    <tr>
        <td width="40%" class="adm-detail-content-cell-l">
            <label for="delement_antivirus_baseline_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_PATH'); ?></label>
        </td>
        <td width="60%" class="adm-detail-content-cell-r">
            <input type="text" size="70" id="delement_antivirus_baseline_path" name="baseline_path" value="<?php echo htmlspecialcharsbx($baselinePath); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <input type="submit" class="adm-btn-save" name="baseline_create" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_CREATE'); ?>">
            <input type="submit" name="baseline_check" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_CHECK'); ?>">
            <input type="submit" name="baseline_update" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_UPDATE'); ?>" onclick="return confirm('<?php echo CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_UPDATE_CONFIRM')); ?>');">
            <?php if (!empty($summary)): ?>
                <a class="adm-btn" href="/bitrix/admin/delement_antivirus_baseline.php?lang=<?php echo LANGUAGE_ID; ?>&amp;export=Y">
                    <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_EXPORT'); ?>
                </a>
            <?php endif; ?>
        </td>
    </tr>
    <?php $tabControl->End(); ?>
</form>

<?php if (!empty($summary)): ?>
    <table class="adm-list-table">
        <tbody>
        <tr>
            <td class="adm-list-table-cell"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SUMMARY_STATUS'); ?></td>
            <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_baseline_status_label($summary['status'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="adm-list-table-cell"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SUMMARY_BASELINE'); ?></td>
            <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx($summary['baseline_created_at'] ?? ''); ?></td>
        </tr>
        <tr>
            <td class="adm-list-table-cell"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SUMMARY_CHANGED'); ?></td>
            <td class="adm-list-table-cell"><?php echo (int)($summary['changed_files'] ?? 0); ?></td>
        </tr>
        <tr>
            <td class="adm-list-table-cell"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SUMMARY_BREAKDOWN'); ?></td>
            <td class="adm-list-table-cell">
                <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_BASELINE_SUMMARY_BREAKDOWN_VALUE', [
                    '#NEW#' => (string)(int)($summary['new_files'] ?? 0),
                    '#MODIFIED#' => (string)(int)($summary['modified_files'] ?? 0),
                    '#DELETED#' => (string)(int)($summary['deleted_files'] ?? 0),
                    '#CRITICAL#' => (string)(int)($summary['critical_changes'] ?? 0),
                ]); ?>
            </td>
        </tr>
        </tbody>
    </table>
<?php endif; ?>

<?php
$lAdmin->DisplayList();

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
