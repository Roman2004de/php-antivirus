<?php

use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Report\ReportManager;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';
$right = $APPLICATION->GetGroupRight($moduleId);

Loc::loadMessages(__FILE__);

if ($right < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

if (isset($_GET['scan_id']) && (string)$_GET['scan_id'] !== '') {
    $redirectUrl = '/bitrix/admin/delement_antivirus_report.php?lang=' . LANGUAGE_ID
        . '&scan_id=' . urlencode((string)$_GET['scan_id']);

    if (isset($_GET['export']) && $_GET['export'] === 'Y') {
        $redirectUrl .= '&export=Y';
    }

    LocalRedirect($redirectUrl);
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TITLE'));

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
        $unknown = isset($labels['unknown']) ? (string)$labels['unknown'] : '';

        return $label !== '' ? $label : ($status !== '' ? $status : $unknown);
    }
}

if (!function_exists('delement_antivirus_results_profile_label')) {
    function delement_antivirus_results_profile_label($profile): string
    {
        $profile = trim((string)$profile);
        $profileKey = strtoupper(str_replace('-', '_', $profile));
        $label = $profileKey !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PROFILE_' . $profileKey)
            : '';

        return $label ?: $profile;
    }
}

if (!function_exists('delement_antivirus_results_normalize_tags')) {
    function delement_antivirus_results_normalize_tags($tags): array
    {
        if (is_string($tags)) {
            $tags = preg_split('/[\s,]+/', $tags);
        }

        if (!is_array($tags)) {
            return [];
        }

        $result = [];
        $seen = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag === '' || isset($seen[$tag])) {
                continue;
            }

            $result[] = $tag;
            $seen[$tag] = true;
        }

        sort($result, SORT_STRING);

        return $result;
    }
}

if (!function_exists('delement_antivirus_results_tags_html')) {
    function delement_antivirus_results_tags_html($tags): string
    {
        $tags = delement_antivirus_results_normalize_tags($tags);

        if (empty($tags)) {
            return '';
        }

        $html = '<span class="delement-antivirus-tags">';

        foreach ($tags as $tag) {
            $safeTag = htmlspecialcharsbx($tag);
            $html .= '<span class="delement-antivirus-tag" title="' . $safeTag . '">' . $safeTag . '</span>';
        }

        return $html . '</span>';
    }
}

if (!function_exists('delement_antivirus_results_filter_by_tag')) {
    function delement_antivirus_results_filter_by_tag(array $reports, string $tag): array
    {
        $tag = strtolower(trim($tag));

        if ($tag === '') {
            return $reports;
        }

        return array_values(array_filter($reports, static function (array $report) use ($tag) {
            return in_array($tag, delement_antivirus_results_normalize_tags($report['tags'] ?? []), true);
        }));
    }
}

if (!function_exists('delement_antivirus_results_sort_reports')) {
    function delement_antivirus_results_sort_reports(array &$reports, $field, $order): void
    {
        $allowedFields = [
            'scan_id',
            'started_at',
            'status',
            'finished_at',
            'processed_files',
            'found_total',
            'runtime_errors',
            'profile',
        ];
        $numericFields = [
            'processed_files',
            'found_total',
            'runtime_errors',
        ];
        $field = in_array((string)$field, $allowedFields, true) ? (string)$field : 'started_at';
        $direction = strtolower((string)$order) === 'asc' ? 1 : -1;

        usort($reports, static function (array $left, array $right) use ($field, $direction, $numericFields) {
            $leftValue = $left[$field] ?? '';
            $rightValue = $right[$field] ?? '';

            if (in_array($field, $numericFields, true)) {
                $leftValue = (int)$leftValue;
                $rightValue = (int)$rightValue;
            } else {
                $leftValue = (string)$leftValue;
                $rightValue = (string)$rightValue;
            }

            if ($leftValue === $rightValue) {
                return 0;
            }

            return ($leftValue < $rightValue ? -1 : 1) * $direction;
        });
    }
}

if (!function_exists('delement_antivirus_results_report_ids')) {
    function delement_antivirus_results_report_ids(array $reports): array
    {
        $ids = [];

        foreach ($reports as $report) {
            $scanId = isset($report['scan_id']) ? (string)$report['scan_id'] : '';

            if ($scanId !== '') {
                $ids[] = $scanId;
            }
        }

        return $ids;
    }
}

$reportManager = new ReportManager();
$messages = [];
$errors = [];
$reports = [];
$sTableID = 'tbl_delement_antivirus_results';
$oSort = new CAdminSorting($sTableID, 'started_at', 'desc');
$lAdmin = new CAdminList($sTableID, $oSort);
$filterFields = ['find_tag'];
$lAdmin->InitFilter($filterFields);
$findTag = isset($find_tag) ? trim((string)$find_tag) : '';

try {
    $reports = $reportManager->listReports(100);
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LIST_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

if (($selectedIds = $lAdmin->GroupAction()) !== false) {
    $action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';

    if ($action === 'delete') {
        if ($right < 'W') {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE_ERROR_ACCESS');
        } elseif (!check_bitrix_sessid()) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE_ERROR_SESSID');
        } else {
            if (isset($_REQUEST['action_target']) && $_REQUEST['action_target'] === 'selected') {
                $selectedIds = delement_antivirus_results_report_ids($reports);
            }

            if (!is_array($selectedIds)) {
                $selectedIds = [$selectedIds];
            }

            $selectedIds = array_values(array_unique(array_filter(array_map('strval', $selectedIds), 'strlen')));
            $deletedCount = 0;

            foreach ($selectedIds as $deleteScanId) {
                try {
                    if ($reportManager->deleteReport($deleteScanId)) {
                        $deletedCount++;
                    }
                } catch (Throwable $exception) {
                    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE_ERROR', [
                        '#SCAN_ID#' => htmlspecialcharsbx($deleteScanId),
                        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                    ]);
                }
            }

            if ($deletedCount > 0) {
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETED', [
                    '#COUNT#' => $deletedCount,
                ]);
            }

            try {
                $reports = $reportManager->listReports(100);
            } catch (Throwable $exception) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LIST_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                ]);
            }
        }
    }
}

$reports = delement_antivirus_results_filter_by_tag($reports, $findTag);
delement_antivirus_results_sort_reports($reports, $by ?? 'started_at', $order ?? 'desc');

$lAdmin->AddHeaders([
    [
        'id' => 'SCAN_ID',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID'),
        'sort' => 'scan_id',
        'default' => true,
    ],
    [
        'id' => 'STARTED_AT',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STARTED_AT'),
        'sort' => 'started_at',
        'default' => true,
    ],
    [
        'id' => 'STATUS',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_STATUS'),
        'sort' => 'status',
        'default' => true,
    ],
    [
        'id' => 'FINISHED_AT',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINISHED_AT'),
        'sort' => 'finished_at',
        'default' => true,
    ],
    [
        'id' => 'PROCESSED',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PROCESSED'),
        'sort' => 'processed_files',
        'default' => true,
    ],
    [
        'id' => 'FOUND',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FOUND'),
        'sort' => 'found_total',
        'default' => true,
    ],
    [
        'id' => 'ERRORS',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ERRORS'),
        'sort' => 'runtime_errors',
        'default' => true,
    ],
    [
        'id' => 'PROFILE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PROFILE'),
        'sort' => 'profile',
        'default' => true,
    ],
    [
        'id' => 'TAGS',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TAGS'),
        'default' => true,
    ],
]);

$rsData = new CDBResult();
$rsData->InitFromArray($reports);
$rsData = new CAdminResult($rsData, $sTableID);
$rsData->NavStart();
$lAdmin->NavText($rsData->GetNavPrint(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LIST_NAV')));

while ($item = $rsData->NavNext(true, 'f_')) {
    $rowScanId = isset($item['scan_id']) ? (string)$item['scan_id'] : '';

    if ($rowScanId === '') {
        continue;
    }

    $viewUrl = '/bitrix/admin/delement_antivirus_report.php?lang=' . LANGUAGE_ID . '&scan_id=' . urlencode($rowScanId);
    $row = $lAdmin->AddRow($rowScanId, $item);
    $row->AddViewField('SCAN_ID', '<a href="' . htmlspecialcharsbx($viewUrl) . '">' . htmlspecialcharsbx($rowScanId) . '</a>');
    $row->AddViewField('STARTED_AT', htmlspecialcharsbx((string)($item['started_at'] ?? '')));
    $row->AddViewField('STATUS', htmlspecialcharsbx(delement_antivirus_results_status_label($item['status'] ?? '')));
    $row->AddViewField('FINISHED_AT', htmlspecialcharsbx((string)($item['finished_at'] ?? '')));
    $row->AddViewField('PROCESSED', (int)($item['processed_files'] ?? 0) . ' / ' . (int)($item['total_files_estimated'] ?? 0));
    $row->AddViewField('FOUND', (int)($item['found_total'] ?? 0));
    $row->AddViewField('ERRORS', (int)($item['runtime_errors'] ?? 0));
    $row->AddViewField('PROFILE', htmlspecialcharsbx(delement_antivirus_results_profile_label($item['profile'] ?? '')));
    $row->AddViewField('TAGS', delement_antivirus_results_tags_html($item['tags'] ?? []));

    $actions = [
        [
            'ICON' => 'view',
            'DEFAULT' => true,
            'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_VIEW'),
            'ACTION' => $lAdmin->ActionRedirect($viewUrl),
        ],
    ];

    if ($right >= 'W') {
        $actions[] = ['SEPARATOR' => true];
        $actions[] = [
            'ICON' => 'delete',
            'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE'),
            'ACTION' => "if(confirm('" . CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE_CONFIRM')) . "')) " . $lAdmin->ActionDoGroup($rowScanId, 'delete'),
        ];
    }

    $row->AddActions($actions);
}

$lAdmin->AddFooter([
    [
        'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LIST_TOTAL'),
        'value' => $rsData->SelectedRowsCount(),
    ],
    [
        'counter' => true,
        'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LIST_SELECTED'),
        'value' => '0',
    ],
]);

if ($right >= 'W') {
    $lAdmin->AddGroupActionTable([
        'delete' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DELETE'),
    ]);
}

$lAdmin->CheckListMode();

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

$filter = new CAdminFilter($sTableID . '_filter', [Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TAG')]);
?>
<form name="find_form" method="get" action="<?php echo htmlspecialcharsbx($APPLICATION->GetCurPage()); ?>">
    <input type="hidden" name="lang" value="<?php echo htmlspecialcharsbx(LANGUAGE_ID); ?>">
    <?php $filter->Begin(); ?>
    <tr>
        <td><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TAG'); ?>:</td>
        <td><input type="text" name="find_tag" value="<?php echo htmlspecialcharsbx($findTag); ?>" size="35"></td>
    </tr>
    <?php
    $filter->Buttons([
        'table_id' => $sTableID,
        'url' => $APPLICATION->GetCurPage(),
        'form' => 'find_form',
    ]);
    $filter->End();
    ?>
</form>
<?php

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

$lAdmin->DisplayList();

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
