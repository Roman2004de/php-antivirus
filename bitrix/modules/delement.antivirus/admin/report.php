<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Quarantine\QuarantineManager;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Whitelist\SuppressionFingerprint;
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

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DETAILS_TITLE'));

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

if (!function_exists('delement_antivirus_results_scan_profile_label')) {
    function delement_antivirus_results_scan_profile_label($scanProfile): string
    {
        $scanProfile = trim((string)$scanProfile);
        $profileKey = strtoupper(str_replace('-', '_', $scanProfile));
        $label = $profileKey !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_PROFILE_' . $profileKey)
            : '';

        return $label ?: $scanProfile;
    }
}

if (!function_exists('delement_antivirus_report_quarantine_manager')) {
    function delement_antivirus_report_quarantine_manager(string $moduleId, string $documentRoot): QuarantineManager
    {
        $path = dirname(__DIR__) . '/default_option.php';
        $defaults = [];
        $delement_antivirus_default_option = [];

        if (is_file($path)) {
            require $path;
        }

        if (is_array($delement_antivirus_default_option)) {
            $defaults = $delement_antivirus_default_option;
        }

        $options = [];

        foreach ($defaults as $name => $defaultValue) {
            $options[$name] = Option::get($moduleId, $name, (string)$defaultValue);
        }

        $config = ScanConfig::fromModuleOptions($options, $documentRoot);

        return new QuarantineManager($config->getQuarantinePath(), $documentRoot);
    }
}

if (!function_exists('delement_antivirus_report_normalize_tags')) {
    function delement_antivirus_report_normalize_tags($tags): array
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

if (!function_exists('delement_antivirus_report_merge_tags')) {
    function delement_antivirus_report_merge_tags(...$tagSets): array
    {
        $tags = [];

        foreach ($tagSets as $tagSet) {
            if (!is_array($tagSet)) {
                continue;
            }

            foreach ($tagSet as $tag) {
                $tags[] = $tag;
            }
        }

        return delement_antivirus_report_normalize_tags($tags);
    }
}

if (!function_exists('delement_antivirus_report_tags_html')) {
    function delement_antivirus_report_tags_html($tags): string
    {
        $tags = delement_antivirus_report_normalize_tags($tags);

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

if (!function_exists('delement_antivirus_report_filter_rows_by_tag')) {
    function delement_antivirus_report_filter_rows_by_tag(array $rows, string $tag): array
    {
        $tag = strtolower(trim($tag));

        if ($tag === '') {
            return $rows;
        }

        return array_values(array_filter($rows, static function (array $row) use ($tag) {
            return in_array($tag, delement_antivirus_report_normalize_tags($row['tags'] ?? []), true);
        }));
    }
}

if (!function_exists('delement_antivirus_report_finding_rows')) {
    function delement_antivirus_report_finding_rows(array $report, string $documentRoot = ''): array
    {
        $summary = isset($report['summary']) && is_array($report['summary']) ? $report['summary'] : [];
        $scanId = (string)($summary['scan_id'] ?? '');
        $results = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];
        $rows = [];

        foreach ($results as $resultIndex => $result) {
            if (!is_array($result)) {
                continue;
            }

            $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];

            foreach ($findings as $findingIndex => $finding) {
                if (!is_array($finding)) {
                    continue;
                }

                $rowId = 'finding_' . (int)$resultIndex . '_' . (int)$findingIndex;
                $filePath = (string)($result['file_path'] ?? '');
                $fingerprint = (string)($finding['fingerprint'] ?? '');

                if ($fingerprint === '') {
                    $fingerprint = SuppressionFingerprint::forFinding($filePath, $finding, $documentRoot);
                }

                $rows[] = [
                    'id' => $rowId,
                    'scan_id' => $scanId,
                    'file_path' => $filePath,
                    'file_hash' => (string)($result['file_hash'] ?? ''),
                    'normalized_hash' => isset($result['normalized_hash']) && $result['normalized_hash'] !== null ? (string)$result['normalized_hash'] : '',
                    'finding_fingerprint' => $fingerprint,
                    'status' => (string)($result['status'] ?? ''),
                    'score' => (int)($result['score'] ?? 0),
                    'severity' => (string)($finding['severity'] ?? ($result['severity'] ?? '')),
                    'signature_id' => (string)($finding['signature_id'] ?? ''),
                    'category' => (string)($finding['category'] ?? ''),
                    'confidence' => (string)($finding['confidence'] ?? ''),
                    'entropy' => isset($finding['entropy']) && $finding['entropy'] !== null ? (float)$finding['entropy'] : null,
                    'length' => isset($finding['length']) && $finding['length'] !== null ? (int)$finding['length'] : null,
                    'url' => (string)($finding['url'] ?? ''),
                    'domain' => (string)($finding['domain'] ?? ''),
                    'excerpt' => (string)($finding['excerpt'] ?? ''),
                    'tags' => delement_antivirus_report_merge_tags($result['tags'] ?? [], $finding['tags'] ?? []),
                    'scan_result' => $result,
                    'finding' => array_merge($finding, ['fingerprint' => $fingerprint]),
                ];
            }
        }

        return $rows;
    }
}

if (!function_exists('delement_antivirus_report_finding_row_map')) {
    function delement_antivirus_report_finding_row_map(array $rows): array
    {
        $map = [];

        foreach ($rows as $row) {
            $id = isset($row['id']) ? (string)$row['id'] : '';

            if ($id !== '') {
                $map[$id] = $row;
            }
        }

        return $map;
    }
}

if (!function_exists('delement_antivirus_report_sort_finding_rows')) {
    function delement_antivirus_report_sort_finding_rows(array &$rows, $field, $order): void
    {
        $allowedFields = [
            'file_path',
            'status',
            'score',
            'severity',
            'signature_id',
            'category',
            'confidence',
            'entropy',
            'length',
            'url',
            'domain',
            'normalized_hash',
            'excerpt',
            'tags',
        ];
        $field = in_array((string)$field, $allowedFields, true) ? (string)$field : 'score';
        $direction = strtolower((string)$order) === 'asc' ? 1 : -1;

        usort($rows, static function (array $left, array $right) use ($field, $direction) {
            if ($field === 'score' || $field === 'length') {
                $leftValue = (int)($left[$field] ?? 0);
                $rightValue = (int)($right[$field] ?? 0);
            } elseif ($field === 'entropy') {
                $leftValue = (float)($left[$field] ?? 0);
                $rightValue = (float)($right[$field] ?? 0);
            } elseif ($field === 'tags') {
                $leftValue = implode(',', delement_antivirus_report_normalize_tags($left[$field] ?? []));
                $rightValue = implode(',', delement_antivirus_report_normalize_tags($right[$field] ?? []));
            } else {
                $leftValue = (string)($left[$field] ?? '');
                $rightValue = (string)($right[$field] ?? '');
            }

            if ($leftValue === $rightValue) {
                return 0;
            }

            return ($leftValue < $rightValue ? -1 : 1) * $direction;
        });
    }
}

if (!function_exists('delement_antivirus_report_finding_row_ids')) {
    function delement_antivirus_report_finding_row_ids(array $rows): array
    {
        $ids = [];

        foreach ($rows as $row) {
            $id = isset($row['id']) ? (string)$row['id'] : '';

            if ($id !== '') {
                $ids[] = $id;
            }
        }

        return $ids;
    }
}

if (!function_exists('delement_antivirus_report_display_rows')) {
    function delement_antivirus_report_display_rows(array $rows): array
    {
        $displayRows = [];

        foreach ($rows as $row) {
            unset($row['scan_result']);
            unset($row['finding']);
            $displayRows[] = $row;
        }

        return $displayRows;
    }
}

if (!function_exists('delement_antivirus_report_path_view_mode')) {
    function delement_antivirus_report_path_view_mode($value): string
    {
        return (string)$value === 'full' ? 'full' : 'relative';
    }
}

if (!function_exists('delement_antivirus_report_format_file_path')) {
    function delement_antivirus_report_format_file_path(string $filePath, string $documentRoot, string $mode): string
    {
        if ($mode === 'full' || $filePath === '') {
            return $filePath;
        }

        $normalizedFilePath = str_replace('\\', '/', $filePath);
        $normalizedDocumentRoot = rtrim(str_replace('\\', '/', $documentRoot), '/');

        if ($normalizedDocumentRoot === '') {
            return $filePath;
        }

        $filePathKey = strtolower($normalizedFilePath);
        $documentRootKey = strtolower($normalizedDocumentRoot);

        if ($filePathKey === $documentRootKey) {
            return '/';
        }

        if (strpos($filePathKey, $documentRootKey . '/') !== 0) {
            return $filePath;
        }

        return '/' . ltrim(substr($normalizedFilePath, strlen($normalizedDocumentRoot)), '/');
    }
}

if (!function_exists('delement_antivirus_report_document_root')) {
    function delement_antivirus_report_document_root(array $report): string
    {
        $config = isset($report['config']) && is_array($report['config']) ? $report['config'] : [];
        $documentRoot = trim((string)($config['document_root'] ?? ''));

        return $documentRoot !== '' ? $documentRoot : (string)($_SERVER['DOCUMENT_ROOT'] ?? '');
    }
}

if (!function_exists('delement_antivirus_report_thresholds')) {
    function delement_antivirus_report_thresholds(array $report, string $documentRoot): array
    {
        $config = isset($report['config']) && is_array($report['config']) ? $report['config'] : [];
        $config['document_root'] = $documentRoot;

        try {
            return ScanConfig::fromArray($config)->getThresholds();
        } catch (Throwable $exception) {
            return ScanConfig::fromArray([
                'document_root' => $documentRoot,
                'profile' => ScanConfig::PROFILE_BALANCED,
            ])->getThresholds();
        }
    }
}

if (!function_exists('delement_antivirus_report_apply_suppressions')) {
    function delement_antivirus_report_apply_suppressions(array $report, WhitelistManager $whitelistManager, string $documentRoot): array
    {
        if (!isset($report['results']) || !is_array($report['results'])) {
            return $report;
        }

        $thresholds = delement_antivirus_report_thresholds($report, $documentRoot);

        foreach ($report['results'] as &$result) {
            if (is_array($result)) {
                $result = $whitelistManager->filterSuppressedFindings($result, $thresholds);
            }
        }
        unset($result);

        return $report;
    }
}

$reportManager = new ReportManager();
$whitelistManager = null;
$quarantineManager = null;
$messages = [];
$errors = [];
$scanId = isset($_GET['scan_id']) ? (string)$_GET['scan_id'] : '';
$report = null;
$displayReport = null;
$reportError = '';
$reportDocumentRoot = (string)($_SERVER['DOCUMENT_ROOT'] ?? '');
$findingRows = [];
$findingRowMap = [];
$pathViewMode = delement_antivirus_report_path_view_mode($_REQUEST['path_view'] ?? 'relative');
$sTableID = 'tbl_delement_antivirus_report_findings';
$oSort = new CAdminSorting($sTableID, 'score', 'desc');
$lAdmin = new CAdminList($sTableID, $oSort);
$filterFields = ['find_tag'];
$lAdmin->InitFilter($filterFields);
$findTag = isset($find_tag) ? trim((string)$find_tag) : '';

try {
    $whitelistManager = new WhitelistManager();
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MANAGER_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

try {
    $quarantineManager = delement_antivirus_report_quarantine_manager($moduleId, (string)$_SERVER['DOCUMENT_ROOT']);
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_MANAGER_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

if ($scanId === '') {
    $reportError = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID_REQUIRED');
} else {
    try {
        $report = $reportManager->load($scanId);
        $reportDocumentRoot = delement_antivirus_report_document_root($report);
        $displayReport = $report;

        if ($whitelistManager !== null) {
            $displayReport = delement_antivirus_report_apply_suppressions($displayReport, $whitelistManager, $reportDocumentRoot);
        }

        $findingRows = delement_antivirus_report_finding_rows($displayReport, $reportDocumentRoot);
        $findingRows = delement_antivirus_report_filter_rows_by_tag($findingRows, $findTag);
        $findingRowMap = delement_antivirus_report_finding_row_map($findingRows);
    } catch (Throwable $exception) {
        $reportError = $exception->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['suppress_action']) && $_POST['suppress_action'] === 'suppress_finding') {
    if ($right < 'W') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_ACCESS');
    } elseif (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_SESSID');
    } elseif ($whitelistManager === null) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_MANAGER_NOT_READY');
    } else {
        $findingId = isset($_POST['finding_id']) ? (string)$_POST['finding_id'] : '';
        $postedFingerprint = isset($_POST['finding_fingerprint']) ? (string)$_POST['finding_fingerprint'] : '';
        $postedFilePath = isset($_POST['file_path']) ? (string)$_POST['file_path'] : '';
        $comment = isset($_POST['comment']) ? (string)$_POST['comment'] : '';

        if ($findingId === '' && $postedFingerprint !== '') {
            foreach ($findingRowMap as $candidateId => $candidateRow) {
                if ((string)($candidateRow['finding_fingerprint'] ?? '') === $postedFingerprint) {
                    $findingId = (string)$candidateId;
                    break;
                }
            }
        }

        if (!isset($findingRowMap[$findingId])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_FINDING_NOT_FOUND');
        } else {
            $row = $findingRowMap[$findingId];
            $userId = is_object($USER) && method_exists($USER, 'GetID') ? (int)$USER->GetID() : 0;

            if ($postedFingerprint !== '' && $postedFingerprint !== (string)($row['finding_fingerprint'] ?? '')) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_FINGERPRINT_MISMATCH');
            } elseif ($postedFilePath !== '' && $postedFilePath !== (string)($row['file_path'] ?? '')) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ERROR_FILE_MISMATCH');
            } else {

                try {
                    $whitelistManager->suppressFinding(
                        isset($row['scan_result']) && is_array($row['scan_result']) ? $row['scan_result'] : [],
                        isset($row['finding']) && is_array($row['finding']) ? $row['finding'] : [],
                        $userId,
                        $comment
                    );
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ADDED');

                if (is_array($report)) {
                    $displayReport = delement_antivirus_report_apply_suppressions($report, $whitelistManager, $reportDocumentRoot);
                    $findingRows = delement_antivirus_report_finding_rows($displayReport, $reportDocumentRoot);
                        $findingRows = delement_antivirus_report_filter_rows_by_tag($findingRows, $findTag);
                        $findingRowMap = delement_antivirus_report_finding_row_map($findingRows);
                    }
                } catch (Throwable $exception) {
                    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_ADD_ERROR', [
                        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                    ]);
                }
            }
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['whitelist_action'])) {
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
} elseif (($selectedIds = $lAdmin->GroupAction()) !== false) {
    $action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';
    $whitelistActions = [
        'whitelist_file_signature' => WhitelistManager::TYPE_FILE_SIGNATURE,
        'whitelist_signature' => WhitelistManager::TYPE_SIGNATURE,
        'whitelist_hash' => WhitelistManager::TYPE_HASH,
        'whitelist_path' => WhitelistManager::TYPE_PATH,
    ];

    if (isset($_REQUEST['action_target']) && $_REQUEST['action_target'] === 'selected') {
        $selectedIds = delement_antivirus_report_finding_row_ids($findingRows);
    }

    if (!is_array($selectedIds)) {
        $selectedIds = [$selectedIds];
    }

    $selectedIds = array_values(array_unique(array_filter(array_map('strval', $selectedIds), 'strlen')));

    if (isset($whitelistActions[$action])) {
        if ($right < 'W') {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_ACCESS');
        } elseif (!check_bitrix_sessid()) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_SESSID');
        } elseif ($whitelistManager === null) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ERROR_MANAGER_NOT_READY');
        } else {
            $addedCount = 0;
            $userId = is_object($USER) && method_exists($USER, 'GetID') ? (int)$USER->GetID() : 0;

            foreach ($selectedIds as $rowId) {
                if (!isset($findingRowMap[$rowId])) {
                    continue;
                }

                $row = $findingRowMap[$rowId];
                $data = [
                    'path' => (string)($row['file_path'] ?? ''),
                    'hash' => (string)($row['file_hash'] ?? ''),
                    'signature_id' => (string)($row['signature_id'] ?? ''),
                ];

                try {
                    $whitelistManager->addRule($whitelistActions[$action], $data, $userId);
                    $addedCount++;
                } catch (Throwable $exception) {
                    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ADD_ERROR', [
                        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                    ]);
                }
            }

            if ($addedCount > 0) {
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_ADDED_COUNT', [
                    '#COUNT#' => $addedCount,
                ]);
            }
        }
    } elseif ($action === 'quarantine_file') {
        if ($right < 'W') {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_ERROR_ACCESS');
        } elseif (!check_bitrix_sessid()) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_ERROR_SESSID');
        } elseif ($quarantineManager === null) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_ERROR_MANAGER_NOT_READY');
        } else {
            $quarantinedCount = 0;
            $processedPaths = [];

            foreach ($selectedIds as $rowId) {
                if (!isset($findingRowMap[$rowId])) {
                    continue;
                }

                $row = $findingRowMap[$rowId];
                $filePath = (string)($row['file_path'] ?? '');

                if ($filePath === '' || isset($processedPaths[$filePath])) {
                    continue;
                }

                $processedPaths[$filePath] = true;
                $scanResult = isset($row['scan_result']) && is_array($row['scan_result']) ? $row['scan_result'] : [];
                $scanResult['planned_action'] = ScanConfig::ACTION_QUARANTINE;
                $scanResult['action'] = ScanConfig::ACTION_QUARANTINE;
                $scanResult['action_status'] = 'forced';

                try {
                    $quarantineManager->quarantine($filePath, $scanResult, $scanId);
                    $quarantinedCount++;
                } catch (Throwable $exception) {
                    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_ADD_ERROR', [
                        '#FILE#' => htmlspecialcharsbx($filePath),
                        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                    ]);
                }
            }

            if ($quarantinedCount > 0) {
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_QUARANTINE_ADDED_COUNT', [
                    '#COUNT#' => $quarantinedCount,
                ]);
            }
        }
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

delement_antivirus_report_sort_finding_rows($findingRows, $by ?? 'score', $order ?? 'desc');

$lAdmin->AddHeaders([
    [
        'id' => 'FILE_PATH',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FILE'),
        'sort' => 'file_path',
        'default' => true,
    ],
    [
        'id' => 'STATUS',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_VERDICT'),
        'sort' => 'status',
        'default' => true,
    ],
    [
        'id' => 'SCORE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCORE'),
        'sort' => 'score',
        'default' => true,
    ],
    [
        'id' => 'SEVERITY',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SEVERITY'),
        'sort' => 'severity',
        'default' => true,
    ],
    [
        'id' => 'SIGNATURE_ID',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SIGNATURE'),
        'sort' => 'signature_id',
        'default' => true,
    ],
    [
        'id' => 'CATEGORY',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_CATEGORY'),
        'sort' => 'category',
        'default' => true,
    ],
    [
        'id' => 'CONFIDENCE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_CONFIDENCE'),
        'sort' => 'confidence',
        'default' => false,
    ],
    [
        'id' => 'ENTROPY',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_ENTROPY'),
        'sort' => 'entropy',
        'default' => false,
    ],
    [
        'id' => 'LENGTH',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_LENGTH'),
        'sort' => 'length',
        'default' => false,
    ],
    [
        'id' => 'URL',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_URL'),
        'sort' => 'url',
        'default' => true,
    ],
    [
        'id' => 'DOMAIN',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_DOMAIN'),
        'sort' => 'domain',
        'default' => false,
    ],
    [
        'id' => 'NORMALIZED_HASH',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_NORMALIZED_HASH'),
        'sort' => 'normalized_hash',
        'default' => false,
    ],
    [
        'id' => 'EXCERPT',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EXCERPT'),
        'sort' => 'excerpt',
        'default' => true,
    ],
    [
        'id' => 'TAGS',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TAGS'),
        'sort' => 'tags',
        'default' => true,
    ],
]);

$rsData = new CDBResult();
$rsData->InitFromArray(delement_antivirus_report_display_rows($findingRows));
$rsData = new CAdminResult($rsData, $sTableID);
$rsData->NavStart();
$lAdmin->NavText($rsData->GetNavPrint(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINDINGS_LIST_NAV')));

while ($rowData = $rsData->NavNext(true, 'f_')) {
    $rowId = isset($rowData['id']) ? (string)$rowData['id'] : '';

    if ($rowId === '') {
        continue;
    }

    $row = $lAdmin->AddRow($rowId, $rowData);
    $filePath = (string)($rowData['file_path'] ?? '');
    $displayFilePath = delement_antivirus_report_format_file_path($filePath, $reportDocumentRoot, $pathViewMode);
    $row->AddViewField(
        'FILE_PATH',
        '<span class="delement-antivirus-report-file-path" title="' . htmlspecialcharsbx($filePath) . '">' . htmlspecialcharsbx($displayFilePath) . '</span>'
    );
    $row->AddViewField('STATUS', htmlspecialcharsbx(delement_antivirus_results_status_label($rowData['status'] ?? '')));
    $row->AddViewField('SCORE', (int)($rowData['score'] ?? 0));
    $row->AddViewField('SEVERITY', htmlspecialcharsbx((string)($rowData['severity'] ?? '')));
    $row->AddViewField('SIGNATURE_ID', htmlspecialcharsbx((string)($rowData['signature_id'] ?? '')));
    $row->AddViewField('CATEGORY', htmlspecialcharsbx((string)($rowData['category'] ?? '')));
    $row->AddViewField('CONFIDENCE', (string)($rowData['confidence'] ?? '') !== '' ? htmlspecialcharsbx((string)$rowData['confidence']) : '&mdash;');
    $row->AddViewField('ENTROPY', $rowData['entropy'] !== null ? htmlspecialcharsbx((string)$rowData['entropy']) : '&mdash;');
    $row->AddViewField('LENGTH', $rowData['length'] !== null ? (int)$rowData['length'] : '&mdash;');
    $row->AddViewField('URL', (string)($rowData['url'] ?? '') !== '' ? '<span title="' . htmlspecialcharsbx((string)$rowData['url']) . '">' . htmlspecialcharsbx((string)$rowData['url']) . '</span>' : '&mdash;');
    $row->AddViewField('DOMAIN', (string)($rowData['domain'] ?? '') !== '' ? htmlspecialcharsbx((string)$rowData['domain']) : '&mdash;');
    $row->AddViewField(
        'NORMALIZED_HASH',
        (string)($rowData['normalized_hash'] ?? '') !== ''
            ? '<span title="' . htmlspecialcharsbx((string)$rowData['normalized_hash']) . '">' . htmlspecialcharsbx(substr((string)$rowData['normalized_hash'], 0, 16)) . '...</span>'
            : '&mdash;'
    );
    $row->AddViewField('EXCERPT', htmlspecialcharsbx((string)($rowData['excerpt'] ?? '')));
    $row->AddViewField('TAGS', delement_antivirus_report_tags_html($rowData['tags'] ?? []));

    if ($right >= 'W') {
        $actions = [];

        if ($whitelistManager !== null) {
            $actions[] = [
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_MENU'),
                'ACTION' => "var c=prompt('" . CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SUPPRESS_COMMENT_PROMPT')) . "',''); if(c!==null){"
                    . "BX('delement-antivirus-suppress-finding-id').value='" . CUtil::JSEscape($rowId) . "';"
                    . "BX('delement-antivirus-suppress-file-path').value='" . CUtil::JSEscape($filePath) . "';"
                    . "BX('delement-antivirus-suppress-fingerprint').value='" . CUtil::JSEscape((string)($rowData['finding_fingerprint'] ?? '')) . "';"
                    . "BX('delement-antivirus-suppress-comment').value=c;"
                    . "BX('delement-antivirus-suppress-form').submit();}",
            ];
            $actions[] = ['SEPARATOR' => true];
            $actions[] = [
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MENU_FILE_SIGNATURE'),
                'ACTION' => $lAdmin->ActionDoGroup($rowId, 'whitelist_file_signature'),
            ];
            $actions[] = [
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MENU_SIGNATURE'),
                'ACTION' => $lAdmin->ActionDoGroup($rowId, 'whitelist_signature'),
            ];

            if ((string)($rowData['file_hash'] ?? '') !== '') {
                $actions[] = [
                    'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MENU_HASH'),
                    'ACTION' => $lAdmin->ActionDoGroup($rowId, 'whitelist_hash'),
                ];
            }

            $actions[] = [
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_WHITELIST_MENU_PATH'),
                'ACTION' => $lAdmin->ActionDoGroup($rowId, 'whitelist_path'),
            ];
        }

        if ($quarantineManager !== null) {
            if (!empty($actions)) {
                $actions[] = ['SEPARATOR' => true];
            }

            $actions[] = [
                'ICON' => 'move',
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FORCE_QUARANTINE'),
                'ACTION' => "if(confirm('" . CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FORCE_QUARANTINE_CONFIRM')) . "')) " . $lAdmin->ActionDoGroup($rowId, 'quarantine_file'),
            ];
        }

        if (!empty($actions)) {
            $row->AddActions($actions);
        }
    }
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

$lAdmin->CheckListMode();

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

    .delement-antivirus-report-table-head {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        gap: 16px !important;
        margin: 18px 0 10px !important;
    }

    .delement-antivirus-report-table-head h2 {
        margin: 0 !important;
    }

    .delement-antivirus-path-switcher {
        display: flex !important;
        align-items: center !important;
        flex-wrap: wrap !important;
        gap: 8px !important;
        color: #555 !important;
        line-height: 1.4 !important;
    }

    .delement-antivirus-path-switcher .adm-btn {
        margin: 0 !important;
    }

    .delement-antivirus-path-switcher-active {
        font-weight: bold !important;
        cursor: default !important;
    }

    .delement-antivirus-report-file-path {
        word-break: break-all !important;
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

if (is_array($report)) {
    $filter = new CAdminFilter($sTableID . '_filter', [Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_TAG')]);
    ?>
    <form name="find_form" method="get" action="<?php echo htmlspecialcharsbx($APPLICATION->GetCurPage()); ?>">
        <input type="hidden" name="lang" value="<?php echo htmlspecialcharsbx(LANGUAGE_ID); ?>">
        <input type="hidden" name="scan_id" value="<?php echo htmlspecialcharsbx($scanId); ?>">
        <input type="hidden" name="path_view" value="<?php echo htmlspecialcharsbx($pathViewMode); ?>">
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
}

?>
<?php if (is_array($report) && $right >= 'W' && $whitelistManager !== null): ?>
    <form id="delement-antivirus-suppress-form" method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['suppress_action', 'finding_id', 'file_path', 'finding_fingerprint', 'comment', 'sessid']); ?>" style="display:none;">
        <?php echo bitrix_sessid_post(); ?>
        <input type="hidden" name="suppress_action" value="suppress_finding">
        <input type="hidden" name="scan_id" value="<?php echo htmlspecialcharsbx($scanId); ?>">
        <input type="hidden" id="delement-antivirus-suppress-finding-id" name="finding_id" value="">
        <input type="hidden" id="delement-antivirus-suppress-file-path" name="file_path" value="">
        <input type="hidden" id="delement-antivirus-suppress-fingerprint" name="finding_fingerprint" value="">
        <input type="hidden" id="delement-antivirus-suppress-comment" name="comment" value="">
    </form>
<?php endif; ?>
<div class="adm-detail-toolbar">
    <span style="position:absolute;"></span>
    <a href="/bitrix/admin/delement_antivirus_results.php?lang=<?php echo LANGUAGE_ID; ?>" class="adm-detail-toolbar-btn" title="" id="btn_list"><span class="adm-detail-toolbar-btn-l"></span><span class="adm-detail-toolbar-btn-text"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_BACK_TO_LIST'); ?></span><span class="adm-detail-toolbar-btn-r"></span></a>
    <?php if (is_array($report)): ?>
        <div class="adm-detail-toolbar-right">
            <a class="adm-btn" href="/bitrix/admin/delement_antivirus_report.php?lang=<?php echo LANGUAGE_ID; ?>&amp;scan_id=<?php echo urlencode($scanId); ?>&amp;export=Y">
                <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_EXPORT_JSON'); ?>
            </a>
        </div>
    <?php endif; ?>
</div>
<?php

if (is_array($report)) {
    $summary = isset($report['summary']) && is_array($report['summary']) ? $report['summary'] : [];
    ?>
    <table class="internal delement-antivirus-results-summary">
        <tbody>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_ID'); ?></td>
            <td><?php echo htmlspecialcharsbx((string)($summary['scan_id'] ?? '')); ?></td>
        </tr>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_SCAN_PROFILE'); ?></td>
            <td><?php echo htmlspecialcharsbx(delement_antivirus_results_scan_profile_label($summary['scan_profile'] ?? '')); ?></td>
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
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINDINGS_TOTAL'); ?></td>
            <td><?php echo (int)($summary['findings_total'] ?? count($findingRows)); ?></td>
        </tr>
        <tr>
            <td class="delement-antivirus-results-summary-label"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_INFORMATIONAL_FINDINGS_TOTAL'); ?></td>
            <td><?php echo (int)($summary['informational_findings_total'] ?? 0); ?></td>
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

    <?php
    $relativePathUrl = $APPLICATION->GetCurPageParam('path_view=relative', ['path_view', 'export']);
    $fullPathUrl = $APPLICATION->GetCurPageParam('path_view=full', ['path_view', 'export']);
    ?>
    <div class="delement-antivirus-report-table-head">
        <h2><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_FINDINGS_TITLE'); ?></h2>
        <div class="delement-antivirus-path-switcher">
            <span><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH_VIEW'); ?></span>
            <?php if ($pathViewMode === 'relative'): ?>
                <span class="adm-btn delement-antivirus-path-switcher-active"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH_VIEW_RELATIVE'); ?></span>
            <?php else: ?>
                <a class="adm-btn" href="<?php echo htmlspecialcharsbx($relativePathUrl); ?>"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH_VIEW_RELATIVE'); ?></a>
            <?php endif; ?>
            <?php if ($pathViewMode === 'full'): ?>
                <span class="adm-btn delement-antivirus-path-switcher-active"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH_VIEW_FULL'); ?></span>
            <?php else: ?>
                <a class="adm-btn" href="<?php echo htmlspecialcharsbx($fullPathUrl); ?>"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_RESULTS_PATH_VIEW_FULL'); ?></a>
            <?php endif; ?>
        </div>
    </div>
    <?php $lAdmin->DisplayList(); ?>
    <?php
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
