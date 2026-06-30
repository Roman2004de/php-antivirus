<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Detection\Hash\HashDatabase;
use Delement\Antivirus\Detection\Hash\HashPrefixIndex;
use Delement\Antivirus\Detection\Hash\Import\PanelicaHashDownloader;
use Delement\Antivirus\Detection\Hash\Import\PanelicaHashImporter;

global $APPLICATION, $USER;

if (!is_object($USER) || !$USER->IsAdmin()) {
    return;
}

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

require __DIR__ . '/default_option.php';
require_once __DIR__ . '/lib/Detection/Severity.php';
require_once __DIR__ . '/lib/Detection/Hash/HashDatabase.php';
require_once __DIR__ . '/lib/Detection/Hash/HashPrefixIndex.php';
require_once __DIR__ . '/lib/Detection/Hash/Import/SignatureSourceMetadata.php';
require_once __DIR__ . '/lib/Detection/Hash/Import/PanelicaImportResult.php';
require_once __DIR__ . '/lib/Detection/Hash/Import/PanelicaHashNormalizer.php';
require_once __DIR__ . '/lib/Detection/Hash/Import/PanelicaHashDownloader.php';
require_once __DIR__ . '/lib/Detection/Hash/Import/PanelicaHashImporter.php';

$defaults = isset($delement_antivirus_default_option) && is_array($delement_antivirus_default_option)
    ? $delement_antivirus_default_option
    : [];

$profiles = [
    'balanced' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_BALANCED'),
    'strict' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_STRICT'),
    'paranoid' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_PARANOID'),
];

$scanProfiles = [
    'quick' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_QUICK'),
    'standard' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_STANDARD'),
    'deep' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_DEEP'),
];

$actions = [
    'report' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_REPORT'),
    'quarantine' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_QUARANTINE'),
    'delete' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_DELETE'),
];

$optionNames = [
    'scan_path',
    'scan_profile',
    'profile',
    'action',
    'dry_run',
    'quarantine_path',
    'signatures_path',
    'exclude_paths',
    'batch_size',
    'max_file_size_mb',
    'enable_common_strings_prefilter',
    'enable_normalized_hash',
    'normalized_hash_max_file_size_mb',
    'enable_ast_analysis',
    'ast_max_file_size',
    'enable_entropy_analyzer',
    'enable_entropy_in_deep_profile',
    'entropy_min_length',
    'entropy_threshold',
    'entropy_context_window',
    'enable_url_analyzer',
    'suspicious_domains_path',
    'enable_hash_db',
    'malware_hashes_path',
    'malware_hash_prefixes_path',
    'malware_hash_prefix_length',
    'panelica_source_path',
    'panelica_download_url',
    'panelica_last_import_at',
    'panelica_imported_count',
    'panelica_source_commit',
    'panelica_source_license',
];

$getDefault = static function ($name) use ($defaults) {
    return isset($defaults[$name]) ? (string)$defaults[$name] : '';
};

$getOption = static function ($name) use ($moduleId, $getDefault) {
    return Option::get($moduleId, $name, $getDefault($name));
};

$hasTraversal = static function ($value) {
    return preg_match('#(^|[\\\\/])\.\.([\\\\/]|$)#', $value) === 1;
};

$expandDocumentRoot = static function ($value) {
    return str_replace('#DOCUMENT_ROOT#', (string)($_SERVER['DOCUMENT_ROOT'] ?? ''), (string)$value);
};

$isPanelicaWebDownloadUrlAllowed = static function ($value) {
    $parts = parse_url((string)$value);

    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
        return false;
    }

    $host = strtolower((string)($parts['host'] ?? ''));
    $path = '/' . trim((string)($parts['path'] ?? ''), '/');

    if ($host === 'github.com') {
        return $path === '/Panelica/malware-signatures'
            || strpos($path, '/Panelica/malware-signatures/') === 0;
    }

    if ($host === 'raw.githubusercontent.com') {
        return strpos($path, '/Panelica/malware-signatures/') === 0;
    }

    return false;
};

$normalizeLines = static function ($value) use ($hasTraversal) {
    $lines = preg_split('/\r\n|\r|\n/', (string)$value);
    $clean = [];
    $seen = [];
    $errors = [];

    foreach ($lines as $line) {
        $line = trim($line);

        if ($line === '') {
            continue;
        }

        if (strpos($line, "\0") !== false || $hasTraversal($line)) {
            $errors[] = $line;
            continue;
        }

        if (!isset($seen[$line])) {
            $clean[] = $line;
            $seen[$line] = true;
        }
    }

    return [$clean, $errors];
};

$errors = [];
$notes = [];
$saved = false;
$postedValues = null;

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && (
        isset($_POST['save'])
        || isset($_POST['apply'])
        || isset($_POST['restore_defaults'])
        || isset($_POST['import_panelica'])
        || isset($_POST['download_panelica'])
        || isset($_POST['validate_hash_db'])
    )
) {
    if (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_SESSID');
    } elseif (isset($_POST['restore_defaults'])) {
        foreach ($optionNames as $name) {
            Option::set($moduleId, $name, $getDefault($name));
        }

        $saved = true;
    } elseif (isset($_POST['download_panelica'])) {
        $panelicaDownloadUrl = trim((string)($_POST['panelica_download_url'] ?? $getDefault('panelica_download_url')));
        $malwareHashesPath = trim((string)($_POST['malware_hashes_path'] ?? $getDefault('malware_hashes_path')));
        $malwarePrefixesPath = trim((string)($_POST['malware_hash_prefixes_path'] ?? $getDefault('malware_hash_prefixes_path')));
        $prefixLength = trim((string)($_POST['malware_hash_prefix_length'] ?? $getDefault('malware_hash_prefix_length')));
        $sourceCommit = trim((string)($_POST['panelica_source_commit'] ?? ''));
        $postedValues = array_merge($postedValues ?: [], [
            'panelica_download_url' => $panelicaDownloadUrl,
            'malware_hashes_path' => $malwareHashesPath,
            'malware_hash_prefixes_path' => $malwarePrefixesPath,
            'malware_hash_prefix_length' => $prefixLength,
            'panelica_source_commit' => $sourceCommit,
        ]);

        foreach ([
            'malware_hashes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASHES_PATH'),
            'malware_hash_prefixes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASH_PREFIXES_PATH'),
        ] as $name => $label) {
            $value = (string)($postedValues[$name] ?? '');

            if ($value === '') {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_REQUIRED', ['#FIELD#' => $label]);
            } elseif (strpos($value, "\0") !== false || $hasTraversal($value)) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            } elseif (strlen($value) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            }
        }

        if ($panelicaDownloadUrl === '' || strlen($panelicaDownloadUrl) > 2048 || !$isPanelicaWebDownloadUrlAllowed($panelicaDownloadUrl)) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_URL_ERROR');
        }

        if (!preg_match('/^\d+$/', $prefixLength) || (int)$prefixLength < 8 || (int)$prefixLength > 12) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_MALWARE_HASH_PREFIX_LENGTH');
        }

        if (empty($errors)) {
            try {
                $download = (new PanelicaHashDownloader(__DIR__))->download($panelicaDownloadUrl);
                $result = (new PanelicaHashImporter(__DIR__))->import((string)$download['source_directory'], [
                    'hashes_output' => $expandDocumentRoot($malwareHashesPath),
                    'prefixes_output' => $expandDocumentRoot($malwarePrefixesPath),
                    'prefix_length' => (int)$prefixLength,
                    'source_commit' => $sourceCommit,
                ]);
                $downloadWarnings = (array)($download['warnings'] ?? []);
            } catch (Throwable $exception) {
                $download = null;
                $result = null;
                $downloadWarnings = [];
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                ]);
            }

            if ($result !== null && !$result->isSuccess()) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($result->getError()),
                ]);
            } elseif ($result !== null && is_array($download)) {
                $metadata = $result->getMetadata();
                Option::set($moduleId, 'enable_hash_db', 'Y');
                Option::set($moduleId, 'panelica_source_path', (string)$download['source_directory']);
                Option::set($moduleId, 'panelica_download_url', $panelicaDownloadUrl);
                Option::set($moduleId, 'panelica_last_import_at', (string)($metadata['imported_at'] ?? date('c')));
                Option::set($moduleId, 'panelica_imported_count', (string)$result->getImported());
                Option::set($moduleId, 'panelica_source_commit', $sourceCommit);
                Option::set($moduleId, 'panelica_source_license', 'MIT');
                Option::set($moduleId, 'malware_hashes_path', $malwareHashesPath);
                Option::set($moduleId, 'malware_hash_prefixes_path', $malwarePrefixesPath);
                Option::set($moduleId, 'malware_hash_prefix_length', $prefixLength);
                $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_IMPORT_OK', [
                    '#COUNT#' => (string)$result->getImported(),
                    '#URL#' => htmlspecialcharsbx($panelicaDownloadUrl),
                ]);

                foreach (array_merge($downloadWarnings, $result->getWarnings()) as $warning) {
                    $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_WARNING', [
                        '#WARNING#' => htmlspecialcharsbx((string)$warning),
                    ]);
                }

                $saved = true;
            }
        }
    } elseif (isset($_POST['import_panelica'])) {
        $panelicaSourcePath = trim((string)($_POST['panelica_source_path'] ?? ''));
        $malwareHashesPath = trim((string)($_POST['malware_hashes_path'] ?? $getDefault('malware_hashes_path')));
        $malwarePrefixesPath = trim((string)($_POST['malware_hash_prefixes_path'] ?? $getDefault('malware_hash_prefixes_path')));
        $prefixLength = trim((string)($_POST['malware_hash_prefix_length'] ?? $getDefault('malware_hash_prefix_length')));
        $sourceCommit = trim((string)($_POST['panelica_source_commit'] ?? ''));
        $postedValues = array_merge($postedValues ?: [], [
            'panelica_source_path' => $panelicaSourcePath,
            'malware_hashes_path' => $malwareHashesPath,
            'malware_hash_prefixes_path' => $malwarePrefixesPath,
            'malware_hash_prefix_length' => $prefixLength,
            'panelica_source_commit' => $sourceCommit,
        ]);

        foreach ([
            'panelica_source_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SOURCE_PATH'),
            'malware_hashes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASHES_PATH'),
            'malware_hash_prefixes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASH_PREFIXES_PATH'),
        ] as $name => $label) {
            $value = (string)($postedValues[$name] ?? '');

            if ($value === '') {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_REQUIRED', ['#FIELD#' => $label]);
            } elseif (strpos($value, "\0") !== false || $hasTraversal($value)) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            } elseif (strlen($value) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            }
        }

        if (!preg_match('/^\d+$/', $prefixLength) || (int)$prefixLength < 8 || (int)$prefixLength > 12) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_MALWARE_HASH_PREFIX_LENGTH');
        }

        if (empty($errors)) {
            try {
                $result = (new PanelicaHashImporter(__DIR__))->import($expandDocumentRoot($panelicaSourcePath), [
                    'hashes_output' => $expandDocumentRoot($malwareHashesPath),
                    'prefixes_output' => $expandDocumentRoot($malwarePrefixesPath),
                    'prefix_length' => (int)$prefixLength,
                    'source_commit' => $sourceCommit,
                ]);
            } catch (Throwable $exception) {
                $result = null;
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                ]);
            }

            if ($result !== null && !$result->isSuccess()) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($result->getError()),
                ]);
            } elseif ($result !== null) {
                $metadata = $result->getMetadata();
                Option::set($moduleId, 'enable_hash_db', 'Y');
                Option::set($moduleId, 'panelica_source_path', $panelicaSourcePath);
                Option::set($moduleId, 'panelica_last_import_at', (string)($metadata['imported_at'] ?? date('c')));
                Option::set($moduleId, 'panelica_imported_count', (string)$result->getImported());
                Option::set($moduleId, 'panelica_source_commit', $sourceCommit);
                Option::set($moduleId, 'panelica_source_license', 'MIT');
                Option::set($moduleId, 'malware_hashes_path', $malwareHashesPath);
                Option::set($moduleId, 'malware_hash_prefixes_path', $malwarePrefixesPath);
                Option::set($moduleId, 'malware_hash_prefix_length', $prefixLength);
                $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_OK', [
                    '#COUNT#' => (string)$result->getImported(),
                    '#SOURCE#' => htmlspecialcharsbx($result->getSourceUsed()),
                ]);

                foreach ($result->getWarnings() as $warning) {
                    $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_WARNING', [
                        '#WARNING#' => htmlspecialcharsbx((string)$warning),
                    ]);
                }

                $saved = true;
            }
        }
    } elseif (isset($_POST['validate_hash_db'])) {
        $malwareHashesPath = trim((string)($_POST['malware_hashes_path'] ?? $getDefault('malware_hashes_path')));
        $malwarePrefixesPath = trim((string)($_POST['malware_hash_prefixes_path'] ?? $getDefault('malware_hash_prefixes_path')));
        $postedValues = array_merge($postedValues ?: [], [
            'malware_hashes_path' => $malwareHashesPath,
            'malware_hash_prefixes_path' => $malwarePrefixesPath,
        ]);
        $database = HashDatabase::fromFile($expandDocumentRoot($malwareHashesPath));
        $prefixIndex = HashPrefixIndex::fromFile($expandDocumentRoot($malwarePrefixesPath));
        $warnings = array_merge($database->getWarnings(), $prefixIndex->getWarnings());

        if (!empty($warnings)) {
            foreach ($warnings as $warning) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_HASH_DB_VALIDATE_WARNING', [
                    '#WARNING#' => htmlspecialcharsbx((string)$warning),
                ]);
            }
        } else {
            $notes[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_HASH_DB_VALIDATE_OK', [
                '#HASHES#' => (string)$database->count(),
                '#PREFIXES#' => (string)$prefixIndex->count(),
            ]);
            $saved = true;
        }
    } else {
        $values = [];

        $values['scan_path'] = trim((string)($_POST['scan_path'] ?? ''));
        $values['scan_profile'] = (string)($_POST['scan_profile'] ?? '');
        $values['profile'] = (string)($_POST['profile'] ?? '');
        $values['action'] = (string)($_POST['action'] ?? '');
        $values['dry_run'] = isset($_POST['dry_run']) && $_POST['dry_run'] === 'Y' ? 'Y' : 'N';
        $values['quarantine_path'] = trim((string)($_POST['quarantine_path'] ?? ''));
        $values['signatures_path'] = trim((string)($_POST['signatures_path'] ?? ''));
        $values['batch_size'] = trim((string)($_POST['batch_size'] ?? ''));
        $values['max_file_size_mb'] = trim((string)($_POST['max_file_size_mb'] ?? ''));
        $values['enable_common_strings_prefilter'] = isset($_POST['enable_common_strings_prefilter']) && $_POST['enable_common_strings_prefilter'] === 'Y' ? 'Y' : 'N';
        $values['enable_normalized_hash'] = isset($_POST['enable_normalized_hash']) && $_POST['enable_normalized_hash'] === 'Y' ? 'Y' : 'N';
        $values['normalized_hash_max_file_size_mb'] = trim((string)($_POST['normalized_hash_max_file_size_mb'] ?? ''));
        $values['enable_ast_analysis'] = isset($_POST['enable_ast_analysis']) && $_POST['enable_ast_analysis'] === 'Y' ? 'Y' : 'N';
        $values['ast_max_file_size'] = trim((string)($_POST['ast_max_file_size'] ?? ''));
        $values['enable_entropy_analyzer'] = isset($_POST['enable_entropy_analyzer']) && $_POST['enable_entropy_analyzer'] === 'Y' ? 'Y' : 'N';
        $values['enable_entropy_in_deep_profile'] = isset($_POST['enable_entropy_in_deep_profile']) && $_POST['enable_entropy_in_deep_profile'] === 'Y' ? 'Y' : 'N';
        $values['entropy_min_length'] = trim((string)($_POST['entropy_min_length'] ?? ''));
        $values['entropy_threshold'] = str_replace(',', '.', trim((string)($_POST['entropy_threshold'] ?? '')));
        $values['entropy_context_window'] = trim((string)($_POST['entropy_context_window'] ?? ''));
        $values['enable_url_analyzer'] = isset($_POST['enable_url_analyzer']) && $_POST['enable_url_analyzer'] === 'Y' ? 'Y' : 'N';
        $values['suspicious_domains_path'] = trim((string)($_POST['suspicious_domains_path'] ?? ''));
        $values['enable_hash_db'] = isset($_POST['enable_hash_db']) && $_POST['enable_hash_db'] === 'Y' ? 'Y' : 'N';
        $values['malware_hashes_path'] = trim((string)($_POST['malware_hashes_path'] ?? ''));
        $values['malware_hash_prefixes_path'] = trim((string)($_POST['malware_hash_prefixes_path'] ?? ''));
        $values['malware_hash_prefix_length'] = trim((string)($_POST['malware_hash_prefix_length'] ?? ''));
        $values['panelica_source_path'] = trim((string)($_POST['panelica_source_path'] ?? ''));
        $values['panelica_download_url'] = trim((string)($_POST['panelica_download_url'] ?? $getDefault('panelica_download_url')));
        $values['panelica_source_commit'] = trim((string)($_POST['panelica_source_commit'] ?? ''));
        $values['panelica_last_import_at'] = $getOption('panelica_last_import_at');
        $values['panelica_imported_count'] = $getOption('panelica_imported_count');
        $values['panelica_source_license'] = $getOption('panelica_source_license');

        $pathFields = [
            'scan_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PATH'),
            'quarantine_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_QUARANTINE_PATH'),
        ];

        foreach ($pathFields as $name => $label) {
            if ($values[$name] === '') {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_REQUIRED', ['#FIELD#' => $label]);
            }

            if (strpos($values[$name], "\0") !== false || $hasTraversal($values[$name])) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            }

            if (strlen($values[$name]) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            }
        }

        if ($values['signatures_path'] !== '') {
            $label = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SIGNATURES_PATH');
            $expandedSignaturesPath = $expandDocumentRoot($values['signatures_path']);

            if (strpos($values['signatures_path'], "\0") !== false || $hasTraversal($values['signatures_path'])) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            } elseif (strlen($values['signatures_path']) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            } elseif (!is_file($expandedSignaturesPath) || !is_readable($expandedSignaturesPath)) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_SIGNATURES_PATH');
            }
        }

        if ($values['suspicious_domains_path'] !== '') {
            $label = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SUSPICIOUS_DOMAINS_PATH');

            if (strpos($values['suspicious_domains_path'], "\0") !== false || $hasTraversal($values['suspicious_domains_path'])) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            } elseif (strlen($values['suspicious_domains_path']) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            }
        }

        foreach ([
            'malware_hashes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASHES_PATH'),
            'malware_hash_prefixes_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASH_PREFIXES_PATH'),
            'panelica_source_path' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SOURCE_PATH'),
        ] as $name => $label) {
            if ($values[$name] === '') {
                continue;
            }

            if (strpos($values[$name], "\0") !== false || $hasTraversal($values[$name])) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PATH', ['#FIELD#' => $label]);
            } elseif (strlen($values[$name]) > 4096) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TOO_LONG', ['#FIELD#' => $label]);
            }
        }

        if (!isset($scanProfiles[$values['scan_profile']])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_SCAN_PROFILE');
        }

        if (!isset($profiles[$values['profile']])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PROFILE');
        }

        if (!isset($actions[$values['action']])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_ACTION');
        }

        if (!preg_match('/^\d+$/', $values['batch_size']) || (int)$values['batch_size'] < 1 || (int)$values['batch_size'] > 1000) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_BATCH_SIZE');
        }

        if (!preg_match('/^\d+$/', $values['max_file_size_mb']) || (int)$values['max_file_size_mb'] < 1 || (int)$values['max_file_size_mb'] > 1024) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_MAX_FILE_SIZE');
        }

        if (!preg_match('/^\d+$/', $values['normalized_hash_max_file_size_mb']) || (int)$values['normalized_hash_max_file_size_mb'] < 1 || (int)$values['normalized_hash_max_file_size_mb'] > 1024) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_NORMALIZED_HASH_MAX_FILE_SIZE');
        }

        if (!preg_match('/^\d+$/', $values['ast_max_file_size']) || (int)$values['ast_max_file_size'] < 1 || (int)$values['ast_max_file_size'] > 104857600) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_AST_MAX_FILE_SIZE');
        }

        if (!preg_match('/^\d+$/', $values['entropy_min_length']) || (int)$values['entropy_min_length'] < 20 || (int)$values['entropy_min_length'] > 100000) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_ENTROPY_MIN_LENGTH');
        }

        if (!preg_match('/^\d+(?:\.\d+)?$/', $values['entropy_threshold']) || (float)$values['entropy_threshold'] < 0.1 || (float)$values['entropy_threshold'] > 8.0) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_ENTROPY_THRESHOLD');
        }

        if (!preg_match('/^\d+$/', $values['entropy_context_window']) || (int)$values['entropy_context_window'] < 0 || (int)$values['entropy_context_window'] > 10000) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_ENTROPY_CONTEXT_WINDOW');
        }

        if (!preg_match('/^\d+$/', $values['malware_hash_prefix_length']) || (int)$values['malware_hash_prefix_length'] < 8 || (int)$values['malware_hash_prefix_length'] > 12) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_MALWARE_HASH_PREFIX_LENGTH');
        }

        if ($values['panelica_download_url'] === '' || strlen($values['panelica_download_url']) > 2048 || !$isPanelicaWebDownloadUrlAllowed($values['panelica_download_url'])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_URL_ERROR');
        }

        [$excludePaths, $excludeErrors] = $normalizeLines($_POST['exclude_paths'] ?? '');

        if (!empty($excludeErrors)) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_EXCLUDE_PATHS');
        }

        $values['exclude_paths'] = implode("\n", $excludePaths);
        $postedValues = $values;

        if (empty($errors)) {
            foreach ($values as $name => $value) {
                Option::set($moduleId, $name, (string)$value);
            }

            $saved = true;
        }
    }
}

$values = [];

foreach ($optionNames as $name) {
    $values[$name] = $getOption($name);
}

if (!empty($errors) && is_array($postedValues)) {
    $values = array_merge($values, $postedValues);
}

$tabControl = new CAdminTabControl(
    'delement_antivirus_options',
    [
        [
            'DIV' => 'edit1',
            'TAB' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_TAB_MAIN'),
            'TITLE' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_TAB_MAIN_TITLE'),
        ],
    ]
);

if (!empty($errors)) {
    CAdminMessage::ShowMessage([
        'MESSAGE' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_TITLE'),
        'DETAILS' => implode('<br>', array_map('htmlspecialcharsbx', $errors)),
        'HTML' => true,
        'TYPE' => 'ERROR',
    ]);
} elseif ($saved) {
    CAdminMessage::ShowNote(Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SAVED'));
}

foreach ($notes as $note) {
    CAdminMessage::ShowNote($note);
}

$tabControl->Begin();
?>
<form method="post" action="<?php echo $APPLICATION->GetCurPage(); ?>?mid=<?php echo urlencode($moduleId); ?>&amp;lang=<?php echo LANGUAGE_ID; ?>">
    <?php echo bitrix_sessid_post(); ?>
    <?php $tabControl->BeginNextTab(); ?>
    <tr>
        <td width="40%" class="adm-detail-content-cell-l">
            <label for="delement_antivirus_scan_profile"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE'); ?></label>
        </td>
        <td width="60%" class="adm-detail-content-cell-r">
            <select id="delement_antivirus_scan_profile" name="scan_profile">
                <?php foreach ($scanProfiles as $value => $label): ?>
                    <option value="<?php echo htmlspecialcharsbx($value); ?>"<?php echo $values['scan_profile'] === $value ? ' selected' : ''; ?>>
                        <?php echo htmlspecialcharsbx($label); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <ul>
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_HINT_QUICK'); ?></li>
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_HINT_STANDARD'); ?></li>
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PROFILE_HINT_DEEP'); ?></li>
            </ul>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td width="40%" class="adm-detail-content-cell-l">
            <label for="delement_antivirus_scan_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PATH'); ?></label>
        </td>
        <td width="60%" class="adm-detail-content-cell-r">
            <input type="text" size="60" id="delement_antivirus_scan_path" name="scan_path" value="<?php echo htmlspecialcharsbx($values['scan_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_NOTE', [
                '#DOCUMENT_ROOT_VALUE#' => htmlspecialcharsbx((string)$_SERVER['DOCUMENT_ROOT']),
            ]); ?>
            <br>
            <a href="/bitrix/admin/delement_antivirus_scan.php?lang=<?php echo LANGUAGE_ID; ?>">
                <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_OPEN_SCAN'); ?>
            </a>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_profile"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <select id="delement_antivirus_profile" name="profile">
                <?php foreach ($profiles as $value => $label): ?>
                    <option value="<?php echo htmlspecialcharsbx($value); ?>"<?php echo $values['profile'] === $value ? ' selected' : ''; ?>>
                        <?php echo htmlspecialcharsbx($label); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_action"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <select id="delement_antivirus_action" name="action">
                <?php foreach ($actions as $value => $label): ?>
                    <option value="<?php echo htmlspecialcharsbx($value); ?>"<?php echo $values['action'] === $value ? ' selected' : ''; ?>>
                        <?php echo htmlspecialcharsbx($label); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <ul style="margin:0 0 8px 18px;padding:0;">
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_LEGEND_REPORT'); ?></li>
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_LEGEND_QUARANTINE'); ?></li>
                <li><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_LEGEND_DELETE'); ?></li>
            </ul>
            <div style="color:#b00020;font-weight:bold;">
                <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_DANGER_WARNING'); ?>
            </div>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_dry_run"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_DRY_RUN'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_dry_run" name="dry_run" value="Y"<?php echo $values['dry_run'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_DRY_RUN_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_quarantine_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_QUARANTINE_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="60" id="delement_antivirus_quarantine_path" name="quarantine_path" value="<?php echo htmlspecialcharsbx($values['quarantine_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_signatures_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SIGNATURES_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="60" id="delement_antivirus_signatures_path" name="signatures_path" value="<?php echo htmlspecialcharsbx($values['signatures_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SIGNATURES_PATH_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_batch_size"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_BATCH_SIZE'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="1" max="1000" id="delement_antivirus_batch_size" name="batch_size" value="<?php echo htmlspecialcharsbx($values['batch_size']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_max_file_size_mb"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MAX_FILE_SIZE_MB'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="1" max="1024" id="delement_antivirus_max_file_size_mb" name="max_file_size_mb" value="<?php echo htmlspecialcharsbx($values['max_file_size_mb']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_common_strings_prefilter"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_COMMON_STRINGS_PREFILTER'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_common_strings_prefilter" name="enable_common_strings_prefilter" value="Y"<?php echo $values['enable_common_strings_prefilter'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_COMMON_STRINGS_PREFILTER_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr class="heading">
        <td colspan="2"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_HASHING_SECTION'); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_normalized_hash"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_NORMALIZED_HASH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_normalized_hash" name="enable_normalized_hash" value="Y"<?php echo $values['enable_normalized_hash'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_NORMALIZED_HASH_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_normalized_hash_max_file_size_mb"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_NORMALIZED_HASH_MAX_FILE_SIZE_MB'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="1" max="1024" id="delement_antivirus_normalized_hash_max_file_size_mb" name="normalized_hash_max_file_size_mb" value="<?php echo htmlspecialcharsbx($values['normalized_hash_max_file_size_mb']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_ast_analysis"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_AST_ANALYSIS'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_ast_analysis" name="enable_ast_analysis" value="Y"<?php echo $values['enable_ast_analysis'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_AST_ANALYSIS_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_ast_max_file_size"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_AST_MAX_FILE_SIZE'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="1" max="104857600" id="delement_antivirus_ast_max_file_size" name="ast_max_file_size" value="<?php echo htmlspecialcharsbx($values['ast_max_file_size']); ?>">
        </td>
    </tr>
    <tr class="heading">
        <td colspan="2"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENTROPY_SECTION'); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_entropy_analyzer"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_ENTROPY_ANALYZER'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_entropy_analyzer" name="enable_entropy_analyzer" value="Y"<?php echo $values['enable_entropy_analyzer'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_ENTROPY_ANALYZER_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_entropy_in_deep_profile"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_ENTROPY_IN_DEEP_PROFILE'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_entropy_in_deep_profile" name="enable_entropy_in_deep_profile" value="Y"<?php echo $values['enable_entropy_in_deep_profile'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_entropy_min_length"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENTROPY_MIN_LENGTH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="20" max="100000" id="delement_antivirus_entropy_min_length" name="entropy_min_length" value="<?php echo htmlspecialcharsbx($values['entropy_min_length']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_entropy_threshold"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENTROPY_THRESHOLD'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" id="delement_antivirus_entropy_threshold" name="entropy_threshold" value="<?php echo htmlspecialcharsbx($values['entropy_threshold']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_entropy_context_window"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENTROPY_CONTEXT_WINDOW'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="0" max="10000" id="delement_antivirus_entropy_context_window" name="entropy_context_window" value="<?php echo htmlspecialcharsbx($values['entropy_context_window']); ?>">
        </td>
    </tr>
    <tr class="heading">
        <td colspan="2"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_URL_SECTION'); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_url_analyzer"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_URL_ANALYZER'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_url_analyzer" name="enable_url_analyzer" value="Y"<?php echo $values['enable_url_analyzer'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_URL_ANALYZER_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_suspicious_domains_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SUSPICIOUS_DOMAINS_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="70" id="delement_antivirus_suspicious_domains_path" name="suspicious_domains_path" value="<?php echo htmlspecialcharsbx($values['suspicious_domains_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SUSPICIOUS_DOMAINS_PATH_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr class="heading">
        <td colspan="2"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_KNOWN_MALWARE_SECTION'); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_enable_hash_db"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_HASH_DB'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_enable_hash_db" name="enable_hash_db" value="Y"<?php echo $values['enable_hash_db'] === 'Y' ? ' checked' : ''; ?>>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ENABLE_HASH_DB_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_malware_hashes_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASHES_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="70" id="delement_antivirus_malware_hashes_path" name="malware_hashes_path" value="<?php echo htmlspecialcharsbx($values['malware_hashes_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_malware_hash_prefixes_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASH_PREFIXES_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="70" id="delement_antivirus_malware_hash_prefixes_path" name="malware_hash_prefixes_path" value="<?php echo htmlspecialcharsbx($values['malware_hash_prefixes_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_malware_hash_prefix_length"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASH_PREFIX_LENGTH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="number" min="8" max="12" id="delement_antivirus_malware_hash_prefix_length" name="malware_hash_prefix_length" value="<?php echo htmlspecialcharsbx($values['malware_hash_prefix_length']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_MALWARE_HASHES_PATH_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr class="heading">
        <td colspan="2"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SECTION'); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_SOURCE'); ?></td>
        <td class="adm-detail-content-cell-r">
            <?php echo htmlspecialcharsbx($values['panelica_download_url']); ?>
            <input type="hidden" name="panelica_download_url" value="<?php echo htmlspecialcharsbx($values['panelica_download_url']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_LICENSE'); ?></td>
        <td class="adm-detail-content-cell-r">MIT</td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_panelica_source_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SOURCE_PATH'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="70" id="delement_antivirus_panelica_source_path" name="panelica_source_path" value="<?php echo htmlspecialcharsbx($values['panelica_source_path']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_panelica_source_commit"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SOURCE_COMMIT'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="text" size="40" id="delement_antivirus_panelica_source_commit" name="panelica_source_commit" value="<?php echo htmlspecialcharsbx($values['panelica_source_commit']); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_LAST_IMPORT_AT'); ?></td>
        <td class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx($values['panelica_last_import_at']); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORTED_COUNT'); ?></td>
        <td class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx($values['panelica_imported_count']); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_SOURCE_LICENSE'); ?></td>
        <td class="adm-detail-content-cell-r"><?php echo htmlspecialcharsbx($values['panelica_source_license']); ?></td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <input type="submit" name="download_panelica" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_DOWNLOAD_IMPORT_BUTTON'); ?>">
            <input type="submit" name="import_panelica" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_IMPORT_BUTTON'); ?>">
            <input type="submit" name="validate_hash_db" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_HASH_DB_VALIDATE_BUTTON'); ?>">
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l"></td>
        <td class="adm-detail-content-cell-r">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PANELICA_HINT'); ?>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <tr>
        <td class="adm-detail-content-cell-l adm-detail-valign-top">
            <label for="delement_antivirus_exclude_paths"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_EXCLUDE_PATHS'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <textarea id="delement_antivirus_exclude_paths" name="exclude_paths" rows="9" cols="70"><?php echo htmlspecialcharsbx($values['exclude_paths']); ?></textarea>
        </td>
    </tr>
    <?php $tabControl->Buttons(); ?>
    <input type="submit" name="save" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SAVE'); ?>" class="adm-btn-save">
    <input type="submit" name="apply" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_APPLY'); ?>">
    <input type="submit" name="restore_defaults" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_RESTORE_DEFAULTS'); ?>" onclick="return confirm('<?php echo CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_RESTORE_CONFIRM')); ?>');">
    <?php $tabControl->End(); ?>
</form>
