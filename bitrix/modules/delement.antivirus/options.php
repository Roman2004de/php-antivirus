<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Localization\Loc;

if (!$USER->IsAdmin()) {
    return;
}

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

require __DIR__ . '/default_option.php';

$defaults = isset($delement_antivirus_default_option) && is_array($delement_antivirus_default_option)
    ? $delement_antivirus_default_option
    : [];

$profiles = [
    'balanced' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_BALANCED'),
    'strict' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_STRICT'),
    'paranoid' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_PROFILE_PARANOID'),
];

$actions = [
    'report' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_REPORT'),
    'quarantine' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_QUARANTINE'),
    'delete' => Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ACTION_DELETE'),
];

$optionNames = [
    'scan_path',
    'profile',
    'action',
    'dry_run',
    'quarantine_path',
    'exclude_paths',
    'batch_size',
    'max_file_size_mb',
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
$saved = false;
$postedValues = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['save']) || isset($_POST['apply']) || isset($_POST['restore_defaults']))) {
    if (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_SESSID');
    } elseif (isset($_POST['restore_defaults'])) {
        foreach ($optionNames as $name) {
            Option::set($moduleId, $name, $getDefault($name));
        }

        $saved = true;
    } else {
        $values = [];

        $values['scan_path'] = trim((string)($_POST['scan_path'] ?? ''));
        $values['profile'] = (string)($_POST['profile'] ?? '');
        $values['action'] = (string)($_POST['action'] ?? '');
        $values['dry_run'] = isset($_POST['dry_run']) && $_POST['dry_run'] === 'Y' ? 'Y' : 'N';
        $values['quarantine_path'] = trim((string)($_POST['quarantine_path'] ?? ''));
        $values['batch_size'] = trim((string)($_POST['batch_size'] ?? ''));
        $values['max_file_size_mb'] = trim((string)($_POST['max_file_size_mb'] ?? ''));

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

        if (!isset($profiles[$values['profile']])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_PROFILE');
        }

        if (!isset($actions[$values['action']])) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_ACTION');
        }

        if ($values['action'] === 'delete' && $values['dry_run'] !== 'Y') {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_DELETE_WITHOUT_DRY_RUN');
        }

        if (!preg_match('/^\d+$/', $values['batch_size']) || (int)$values['batch_size'] < 1 || (int)$values['batch_size'] > 1000) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_BATCH_SIZE');
        }

        if (!preg_match('/^\d+$/', $values['max_file_size_mb']) || (int)$values['max_file_size_mb'] < 1 || (int)$values['max_file_size_mb'] > 1024) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_ERROR_MAX_FILE_SIZE');
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

$tabControl->Begin();
?>
<form method="post" action="<?php echo $APPLICATION->GetCurPage(); ?>?mid=<?php echo urlencode($moduleId); ?>&amp;lang=<?php echo LANGUAGE_ID; ?>">
    <?php echo bitrix_sessid_post(); ?>
    <?php $tabControl->BeginNextTab(); ?>
    <tr>
        <td width="40%" class="adm-detail-content-cell-l">
            <label for="delement_antivirus_scan_path"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SCAN_PATH'); ?></label>
        </td>
        <td width="60%" class="adm-detail-content-cell-r">
            <input type="text" size="60" id="delement_antivirus_scan_path" name="scan_path" value="<?php echo htmlspecialcharsbx($values['scan_path']); ?>">
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
        <td class="adm-detail-content-cell-l">
            <label for="delement_antivirus_dry_run"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_DRY_RUN'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <input type="checkbox" id="delement_antivirus_dry_run" name="dry_run" value="Y"<?php echo $values['dry_run'] === 'Y' ? ' checked' : ''; ?>>
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
        <td class="adm-detail-content-cell-l adm-detail-valign-top">
            <label for="delement_antivirus_exclude_paths"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_EXCLUDE_PATHS'); ?></label>
        </td>
        <td class="adm-detail-content-cell-r">
            <textarea id="delement_antivirus_exclude_paths" name="exclude_paths" rows="9" cols="70"><?php echo htmlspecialcharsbx($values['exclude_paths']); ?></textarea>
        </td>
    </tr>
    <tr>
        <td colspan="2">
            <?php echo BeginNote(); ?>
            <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_NOTE'); ?>
            <br>
            <a href="/bitrix/admin/delement_antivirus_scan.php?lang=<?php echo LANGUAGE_ID; ?>">
                <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_OPEN_SCAN'); ?>
            </a>
            <?php echo EndNote(); ?>
        </td>
    </tr>
    <?php $tabControl->Buttons(); ?>
    <input type="submit" name="save" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_SAVE'); ?>" class="adm-btn-save">
    <input type="submit" name="apply" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_APPLY'); ?>">
    <input type="submit" name="restore_defaults" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_RESTORE_DEFAULTS'); ?>" onclick="return confirm('<?php echo CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_OPTIONS_RESTORE_CONFIRM')); ?>');">
    <?php $tabControl->End(); ?>
</form>
