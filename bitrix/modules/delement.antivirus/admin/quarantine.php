<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Quarantine\QuarantineManager;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';
$right = $APPLICATION->GetGroupRight($moduleId);

Loc::loadMessages(__FILE__);

if ($right < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_TITLE'));

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

if (!function_exists('delement_antivirus_quarantine_status_label')) {
    function delement_antivirus_quarantine_status_label($status): string
    {
        $status = trim((string)$status);
        $key = strtoupper(str_replace('-', '_', $status));
        $label = $key !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_STATUS_' . $key)
            : '';

        return $label ?: $status;
    }
}

if (!function_exists('delement_antivirus_quarantine_scan_status_label')) {
    function delement_antivirus_quarantine_scan_status_label($status): string
    {
        $status = trim((string)$status);
        $key = strtoupper(str_replace('-', '_', $status));
        $label = $key !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_SCAN_STATUS_' . $key)
            : '';

        return $label ?: $status;
    }
}

if (!function_exists('delement_antivirus_quarantine_manager')) {
    function delement_antivirus_quarantine_manager(string $moduleId, string $documentRoot): QuarantineManager
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

$messages = [];
$errors = [];
$manager = null;
$items = [];

try {
    $manager = delement_antivirus_quarantine_manager($moduleId, (string)$_SERVER['DOCUMENT_ROOT']);
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_MANAGER_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['quarantine_action'])) {
    $action = (string)$_POST['quarantine_action'];
    $id = isset($_POST['id']) ? (string)$_POST['id'] : '';

    if ($right < 'W') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ERROR_ACCESS');
    } elseif (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ERROR_SESSID');
    } elseif ($manager === null) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ERROR_MANAGER_NOT_READY');
    } elseif ($id === '') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ERROR_ID_REQUIRED');
    } else {
        try {
            if ($action === 'restore') {
                $manager->restore($id);
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_RESTORED');
            } elseif ($action === 'delete') {
                $manager->deletePayload($id);
                $messages[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_DELETED');
            } else {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ERROR_UNKNOWN_ACTION');
            }
        } catch (Throwable $exception) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ACTION_ERROR', [
                '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
            ]);
        }
    }
}

if ($manager !== null) {
    try {
        $items = $manager->listItems();
    } catch (Throwable $exception) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_LIST_ERROR', [
            '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
        ]);
    }
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';

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

if (empty($items)) {
    CAdminMessage::ShowNote(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_EMPTY'));
} else {
    ?>
    <table class="adm-list-table">
        <thead>
        <tr class="adm-list-table-header">
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ID'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_STATUS'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ORIGINAL_PATH'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_QUARANTINED_AT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_SCAN_ID'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_VERDICT'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_SIZE'); ?></div></td>
            <td class="adm-list-table-cell"><div class="adm-list-table-cell-inner"><?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_ACTIONS'); ?></div></td>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($items as $item): ?>
            <?php
            $id = isset($item['id']) ? (string)$item['id'] : '';
            $isActive = (string)($item['status'] ?? '') === QuarantineManager::STATUS_QUARANTINED;
            $payloadExists = !empty($item['payload_exists']);
            ?>
            <tr class="adm-list-table-row">
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx($id); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_quarantine_status_label($item['status'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['original_path'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['quarantined_at'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx((string)($item['scan_id'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo htmlspecialcharsbx(delement_antivirus_quarantine_scan_status_label($item['scan_status'] ?? '')); ?></td>
                <td class="adm-list-table-cell"><?php echo (int)($item['size'] ?? 0); ?></td>
                <td class="adm-list-table-cell">
                    <?php if ($right >= 'W' && $isActive && $payloadExists): ?>
                        <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['quarantine_action', 'id', 'sessid']); ?>" style="display:inline-block;margin:0 6px 0 0;">
                            <?php echo bitrix_sessid_post(); ?>
                            <input type="hidden" name="quarantine_action" value="restore">
                            <input type="hidden" name="id" value="<?php echo htmlspecialcharsbx($id); ?>">
                            <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_RESTORE'); ?>">
                        </form>
                        <form method="post" action="<?php echo $APPLICATION->GetCurPageParam('', ['quarantine_action', 'id', 'sessid']); ?>" style="display:inline-block;margin:0;">
                            <?php echo bitrix_sessid_post(); ?>
                            <input type="hidden" name="quarantine_action" value="delete">
                            <input type="hidden" name="id" value="<?php echo htmlspecialcharsbx($id); ?>">
                            <input type="submit" class="adm-btn" value="<?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_DELETE'); ?>" onclick="return confirm('<?php echo CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_DELETE_CONFIRM')); ?>');">
                        </form>
                    <?php elseif (!$payloadExists && $isActive): ?>
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_PAYLOAD_MISSING'); ?>
                    <?php else: ?>
                        <?php echo Loc::getMessage('DELEMENT_ANTIVIRUS_QUARANTINE_NO_ACTIONS'); ?>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
