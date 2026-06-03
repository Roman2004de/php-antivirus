<?php

use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Whitelist\WhitelistManager;

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_before.php';

$moduleId = 'delement.antivirus';
$right = $APPLICATION->GetGroupRight($moduleId);

Loc::loadMessages(__FILE__);

if ($right < 'R') {
    $APPLICATION->AuthForm(Loc::getMessage('ACCESS_DENIED'));
}

if (!Loader::includeModule($moduleId)) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_admin_after.php';
    CAdminMessage::ShowMessage(Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_MODULE_NOT_LOADED'));
    require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
    return;
}

$APPLICATION->SetTitle(Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_TITLE'));

if (!function_exists('delement_antivirus_whitelist_type_label')) {
    function delement_antivirus_whitelist_type_label($type): string
    {
        $type = strtoupper(str_replace('-', '_', trim((string)$type)));
        $label = $type !== ''
            ? Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_TYPE_' . $type)
            : '';

        return $label ?: $type;
    }
}

if (!function_exists('delement_antivirus_whitelist_rule_value')) {
    function delement_antivirus_whitelist_rule_value(array $rule): string
    {
        $type = (string)($rule['type'] ?? '');

        if ($type === WhitelistManager::TYPE_PATH) {
            return (string)($rule['path'] ?? '');
        }

        if ($type === WhitelistManager::TYPE_PATH_REGEX) {
            return (string)($rule['pattern'] ?? '');
        }

        if ($type === WhitelistManager::TYPE_HASH) {
            return (string)($rule['hash'] ?? '');
        }

        if ($type === WhitelistManager::TYPE_SIGNATURE) {
            return (string)($rule['signature_id'] ?? '');
        }

        if ($type === WhitelistManager::TYPE_FILE_SIGNATURE) {
            return trim((string)($rule['path'] ?? '') . ' + ' . (string)($rule['signature_id'] ?? ''));
        }

        return '';
    }
}

if (!function_exists('delement_antivirus_whitelist_sort_rules')) {
    function delement_antivirus_whitelist_sort_rules(array &$rules, $field, $order): void
    {
        $allowedFields = [
            'id',
            'active',
            'type',
            'value',
            'created_at',
            'created_by',
            'disabled_at',
        ];
        $field = in_array((string)$field, $allowedFields, true) ? (string)$field : 'created_at';
        $direction = strtolower((string)$order) === 'asc' ? 1 : -1;

        usort($rules, static function (array $left, array $right) use ($field, $direction) {
            if ($field === 'value') {
                $leftValue = delement_antivirus_whitelist_rule_value($left);
                $rightValue = delement_antivirus_whitelist_rule_value($right);
            } elseif ($field === 'created_by') {
                $leftValue = (int)($left[$field] ?? 0);
                $rightValue = (int)($right[$field] ?? 0);
            } elseif ($field === 'active') {
                $leftValue = !empty($left[$field]) ? 1 : 0;
                $rightValue = !empty($right[$field]) ? 1 : 0;
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

if (!function_exists('delement_antivirus_whitelist_rule_ids')) {
    function delement_antivirus_whitelist_rule_ids(array $rules): array
    {
        $ids = [];

        foreach ($rules as $rule) {
            $id = isset($rule['id']) ? (string)$rule['id'] : '';

            if ($id !== '') {
                $ids[] = $id;
            }
        }

        return $ids;
    }
}

$messages = [];
$errors = [];
$manager = null;
$rules = [];
$sTableID = 'tbl_delement_antivirus_whitelist';
$oSort = new CAdminSorting($sTableID, 'created_at', 'desc');
$lAdmin = new CAdminList($sTableID, $oSort);

try {
    $manager = new WhitelistManager();
} catch (Throwable $exception) {
    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_MANAGER_ERROR', [
        '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
    ]);
}

if ($manager !== null) {
    try {
        $rules = $manager->listRules();
    } catch (Throwable $exception) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_LIST_ERROR', [
            '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
        ]);
    }
}

if (($selectedIds = $lAdmin->GroupAction()) !== false) {
    $action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';

    if ($right < 'W') {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ERROR_ACCESS');
    } elseif (!check_bitrix_sessid()) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ERROR_SESSID');
    } elseif ($manager === null) {
        $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ERROR_MANAGER_NOT_READY');
    } else {
        if (isset($_REQUEST['action_target']) && $_REQUEST['action_target'] === 'selected') {
            $selectedIds = delement_antivirus_whitelist_rule_ids($rules);
        }

        if (!is_array($selectedIds)) {
            $selectedIds = [$selectedIds];
        }

        $selectedIds = array_values(array_unique(array_filter(array_map('strval', $selectedIds), 'strlen')));
        $processedCount = 0;

        foreach ($selectedIds as $id) {
            try {
                if ($action === 'activate') {
                    $manager->activateRule($id);
                    $processedCount++;
                } elseif ($action === 'deactivate') {
                    $manager->deactivateRule($id);
                    $processedCount++;
                } elseif ($action === 'delete') {
                    $manager->deleteRule($id);
                    $processedCount++;
                } else {
                    $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ERROR_UNKNOWN_ACTION');
                    break;
                }
            } catch (Throwable $exception) {
                $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ACTION_ERROR', [
                    '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
                ]);
            }
        }

        if ($processedCount > 0) {
            $messageKey = 'DELEMENT_ANTIVIRUS_WHITELIST_ACTION_DONE';

            if ($action === 'activate') {
                $messageKey = 'DELEMENT_ANTIVIRUS_WHITELIST_ACTIVATED';
            } elseif ($action === 'deactivate') {
                $messageKey = 'DELEMENT_ANTIVIRUS_WHITELIST_DEACTIVATED';
            } elseif ($action === 'delete') {
                $messageKey = 'DELEMENT_ANTIVIRUS_WHITELIST_DELETED';
            }

            $messages[] = Loc::getMessage($messageKey, ['#COUNT#' => $processedCount]);
        }

        try {
            $rules = $manager->listRules();
        } catch (Throwable $exception) {
            $errors[] = Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_LIST_ERROR', [
                '#ERROR#' => htmlspecialcharsbx($exception->getMessage()),
            ]);
        }
    }
}

delement_antivirus_whitelist_sort_rules($rules, $by ?? 'created_at', $order ?? 'desc');

$lAdmin->AddHeaders([
    [
        'id' => 'ID',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ID'),
        'sort' => 'id',
        'default' => true,
    ],
    [
        'id' => 'ACTIVE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ACTIVE'),
        'sort' => 'active',
        'default' => true,
    ],
    [
        'id' => 'TYPE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_TYPE'),
        'sort' => 'type',
        'default' => true,
    ],
    [
        'id' => 'VALUE',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_VALUE'),
        'sort' => 'value',
        'default' => true,
    ],
    [
        'id' => 'CREATED_AT',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_CREATED_AT'),
        'sort' => 'created_at',
        'default' => true,
    ],
    [
        'id' => 'CREATED_BY',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_CREATED_BY'),
        'sort' => 'created_by',
        'default' => true,
    ],
    [
        'id' => 'DISABLED_AT',
        'content' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DISABLED_AT'),
        'sort' => 'disabled_at',
        'default' => true,
    ],
]);

$rsData = new CDBResult();
$rsData->InitFromArray($rules);
$rsData = new CAdminResult($rsData, $sTableID);
$rsData->NavStart();
$lAdmin->NavText($rsData->GetNavPrint(Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_LIST_NAV')));

while ($rule = $rsData->NavNext(true, 'f_')) {
    $id = isset($rule['id']) ? (string)$rule['id'] : '';

    if ($id === '') {
        continue;
    }

    $isActive = !empty($rule['active']);
    $row = $lAdmin->AddRow($id, $rule);
    $row->AddViewField('ID', htmlspecialcharsbx($id));
    $row->AddViewField('ACTIVE', $isActive ? Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_YES') : Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_NO'));
    $row->AddViewField('TYPE', htmlspecialcharsbx(delement_antivirus_whitelist_type_label($rule['type'] ?? '')));
    $row->AddViewField('VALUE', htmlspecialcharsbx(delement_antivirus_whitelist_rule_value($rule)));
    $row->AddViewField('CREATED_AT', htmlspecialcharsbx((string)($rule['created_at'] ?? '')));
    $row->AddViewField('CREATED_BY', (int)($rule['created_by'] ?? 0));
    $row->AddViewField('DISABLED_AT', htmlspecialcharsbx((string)($rule['disabled_at'] ?? '')));

    if ($right >= 'W') {
        $actions = [
            [
                'ICON' => $isActive ? 'deactivate' : 'activate',
                'TEXT' => $isActive
                    ? Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DEACTIVATE')
                    : Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ACTIVATE'),
                'ACTION' => $lAdmin->ActionDoGroup($id, $isActive ? 'deactivate' : 'activate'),
            ],
            ['SEPARATOR' => true],
            [
                'ICON' => 'delete',
                'TEXT' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DELETE'),
                'ACTION' => "if(confirm('" . CUtil::JSEscape(Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DELETE_CONFIRM')) . "')) " . $lAdmin->ActionDoGroup($id, 'delete'),
            ],
        ];

        $row->AddActions($actions);
    }
}

$lAdmin->AddFooter([
    [
        'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_LIST_TOTAL'),
        'value' => $rsData->SelectedRowsCount(),
    ],
    [
        'counter' => true,
        'title' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_LIST_SELECTED'),
        'value' => '0',
    ],
]);

if ($right >= 'W') {
    $lAdmin->AddGroupActionTable([
        'activate' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_ACTIVATE'),
        'deactivate' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DEACTIVATE'),
        'delete' => Loc::getMessage('DELEMENT_ANTIVIRUS_WHITELIST_DELETE'),
    ]);
}

$lAdmin->CheckListMode();

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

$lAdmin->DisplayList();

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/epilog_admin.php';
