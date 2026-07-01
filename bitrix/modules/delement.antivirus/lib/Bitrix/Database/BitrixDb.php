<?php

namespace Delement\Antivirus\Bitrix\Database;

use Throwable;

class BitrixDb
{
    private $connection;

    public function __construct($connection = null)
    {
        $this->connection = $connection;
    }

    public function isAvailable(): bool
    {
        return $this->getConnection() !== null || $this->getLegacyDb() !== null;
    }

    public function tableExists(string $tableName): bool
    {
        if (!$this->isSafeTableName($tableName)) {
            return false;
        }

        $connection = $this->getConnection();

        if ($connection !== null) {
            try {
                if (method_exists($connection, 'isTableExists')) {
                    return (bool)$connection->isTableExists($tableName);
                }

                if (method_exists($connection, 'query')) {
                    $connection->query('SELECT 1 FROM ' . $tableName . ' WHERE 1=0');
                    return true;
                }
            } catch (Throwable $exception) {
                return false;
            }
        }

        $legacyDb = $this->getLegacyDb();

        if ($legacyDb !== null && method_exists($legacyDb, 'Query')) {
            try {
                $result = $legacyDb->Query('SELECT 1 FROM ' . $tableName . ' WHERE 1=0', true);

                return is_object($result);
            } catch (Throwable $exception) {
                return false;
            }
        }

        return false;
    }

    public function fetchAgents(): array
    {
        $sql = 'SELECT ID, MODULE_ID, NAME, ACTIVE, NEXT_EXEC FROM b_agent ORDER BY ID ASC';
        $rows = [];
        $connection = $this->getConnection();

        if ($connection !== null && method_exists($connection, 'query')) {
            $result = $connection->query($sql);

            while (is_object($result) && method_exists($result, 'fetch') && ($row = $result->fetch())) {
                $rows[] = $this->normalizeAgentRow(is_array($row) ? $row : []);
            }

            return $rows;
        }

        $legacyDb = $this->getLegacyDb();

        if ($legacyDb !== null && method_exists($legacyDb, 'Query')) {
            $result = $legacyDb->Query($sql);

            while (is_object($result) && method_exists($result, 'Fetch') && ($row = $result->Fetch())) {
                $rows[] = $this->normalizeAgentRow(is_array($row) ? $row : []);
            }
        }

        return $rows;
    }

    public function isModuleInstalled(string $moduleId): ?bool
    {
        $moduleId = trim($moduleId);

        if ($moduleId === '') {
            return false;
        }

        try {
            if (class_exists('\\Bitrix\\Main\\ModuleManager')) {
                return (bool)\Bitrix\Main\ModuleManager::isModuleInstalled($moduleId);
            }

            if (class_exists('\\CModule') && method_exists('\\CModule', 'IsModuleInstalled')) {
                return (bool)\CModule::IsModuleInstalled($moduleId);
            }
        } catch (Throwable $exception) {
            return null;
        }

        return null;
    }

    protected function normalizeAgentRow(array $row): array
    {
        return [
            'ID' => isset($row['ID']) ? (string)$row['ID'] : '',
            'MODULE_ID' => isset($row['MODULE_ID']) ? (string)$row['MODULE_ID'] : '',
            'NAME' => isset($row['NAME']) ? (string)$row['NAME'] : '',
            'ACTIVE' => isset($row['ACTIVE']) ? (string)$row['ACTIVE'] : '',
            'NEXT_EXEC' => isset($row['NEXT_EXEC']) ? (string)$row['NEXT_EXEC'] : '',
            'LAST_EXEC' => isset($row['LAST_EXEC']) ? (string)$row['LAST_EXEC'] : '',
        ];
    }

    private function getConnection()
    {
        if ($this->connection !== null) {
            return $this->connection;
        }

        if (!class_exists('\\Bitrix\\Main\\Application')) {
            return null;
        }

        try {
            $application = \Bitrix\Main\Application::getInstance();
            $this->connection = $application->getConnection();
        } catch (Throwable $exception) {
            $this->connection = null;
        }

        return $this->connection;
    }

    private function getLegacyDb()
    {
        return isset($GLOBALS['DB']) && is_object($GLOBALS['DB']) ? $GLOBALS['DB'] : null;
    }

    private function isSafeTableName(string $tableName): bool
    {
        return preg_match('/^[a-zA-Z0-9_]+$/', $tableName) === 1;
    }
}
