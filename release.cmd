@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "VERSION="
set "UNKNOWN_ARG="

if "%~1"=="" goto :usage

:parse_args
if "%~1"=="" goto :after_parse

set "ARG=%~1"

if /I "%ARG%"=="--help" goto :usage

if /I "%ARG%"=="--version" goto :parse_version_value

if /I "%ARG:~0,10%"=="--version=" (
    set "VERSION=%ARG:~10%"
) else (
    set "UNKNOWN_ARG=%ARG%"
)

shift
goto :parse_args

:parse_version_value
shift
if "%~1"=="" (
    echo Missing value for --version 1>&2
    goto :usage_error
)
set "VERSION=%~1"
shift
goto :parse_args

:after_parse

if not "%UNKNOWN_ARG%"=="" (
    echo Unknown argument: %UNKNOWN_ARG% 1>&2
    goto :usage_error
)

if "%VERSION%"=="" (
    echo Missing required argument: --version=x.x.x 1>&2
    goto :usage_error
)

set "RELEASE_VERSION=%VERSION%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "if ($env:RELEASE_VERSION -notmatch '^\d+\.\d+\.\d+$') { Write-Error 'Version must match x.x.x, for example 0.0.4'; exit 1 }"
if errorlevel 1 exit /b 1

set "ROOT=%~dp0"
set "MODULE_DIR=%ROOT%bitrix\modules\delement.antivirus"
set "ZIP_PATH=%ROOT%%VERSION%.zip"
set "STAGE_ROOT=%TEMP%\delement_antivirus_release_%VERSION%_%RANDOM%%RANDOM%"
set "STAGE_DIR=%STAGE_ROOT%\%VERSION%"

if not exist "%MODULE_DIR%\" (
    echo Module directory not found: %MODULE_DIR% 1>&2
    exit /b 1
)

if exist "%STAGE_ROOT%\" (
    rmdir /S /Q "%STAGE_ROOT%" >nul 2>nul
)

mkdir "%STAGE_DIR%" >nul 2>nul
if errorlevel 1 (
    echo Cannot create staging directory: %STAGE_DIR% 1>&2
    exit /b 1
)

robocopy "%MODULE_DIR%" "%STAGE_DIR%" /E /NFL /NDL /NJH /NJS /NP >nul
set "ROBOCOPY_EXIT=%ERRORLEVEL%"
if %ROBOCOPY_EXIT% GEQ 8 (
    echo Failed to copy module files. Robocopy exit code: %ROBOCOPY_EXIT% 1>&2
    goto :cleanup_error
)

set "RELEASE_STAGE_DIR=%STAGE_DIR%"
set "RELEASE_STAGE_ROOT=%STAGE_ROOT%"
set "RELEASE_ZIP_PATH=%ZIP_PATH%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $version=$env:RELEASE_VERSION; $stageDir=$env:RELEASE_STAGE_DIR; $stageRoot=$env:RELEASE_STAGE_ROOT; $zipPath=$env:RELEASE_ZIP_PATH; $versionFile=Join-Path $stageDir 'install\version.php'; if (-not (Test-Path -LiteralPath $versionFile)) { throw 'install/version.php was not found in staged module'; }; $text=[System.IO.File]::ReadAllText($versionFile); $date=(Get-Date).ToString('yyyy-MM-dd 00:00:00'); $text=[regex]::Replace($text, '''VERSION''\s*=>\s*''[^'']*''', '''VERSION'' => ''' + $version + ''''); $text=[regex]::Replace($text, '''VERSION_DATE''\s*=>\s*''[^'']*''', '''VERSION_DATE'' => ''' + $date + ''''); $encoding=New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($versionFile, $text, $encoding); if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force; }; Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $zipPath -Force; if (-not (Test-Path -LiteralPath $zipPath)) { throw 'zip_not_created'; }"

if errorlevel 1 goto :cleanup_error

rmdir /S /Q "%STAGE_ROOT%" >nul 2>nul

echo Release package created: %ZIP_PATH%
exit /b 0

:cleanup_error
if exist "%STAGE_ROOT%\" (
    rmdir /S /Q "%STAGE_ROOT%" >nul 2>nul
)
exit /b 1

:usage
echo Usage:
echo   release.cmd --version=x.x.x
echo.
echo Creates x.x.x.zip in the repository root.
echo The archive contains folder x.x.x with files from bitrix\modules\delement.antivirus.
exit /b 0

:usage_error
echo.
echo Usage:
echo   release.cmd --version=x.x.x
exit /b 2
