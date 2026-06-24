<?php

namespace Delement\Antivirus\Detection\Htaccess;

use Delement\Antivirus\Detection\Severity;

class HtaccessRule
{
    private $signatureId;
    private $name;
    private $severity;
    private $score;

    public function __construct(string $signatureId, string $name, string $severity, int $score)
    {
        $this->signatureId = $signatureId;
        $this->name = $name;
        $this->severity = $severity;
        $this->score = $score;
    }

    public static function phpHandlerForStaticExt(): self
    {
        return new self('htaccess_php_handler_for_static_ext', 'PHP handler for static extension in .htaccess', Severity::CRITICAL, 10);
    }

    public static function autoPrependAppend(): self
    {
        return new self('htaccess_auto_prepend_append', 'auto_prepend_file or auto_append_file in .htaccess', Severity::CRITICAL, 10);
    }

    public static function embeddedCode(): self
    {
        return new self('htaccess_embedded_code', 'Embedded code marker in .htaccess', Severity::CRITICAL, 10);
    }

    public static function suspiciousRewrite(): self
    {
        return new self('htaccess_suspicious_rewrite', 'Suspicious rewrite rule in .htaccess', Severity::HIGH, 7);
    }

    public static function foreignCmsMarker(): self
    {
        return new self('htaccess_foreign_cms_marker', 'Foreign CMS marker in Bitrix .htaccess', Severity::MEDIUM, 4);
    }

    public static function accessBypass(): self
    {
        return new self('htaccess_access_bypass', 'Access bypass directive in sensitive .htaccess', Severity::HIGH, 7);
    }

    public function getSignatureId(): string
    {
        return $this->signatureId;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getScore(): int
    {
        return $this->score;
    }
}
