<?php

namespace Delement\Antivirus\Detection\Url;

class UrlExtractor
{
    public function extract(string $content, string $filePath): array
    {
        if ($content === '') {
            return [];
        }

        $items = [];
        $seen = [];

        if (preg_match_all('~https?://[^\s\'"<>()\[\]{}]+~i', $content, $matches, PREG_OFFSET_CAPTURE) !== 1) {
            return [];
        }

        foreach ($matches[0] as $match) {
            $rawUrl = (string)$match[0];
            $offset = (int)$match[1];
            $url = $this->trimUrl($rawUrl);

            if ($url === '') {
                continue;
            }

            $key = strtolower($url) . ':' . $offset;

            if (isset($seen[$key])) {
                continue;
            }

            $line = $this->lineNumber($content, $offset);
            $lineText = $this->lineText($content, $offset);

            $items[] = [
                'url' => $url,
                'domain' => $this->domainFromUrl($url),
                'offset' => $offset,
                'line' => $line,
                'line_text' => $lineText,
                'context' => $this->context($content, $offset, strlen($rawUrl)),
                'file_path' => $filePath,
            ];
            $seen[$key] = true;
        }

        return $items;
    }

    private function trimUrl(string $url): string
    {
        return rtrim($url, ".,;'");
    }

    private function domainFromUrl(string $url): string
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (!is_string($host) || $host === '') {
            return '';
        }

        return strtolower(rtrim($host, '.'));
    }

    private function lineNumber(string $content, int $offset): int
    {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }

    private function lineText(string $content, int $offset): string
    {
        $start = strrpos(substr($content, 0, $offset), "\n");
        $start = $start === false ? 0 : $start + 1;
        $end = strpos($content, "\n", $offset);
        $end = $end === false ? strlen($content) : $end;

        return trim((string)substr($content, $start, $end - $start));
    }

    private function context(string $content, int $offset, int $length): string
    {
        $start = max(0, $offset - 240);
        $end = min(strlen($content), $offset + $length + 240);
        $context = substr($content, $start, $end - $start);

        return trim((string)preg_replace('/\s+/', ' ', $context));
    }
}
