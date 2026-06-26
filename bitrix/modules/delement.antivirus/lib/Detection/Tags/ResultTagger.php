<?php

namespace Delement\Antivirus\Detection\Tags;

use Delement\Antivirus\Detection\Finding;

class ResultTagger
{
    private $pathTagger;
    private $findingTagger;

    public function __construct(PathTagger $pathTagger = null, FindingTagger $findingTagger = null)
    {
        $this->pathTagger = $pathTagger ?: new PathTagger();
        $this->findingTagger = $findingTagger ?: new FindingTagger();
    }

    public function tagFindings(array $findings): array
    {
        $tagged = [];

        foreach ($findings as $finding) {
            if ($finding instanceof Finding) {
                $tagged[] = $this->findingTagger->tag($finding);
                continue;
            }

            $tagged[] = $finding;
        }

        return $tagged;
    }

    public function tagsForResult(string $filePath, array $findings): array
    {
        $tags = $this->pathTagger->tagsForPath($filePath);

        foreach ($findings as $finding) {
            if ($finding instanceof Finding) {
                $findingTags = $finding->getTags();

                if (empty($findingTags)) {
                    $findingTags = $this->findingTagger->tagsForFindingArray($finding->toArray());
                }

                $tags = TagCatalog::merge($tags, $findingTags);
                continue;
            }

            if (is_array($finding)) {
                $tags = TagCatalog::merge($tags, $this->findingTagger->tagsForFindingArray($finding));
            }
        }

        return TagCatalog::normalize($tags);
    }

    public function tagsForResultArray(array $result): array
    {
        $filePath = (string)($result['file_path'] ?? '');
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];
        $existingTags = isset($result['tags']) && is_array($result['tags']) ? $result['tags'] : [];

        return TagCatalog::merge($existingTags, $this->tagsForResult($filePath, $findings));
    }

    public function tagResultArray(array $result): array
    {
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];
        $taggedFindings = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                $taggedFindings[] = $finding;
                continue;
            }

            $finding['tags'] = $this->findingTagger->tagsForFindingArray($finding);
            $taggedFindings[] = $finding;
        }

        $result['findings'] = $taggedFindings;
        $result['tags'] = $this->tagsForResultArray($result);

        return $result;
    }
}
