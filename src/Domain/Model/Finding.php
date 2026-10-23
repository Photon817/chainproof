<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Enum\Severity;
use App\Domain\Enum\VulnType;

final class Finding
{
    public string $status = 'candidate';

    public ?Verdict $verdict = null;

    public ?AttackPlan $plan = null;

    /** @var array<string, mixed>|null */
    public ?array $proof = null;

    /**
     * @param array<string, mixed> $meta
     */
    public function __construct(
        public string $id,
        public VulnType $type,
        public Severity $severity,
        public string $contract,
        public string $function,
        public string $title,
        public string $description,
        public string $file,
        public int $lineStart,
        public int $lineEnd,
        public string $vulnerableCode,
        public string $attackVector,
        public string $remediation,
        public float $confidence,
        public string $skill,
        public array $meta = [],
    ) {
    }

    public function withPlan(?AttackPlan $plan): self
    {
        $this->plan = $plan;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type->value,
            'severity' => $this->severity->value,
            'contract' => $this->contract,
            'function' => $this->function,
            'title' => $this->title,
            'description' => $this->description,
            'file' => $this->file,
            'line_start' => $this->lineStart,
            'line_end' => $this->lineEnd,
            'vulnerable_code' => $this->vulnerableCode,
            'attack_vector' => $this->attackVector,
            'remediation' => $this->remediation,
            'confidence' => $this->confidence,
            'skill' => $this->skill,
            'status' => $this->status,
            'verdict' => $this->verdict?->toArray(),
            'plan' => $this->plan?->toArray(),
            'proof' => $this->proof,
            'meta' => $this->meta,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $finding = new self(
            (string) $data['id'],
            VulnType::parse($data['type'] ?? null),
            Severity::parse($data['severity'] ?? null),
            (string) ($data['contract'] ?? ''),
            (string) ($data['function'] ?? ''),
            (string) ($data['title'] ?? ''),
            (string) ($data['description'] ?? ''),
            (string) ($data['file'] ?? ''),
            (int) ($data['line_start'] ?? 0),
            (int) ($data['line_end'] ?? 0),
            (string) ($data['vulnerable_code'] ?? ''),
            (string) ($data['attack_vector'] ?? ''),
            (string) ($data['remediation'] ?? ''),
            (float) ($data['confidence'] ?? 0.0),
            (string) ($data['skill'] ?? ''),
            is_array($data['meta'] ?? null) ? $data['meta'] : [],
        );

        $finding->status = (string) ($data['status'] ?? 'candidate');
        $finding->verdict = is_array($data['verdict'] ?? null) ? Verdict::fromArray($data['verdict']) : null;
        $finding->plan = is_array($data['plan'] ?? null) ? AttackPlan::fromArray($data['plan']) : null;
        $finding->proof = is_array($data['proof'] ?? null) ? $data['proof'] : null;

        return $finding;
    }
}
