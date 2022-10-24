<?php
namespace OCA\EntAuth\Security;

interface TokenValidatorInterface
{
    public function withToken(string $data): TokenValidatorInterface;
    public function withEncription(): TokenValidatorInterface;
    public function withNonce(): TokenValidatorInterface;
    public function validate(): bool;
    public function getData(): string;
}