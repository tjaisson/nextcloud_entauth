<?php
namespace OCA\EntAuth\Security;

interface KeyRepositoryInterface
{
    public function find(int $id): ?KeyInterface;
    public function getSuitableKey(int $ttl): KeyInterface;
}