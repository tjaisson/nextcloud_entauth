<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security;

interface TokenBuilderInterface
{
    public function withTTL(int $ttl): TokenBuilderInterface;
    public function withExpiration(int $expiration): TokenBuilderInterface;
    public function withData(string $data): TokenBuilderInterface;
    public function withSubject(string $subject): TokenBuilderInterface;
    public function withEncription(): TokenBuilderInterface;
    public function withNonce(): TokenBuilderInterface;
    public function toString(): string;
}