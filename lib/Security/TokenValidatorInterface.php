<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security;

interface TokenValidatorInterface
{
    public function withToken(string $data): TokenValidatorInterface;
    public function withEncription(): TokenValidatorInterface;
    public function withNonce(): TokenValidatorInterface;
    public function withSubject(string $subject): TokenValidatorInterface;
    public function validate(): bool;
    public function getData(): string;
    public function getExpiration(): int;
}