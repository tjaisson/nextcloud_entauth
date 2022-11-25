<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security;

interface KeyInterface
{
    const SIGN_KEY_LEN = 32;
    const CYPHER_KEY_LEN = 32;
    public function getId(): int;
    public function getSignKey(): string;
    public function getCypherKey(): string;
    public function getExpiration(): int;
}