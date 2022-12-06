<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\KeyInterface;

class Key implements KeyInterface
{
    public function __construct($rec)
    {
        $this->id = (int)$rec->id;
        $this->sign = (string)$rec->sign;
        $this->cypher = (string)$rec->cypher;
        $this->exp = (int)$rec->exp;
    }

    protected int $id;
    protected string $sign;
    protected string $cypher;
    protected int $exp;
    public function getId(): int
    {
        return $this->id;
    }
    public function getSignKey(): string
    {
        return $this->sign;
    }
    public function getCypherKey(): string
    {
        return $this->cypher;
    }
    public function getExpiration(): int
    {
        return $this->exp;
    }
}