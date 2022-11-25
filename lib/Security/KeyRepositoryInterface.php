<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security;

interface KeyRepositoryInterface
{
    public function find(int $id): ?KeyInterface;
    public function getSuitableKey(int $ttl): KeyInterface;
}