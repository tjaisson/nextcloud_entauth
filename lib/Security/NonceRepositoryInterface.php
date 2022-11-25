<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security;

interface NonceRepositoryInterface
{
    const LENGTH = 8;
    /**
     * Crée un nonce en s'assurant qu'il n'existe pas déjà en base.
     */
    public function createNonce(): int;

    /**
     * Valide qu'un nonce n'est pas déjà en base et le stocke en base
     * pour s'assurer qu'il n'est pas réemployé.
     * 
     * @param int $nonce le nonce à valider
     * @param int $exp Timestamp à partir duquel le nonce pourra être réemployé.
     */
    public function validateNonce(int $nonce, int $exp): bool;
}