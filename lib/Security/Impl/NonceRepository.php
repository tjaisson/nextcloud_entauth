<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\NonceRepositoryInterface;
use OCP\IDBConnection;
use Doctrine\DBAL\FetchMode;

class NonceRepository implements NonceRepositoryInterface
{
    const TABLE = 'entauth_nonces';

    /** @var \OCP\IDBConnection $db */
    protected $db;

    /** 
     * @param \OCP\IDBConnection $db
     */
    public function __construct(IDBConnection $db) { $this->db = $db; }
    
    const MAX_ATTEMPTS = 5;
    public function createNonce(): int
    {
        $this->clear();
        $tbl = self::TABLE;
        $qbSub = $this->db->getQueryBuilder();
        $qbSub->select('1')->from($tbl)->where($qbSub->expr()->eq('val', ':val'));

        $qb = $this->db->getQueryBuilder();
        $qb->select('EXISTS(' . $qbSub->getSQL() . ')');

        $maxAttempts = self::MAX_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $val = \random_bytes(8);
            $val[0] = \chr(0x7f & \ord($val[0])); 
            $val = \unpack('J',$val)[1] ;
            $qb->setParameter(':val', $val);
            $rs = $qb->execute();
            $exists = $rs->fetch(FetchMode::COLUMN);
            $rs->closeCursor();
            if (!$exists) return $val;
        }
        throw new \Exception('Impossible de trouver un nonce qui n\'est pas déjà la table ' . self::TABLE .'.');
    }

    public function validateNonce(int $nonce, int $exp): bool
    {
        $this->clear();
        $tbl = self::TABLE;
        $qbSub = $this->db->getQueryBuilder();
        $qbSub->select('1')->from($tbl)->where($qbSub->expr()->eq('val', ':val'));

        $qb = $this->db->getQueryBuilder();
        $qb->select('EXISTS(' . $qbSub->getSQL() . ')');
        $qb->setParameter(':val', $nonce);
        $rs = $qb->execute();
        $exists = $rs->fetch(FetchMode::COLUMN);
        $rs->closeCursor();
        if (!!$exists) return false;

        $qb = $this->db->getQueryBuilder();
        $qb->insert($tbl)->values(['val' => ':val', 'exp' => ':exp']);
        $qb->setParameters([':val' => $nonce, ':exp' => $exp]);
        $qb->execute();
        return true;
    }

    protected function clear()
    {
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qb->delete($tbl)->where($qb->expr()->lt('exp', ':exp'));
        $qb->setParameter(':exp', \time());
        $qb->execute();
    }
}