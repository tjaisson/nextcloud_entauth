<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\NonceRepositoryInterface;
use OCP\IDBConnection;
use OC\DB\QueryBuilder\QueryFunction;
use OCP\DB\QueryBuilder\IQueryBuilder;

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
        $qb = $this->db->getQueryBuilder();
        $qbSub = $this->db->getQueryBuilder();
        $qbSub->select($qbSub->expr()->literal('one'))->from($tbl)->where(
            $qbSub->expr()->eq('val', $qb->createParameter('val'))
        );

        $qb->select(new QueryFunction('EXISTS(' . $qbSub->getSQL() . ')'));

        $maxAttempts = self::MAX_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $val = \random_bytes(8);
            $val[0] = \chr(0x7f & \ord($val[0])); 
            $val = \unpack('J',$val)[1] ;
            $qb->setParameter('val', $val);
            $rs = $qb->execute();
            $exists = $rs->fetch(\PDO::FETCH_COLUMN);
            $rs->closeCursor();
            if (!$exists) return $val;
        }
        throw new \Exception('Impossible de trouver un nonce qui n\'est pas déjà la table ' . self::TABLE .'.');
    }

    public function validateNonce(int $nonce, int $exp): bool
    {
        $this->clear();
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qbSub = $this->db->getQueryBuilder();
        $qbSub->select($qbSub->expr()->literal('one'))->from($tbl)->where(
            $qbSub->expr()->eq('val', $qb->createParameter('val'))
        );

        $qb->select(new QueryFunction('EXISTS(' . $qbSub->getSQL() . ')'));

        $qb->setParameter('val', $nonce, IQueryBuilder::PARAM_INT);
        $rs = $qb->execute();
        $exists = $rs->fetch(\PDO::FETCH_COLUMN);
        $rs->closeCursor();
        if (!!$exists) return false;

        $qb = $this->db->getQueryBuilder();
        $qb->insert($tbl)->values([
            'val' => $qb->createParameter('val'),
            'exp' => $qb->createParameter('exp')
        ])
        ->setParameter('val', $nonce, IQueryBuilder::PARAM_INT)
        ->setParameter('exp', $exp, IQueryBuilder::PARAM_INT);
        $qb->execute();
        return true;
    }

    protected function clear()
    {
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qb->delete($tbl)->where(
            $qb->expr()->lt('exp', $qb->createNamedParameter(\time(), IQueryBuilder::PARAM_INT))
        );
        $qb->execute();
    }
}