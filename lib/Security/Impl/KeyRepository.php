<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\KeyInterface;
use OCA\EntAuth\Security\KeyRepositoryInterface;
use OCP\IDBConnection;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OC\DB\QueryBuilder\QueryFunction;
use Doctrine\DBAL\FetchMode;

Class KeyRepository implements KeyRepositoryInterface
{
    const TABLE = 'entauth_keys';
    const ROTATION = 3600;
    /** @var \OCP\IDBConnection $db */
    protected $db;

    /** 
     * @param \OCP\IDBConnection $db
     */
    public function __construct(IDBConnection $db) { $this->db = $db; }

    public function find(int $id): ?KeyInterface
    {
        $this->clear();
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qb->select('id', 'sign', 'cypher', 'exp')
        ->from($tbl)->where(
            $qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT))
        );
        $rs = $qb->execute();
        $rec = $rs->fetch(FetchMode::STANDARD_OBJECT);
        $rs->closeCursor();
        if (! $rec) return null;
        return new Key($rec);
    }

    public function getSuitableKey(int $ttl): KeyInterface
    {
        $this->clear();
        $tbl = self::TABLE;
        $now = \time();
        $min = $now + $ttl;
        $max = $now + 2* \max(self::ROTATION, $ttl);
        $qb = $this->db->getQueryBuilder();
        $qb->select('id', 'sign', 'cypher', 'exp')->from($tbl)
        ->where(
            $qb->expr()->gte('exp', $qb->createNamedParameter($min, IQueryBuilder::PARAM_INT)),
            $qb->expr()->lte('exp', $qb->createNamedParameter($max, IQueryBuilder::PARAM_INT))
        );
        $rs = $qb->execute();
        $rec = $rs->fetch(FetchMode::STANDARD_OBJECT);
        $rs->closeCursor();
        if ($rec) return new Key($rec);
        else return $this->createKey($max);
    }

    protected function clear()
    {
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qb->delete($tbl)->where(
            $qb->expr()->lt('exp',$qb->createNamedParameter(\time(), IQueryBuilder::PARAM_INT))
        );
        $qb->execute();
    }

    protected function createKey(int $exp): KeyInterface
    {
        $rec = (object)[
            'id' => $this->createId(),
            'sign' => \random_bytes(KeyInterface::SIGN_KEY_LEN),
            'cypher' => \random_bytes(KeyInterface::CYPHER_KEY_LEN),
            'exp' => $exp,
        ];
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qb->insert($tbl)->values(['id' => ':id', 'sign' => ':sign', 'cypher' => ':cypher', 'exp' => ':exp']);
        $qb->setParameters([':id' => $rec->id, ':sign' => $rec->sign, ':cypher' => $rec->cypher, ':exp' => $rec->exp]);
        $qb->execute();
        return new Key($rec);
    }

    const MAX_ATTEMPTS = 5;
    protected function createId()
    {
        $tbl = self::TABLE;
        $qb = $this->db->getQueryBuilder();
        $qbSub = $this->db->getQueryBuilder();
        $qbSub->select($qbSub->expr()->literal('one'))->from($tbl)->where(
            $qbSub->expr()->eq('id', $qb->createParameter('id'))
        );

        $qb->select(new QueryFunction('EXISTS(' . $qbSub->getSQL() . ')'));

        $maxAttempts = self::MAX_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $id = \unpack('V',\random_bytes(4))[1];
            $qb->setParameter('id', $id);
            $rs = $qb->execute();
            $exists = $rs->fetch(FetchMode::COLUMN);
            $rs->closeCursor();
            if (!$exists) return $id;
        }
        throw new \Exception('Collision d\'identifiant dans la table ' . self::TABLE);
    }
}