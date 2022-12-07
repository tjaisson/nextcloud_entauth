<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

class ExternalIds {
    const TTL = 6 * 31 * 24 * 3600; // 6 mois
    private const TBL = 'entauth';
    private $db;
    
    public function __construct(IDBConnection $db) {
        $this->db = $db;
    }
    
    public function GetUser($ent, $extid) {
        $qb = $this->db->getQueryBuilder();
        $qb->delete(self::TBL)
        ->where(
            $qb->expr()->lt('exp', $qb->createNamedParameter(\time(), IQueryBuilder::PARAM_INT))
            ,
            $qb->expr()->eq('ent', $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT))
            ,
            $qb->expr()->eq('extid', $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR))
            );
        $qb->execute();
        $qb = $this->db->getQueryBuilder();
        $qb->select('uid')
        ->from(self::TBL)
        ->where(
            $qb->expr()->eq('ent', $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT))
            ,
            $qb->expr()->eq('extid', $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR))
            );
        $cursor = $qb->execute();
        $row = $cursor->fetchAll(\PDO::FETCH_ASSOC);
        if (\count($row) === 0) return false;
        $cursor->closeCursor();
        return $row[0]['uid'];
    }

    public function TouchUser($ent, $extid) {
        $qb = $this->db->getQueryBuilder();
        $qb->update(self::TBL)
        ->set('exp', $qb->createNamedParameter(\time() + self::TTL, IQueryBuilder::PARAM_INT))
        ->where(
            $qb->expr()->eq('ent', $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT))
            ,
            $qb->expr()->eq('extid', $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR))
            );
        $qb->execute();
    }

    public function AddUser($ent, $extid, $uid) {
        if((!$ent) || (!$extid) || (!$uid)) throw new \Exception("Liaison impossible");
        $qb = $this->db->getQueryBuilder();
        $qb->insert(self::TBL)
        ->values([
            'ent' => $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT),
            'extid' => $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR),
            'uid' => $qb->createNamedParameter($uid, IQueryBuilder::PARAM_STR),
            'exp' => $qb->createNamedParameter(\time() + self::TTL, IQueryBuilder::PARAM_INT)
        ]);
        try {
            return $qb->execute() == 1 ? true : false;
        } catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {
            $uid2 = $this->GetUser($ent, $extid);
            if($uid2 == $uid) return true;
            throw new \Exception("Utilisateur {$ent}/{$extid} déjà lié à {$uid2}");
        }
    }

    public function DeleteUser($uid) {
        $qb = $this->db->getQueryBuilder();
        $qb->delete(self::TBL)
        ->where(
            $qb->expr()->eq('uid', $qb->createNamedParameter($uid, IQueryBuilder::PARAM_STR))
            );
        return $qb->execute() >= 1 ? true : false;
    }

}

