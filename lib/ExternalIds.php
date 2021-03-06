<?php
namespace OCA\EntAuth;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

class ExternalIds {
    private const TBL = 'entauth';
    private $db;
    
    public function __construct(IDBConnection $db) {
        $this->db = $db;
    }
    
    public function GetUser($ent, $extid) {
        $qb = $this->db->getQueryBuilder();
        $qb->select('uid')
        ->from(self::TBL)
        ->where(
            $qb->expr()->eq('ent', $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT))
            )
        ->andwhere(
            $qb->expr()->eq('extid', $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR))
            );
        $cursor = $qb->execute();
        $row = $cursor->fetch();
        $cursor->closeCursor();
        if($row) return $row['uid'];
        return false;
    }

    public function AddUser($ent, $extid, $uid) {
        if((!$ent) || (!$extid) || (!$uid)) throw new \Exception("Liaison impossible");
        $qb = $this->db->getQueryBuilder();
        $qb->insert(self::TBL)
        ->values([
            'ent' => $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT),
            'extid' => $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR),
            'uid' => $qb->createNamedParameter($uid, IQueryBuilder::PARAM_STR),
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

