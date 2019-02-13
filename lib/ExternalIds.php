<?php
namespace OCA\EntAuth;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

class ExternalIds {
    private $db;
    
    public function __construct(IDBConnection $db) {
        $this->db = $db;
    }
    
    public function GetUser($ent, $extid) {
        $qb = $this->db->getQueryBuilder();
        
        $qb->select('uid')
        ->from('entauth')
        ->where(
            $qb->expr()->eq('ent', $qb->createNamedParameter($ent, IQueryBuilder::PARAM_INT))
            )
        ->andwhere(
            $qb->expr()->eq('extid', $qb->createNamedParameter($extid, IQueryBuilder::PARAM_STR))
            );
        
        $cursor = $qb->execute();
        $row = $cursor->fetch();
        $cursor->closeCursor();
        return $row;
    }

    public function AddUser($ent, $extid, $uid) {
        
    }
}

