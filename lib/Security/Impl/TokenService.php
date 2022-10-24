<?php
namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\TokenServiceInterface;
use OCA\EntAuth\Security\TokenBuilderInterface;
use OCA\EntAuth\Security\TokenValidatorInterface;
use OCP\IDBConnection;

class TokenService implements TokenServiceInterface
{
    /** @var \OCP\IDBConnection $db */
    protected $db;

    /**
     * @param \OCP\IDBConnection $db
     */
    public function __construct(IDBConnection $db) { $this->db = $db; }

    public function createBuilder(): TokenBuilderInterface
    {
        return new TokenBuilder(
            $this->get_kr(),
            $this->get_nr()
        );
    }
    public function createValidator(): TokenValidatorInterface
    {
        return new TokenValidator(
            $this->get_kr(),
            $this->get_nr()
        );
    }

    protected $kr_inst = null;
    protected function get_kr()
    {
        $inst = $this->kr_inst;
        if (null === $inst) {
            $inst = new KeyRepository($this->db);
            $this->kr_inst = $inst;
        }
        return $inst;
    }
    protected $nr_inst = null;
    protected function get_nr()
    {
        $inst = $this->nr_inst;
        if (null === $inst) {
            $inst = new NonceRepository($this->db);
            $this->nr_inst = $inst;
        }
        return $inst;
    }
}