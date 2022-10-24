<?php
namespace OCA\EntAuth\Security;

interface TokenServiceInterface
{
    public function createBuilder(): TokenBuilderInterface;
    public function createValidator(): TokenValidatorInterface;
}