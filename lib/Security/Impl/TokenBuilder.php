<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Security\Impl;

use OCA\EntAuth\Security\TokenBuilderInterface;

class TokenBuilder implements TokenBuilderInterface
{
    /** @var \OCA\EntAuth\Security\KeyRepositoryInterface $keyRepository */
    protected $keyRepository;
    /** @var \OCA\EntAuth\Security\NonceRepositoryInterface $nonceRepository */
    protected $nonceRepository;
    protected bool $expirSet = false;
    protected int $ttl;
    protected int $exp;
    protected string $data = '';
    protected string $subject = '';
    protected bool $useEncryption = false;
    protected bool $useNonce = false;
    /**
     * @param \OCA\EntAuth\Security\KeyRepositoryInterface $keyRepository
     * @param \OCA\EntAuth\Security\NonceRepositoryInterface $nonceRepository
     */
    public function __construct($keyRepository, $nonceRepository)
    {
        $this->keyRepository = $keyRepository;
        $this->nonceRepository = $nonceRepository;
    }
    public function withTTL(int $ttl): TokenBuilderInterface
    {
        if ($ttl < 0) throw new \Exception('Token expiration can\'t be in the past');
        $this->ttl = $ttl;
        $this->exp = \time() + $ttl;
        $this->expirSet = true;
        return $this;
    }
    public function withExpiration(int $expiration): TokenBuilderInterface
    {
        $now = \time();
        if ($expiration < $now) throw new \Exception('Token expiration can\'t be in the past');
        $this->exp = $expiration;
        $this->ttl = $expiration - $now;
        $this->expirSet = true;
        return $this;
    }
    public function withData(string $data): TokenBuilderInterface
    {
        $this->data = $data;
        return $this;
    }
    public function withSubject(string $subject): TokenBuilderInterface
    {
        if (\strlen($subject) > 0x100) throw new \Exception('Subject string too long. Max is 256 characters.');
        $this->subject = $subject;
        return $this;
    }
    public function withEncription(): TokenBuilderInterface
    {
        $this->useEncryption = true;
        return $this;
    }
    public function withNonce(): TokenBuilderInterface
    {
        $this->useNonce = true;
        return $this;
    }
    public function toString(): string
    {
        if (! $this->expirSet) throw new \Exception('Token expiration must be set.');
        $key = $this->keyRepository->getSuitableKey($this->ttl);
        $kid = \pack('V', $key->getId());
        $data = $this->data;
        if ($this->subject !== '') {
            $flag = 0x40;
            $data = \chr(\strlen($this->subject) - 1) . $this->subject . $data;
        } else {
            $flag = 0;
        }
        $dl = \strlen($data);
        if ($dl < 32) {
            $_flag = 31 - $dl;
            if ($_flag === 0) $_flag = 1;
            $data = \random_bytes($_flag + 1) . $data;
            $flag |= $_flag;
        }
        if ($this->useNonce) {
            $flag |= 0x80;
            $data = \pack('J', $this->nonceRepository->createNonce()) . $data;
        }
        $data = \chr($flag) . \pack('J', $this->exp) . $data;
        $signature = \hash_hmac('sha256', $data, $key->getSignKey(), true);
        $data .= $signature;
        if ($this->useEncryption) {
            $iv = \random_bytes(16);
            $data = \openssl_encrypt($data, 'aes-256-ctr', $key->getCypherKey(), \OPENSSL_RAW_DATA, $iv);
            $data = $iv . $data;
            $flag = \chr(0x10);
        } else {
            $flag = \chr(0x00);
        }
        $data = \strtr(\rtrim(\base64_encode($data), '='), '+/', '-_');
        $hdr = \strtr(\substr(\base64_encode($kid . $flag), 0, 6), '+/', '-_');
        return $hdr . $data;
    }
}