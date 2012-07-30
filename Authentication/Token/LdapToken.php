<?php

namespace IMAG\LdapBundle\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class LdapToken extends AbstractToken
{

    public function __construct($username, $password, $providerKey, array $roles= array())
    {
        parent::__construct($roles);

        $this->setuser($username);
        $this->credentials = $password;
        $this->providerKey = $providerKey;
    }

    public function getCredentials()
    {
        return $this->credentials;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function eraseCredentials()
    {
        parent::eraseCredentials();

        $this->credentials = null;
    }

    public function serialize()
    {
        return serialize(array($this->credentials, $this->providerKey, parent::serialize()));
    }

    public function unserialize($str)
    {
        list($this->credentials, $this->providerKey, $parentStr) = unserialize($str);
        parent::unserialize($parentStr);
    }
    
}