<?php

namespace IMAG\LdapBundle\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class LdapToken extends AbstractToken
{

    private $providerKey;
        
    public function __construct($username, $providerKey, array $roles= array())
    {
        parent::__construct($roles);

        $this->setuser($username);
        $this->providerKey = $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return null;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function serialize()
    {
        return serialize(array(
            $this->providerKey,
            parent::serialize()
        ));
    }

    public function unserialize($str)
    {
        list(
            $this->providerKey,
            $parentStr
        ) = unserialize($str);
        
        parent::unserialize($parentStr);
    }
}
