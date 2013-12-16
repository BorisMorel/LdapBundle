<?php

namespace IMAG\LdapBundle\Event;

use IMAG\LdapBundle\Authentication\Token\LdapToken;
use Symfony\Component\EventDispatcher\Event;

class LdapTokenEvent extends Event
{
    private $token;

    public function __construct(LdapToken $token)
    {
        $this->token = $token;
    }

    public function getToken()
    {
        return $this->token;
    }
}
