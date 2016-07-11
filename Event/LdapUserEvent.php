<?php

namespace IMAG\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;
use IMAG\LdapBundle\User\LdapUserInterface;

class LdapUserEvent extends Event
{
    private $user;
    private $token;

    public function __construct(LdapUserInterface $user, $token = null)
    {
        $this->user = $user;
        $this->token = $token;
    }

    public function getUser()
    {
        return $this->user;
    }

    public function setUser($user)
    {
        $this->user = $user;

        return $this;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function setToken($token)
    {
        $this->token = $token;
    }
}
