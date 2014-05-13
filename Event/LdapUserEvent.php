<?php

namespace IMAG\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

use IMAG\LdapBundle\User\LdapUserInterface;

class LdapUserEvent extends Event
{
    private $user;
    private $token;

    public function __construct(LdapUserInterface $user, TokenInterface $token)
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
	return $this;
    }
}
