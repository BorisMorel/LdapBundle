<?php

namespace IMAG\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;

use Symfony\Component\Security\Core\User\UserInterface;

use IMAG\LdapBundle\User\LdapUser;

class LdapUserEvent extends Event
{ 
    private
        $user
        ;

    public function __construct(LdapUser $user)
    {
        $this->user = $user;
    }

    public function getUser()
    {
        return $this->user;
    }

    public function setUser(UserInterface $user)
    {
        $this->user = $user;

        return $this;
    }
}