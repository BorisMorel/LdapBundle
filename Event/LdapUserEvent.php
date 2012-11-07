<?php

namespace IMAG\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;

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

}