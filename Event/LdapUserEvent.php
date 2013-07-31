<?php

namespace IMAG\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;

use IMAG\LdapBundle\User\LdapUserInterface;

class LdapUserEvent extends Event
{
    private $user;

    public function __construct(LdapUserInterface $user)
    {
        $this->user = $user;
    }

    public function getUser()
    {
        return $this->user;
    }
}
