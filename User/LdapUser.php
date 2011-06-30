<?php

namespace IMAG\LdapBundle\User;

use Symfony\Component\Security\Core\User\UserInterface,
  IMAG\LdapBundle\Manager\LdapManagerInterface;

class LdapUser implements UserInterface
{
  private
    $ldapManager;

  public function __construct(LdapManagerInterface $ldapManager)
  {
     $this->_ldapManager = $ldapManager;
  }

  public function getRoles()
  {
    return $this->_ldapManager->getRoles();
  }

  public function getPassword()
  {
    return null;
  }

  public function getSalt()
  {
    return null;
  }

  public function getUserName()
  {

    return $this->_ldapManager->getUsername();
  }

  public function eraseCredentials()
  {
    return null; //With ldap No credentials with stored ; Maybe forgotten the roles
  }

  public function equals(UserInterface $user)
  {
    return ($user === $this);
  }
}