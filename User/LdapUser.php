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
    return array();
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

  }

  public function equals(UserInterface $user)
  {
    
  }
}