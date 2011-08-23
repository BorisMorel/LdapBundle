<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface,
  Symfony\Component\Security\Core\User\UserInterface,
  IMAG\LdapBundle\Manager\LdapManagerInterface,
  Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
  Symfony\Component\Security\Core\Exception\UnsupportedUserException,
  IMAG\LdapBundle\User\LdapUser;

class LdapUserProvider implements UserProviderInterface
{
  private 
    $ldapManager;

  public function __construct(LdapManagerInterface $ldapManager)
  {
    $this->ldapManager = $ldapManager;
  }
  
  public function loadUserByUsername($username)
  {
    if(!$this->ldapManager->exists($username))
        throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));

    $lm = $this->ldapManager
      ->setUsername($username)
      ->compile();
    
    $ldapUser = new LdapUser();
    $ldapUser
      ->setUsername($lm->getUsername())
      ->setEmail($lm->getEmail())
      ->setRoles($lm->getRoles());
    
    return $ldapUser;
  }

  public function refreshUser(UserInterface $user)
  {
    if(!$user instanceof LdapUser)
      throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));

    return $this->loadUserByUsername($user->getUsername());
  }
    
  public function supportsClass($class)
  {
    return (bool)$class === 'IMAG\LdapBundle\User\LdapUser';
  }
}