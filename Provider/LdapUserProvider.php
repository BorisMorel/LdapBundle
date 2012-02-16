<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface,
  Symfony\Component\Security\Core\User\UserInterface,
  IMAG\LdapBundle\Manager\LdapManagerUserInterface,
  Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
  Symfony\Component\Security\Core\Exception\UnsupportedUserException,
  IMAG\LdapBundle\User\LdapUser;

class LdapUserProvider implements UserProviderInterface
{
  private 
    $ldapManager;

  public function __construct(LdapManagerUserInterface $ldapManager)
  {
    $this->ldapManager = $ldapManager;
  }
  
  public function loadUserByUsername($username)
  {
    if(!$this->ldapManager->exists($username))
        throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));

    $lm = $this->ldapManager
      ->setUsername($username)
      ->doPass();
    
    $ldapUser = new LdapUser();
    $ldapUser
      ->setUsername($lm->getUsername())
      ->setEmail($lm->getEmail())
      ->setRoles($lm->getRoles())
      ->setDn($lm->getDn())
      ->setAttributes($lm->getAttributes())
     ;

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
