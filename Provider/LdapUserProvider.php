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
  private
    $ldapUserClass;

  public function __construct(LdapManagerUserInterface $ldapManager, $ldapUserClass)
  {
    $this->ldapManager = $ldapManager;
    $this->ldapUserClass = $ldapUserClass;
  }

  protected function createLdapUser() {
      $class = $this->ldapUserClass;
      return new $class();
  }

  public function loadUserByUsername($username)
  {
    if(!$this->ldapManager->exists($username))
        throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));

    $lm = $this->ldapManager
      ->setUsername($username)
      ->doPass();

    $ldapUser = $this->createLdapUser();
    $ldapUser->setUsername($lm->getUsername());
    $ldapUser->setEmail($lm->getEmail());
    $ldapUser->setRoles($lm->getRoles());
    $ldapUser->setDn($lm->getDn());
    $ldapUser->setAttributes($lm->getAttributes());

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
    return (bool)($class === 'IMAG\LdapBundle\User\LdapUser');
  }
}
