<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface,
  Symfony\Component\Security\Core\User\UserProviderInterface,
  Symfony\Component\Security\Core\Authentication\Token\TokenInterface,
  Symfony\Component\Security\Core\User\UserInterface,
  Symfony\Component\Security\Core\Exception\AuthenticationException,
  IMAG\LdapBundle\Manager\LdapManagerUserInterface,
  IMAG\LdapBundle\Authentication\Token\LdapToken;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
  private
    $userProvider,
    $ldapManager,
    $providerKey;
 
  public function __construct(UserProviderInterface $userProvider, LdapManagerUserInterface $ldapManager, $providerKey)
  {
    $this->userProvider = $userProvider;
    $this->ldapManager = $ldapManager;
    $this->providerKey = $providerKey;
  }

  public function authenticate(TokenInterface $token)
  {
    $user = $this->userProvider->loadUserByUsername($token->getUsername());
   
    if($this->bind($user, $token)) {
      $ldapToken = new LdapToken($user, '', $user->getRoles());
      $ldapToken->setAuthenticated(true);
      $ldapToken->setAttributes($token->getAttributes());
      
      return $ldapToken;        
    }

    throw new AuthenticationException('The LDAP authentication failed.');
  }
 
  private function bind(UserInterface $user, TokenInterface $token)
  {
    return (bool)
      $this->ldapManager
      ->setUsername($user->getUsername())
      ->setPassword($token->getCredentials())
      ->auth();
  }
  
  public function supports(TokenInterface $token)
  {
    return $token instanceof LdapToken;
  }

}