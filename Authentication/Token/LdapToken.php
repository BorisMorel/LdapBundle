<?php

namespace IMAG\LdapBundle\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class LdapToken extends AbstractToken
{
  private 
    $credentials;

  public function __construct($username, $password, array $roles= array())
  {
    parent::__construct($roles);

    $this->setuser($username);
    $this->credentials = $password;
  }

  public function getCredentials()
  {
    return $this->credentials;
  }

  
}