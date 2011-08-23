<?php

namespace IMAG\LdapBundle\User;

use Symfony\Component\Security\Core\User\UserInterface;

class LdapUser implements UserInterface, \Serializable
{
  protected 
    $username,
    $email,
    $roles;

  public function getRoles()
  {
    return $this->roles;
  }

  public function getUserName()
  {

    return $this->username;
  }

  public function getEmail()
  {
    return $this->email;
  }

  public function getPassword()
  {
    return null;
  }

  public function getSalt()
  {
    return null;
  }

  public function setUsername($username)
  {
    $this->username = $username;

    return $this;
  }

  public function setEmail($email)
  {
    $this->email = $email;

    return $this;
  }

  public function setRoles(array $roles)
  {
    $this->roles = $roles;

    return $this;
  }

  public function eraseCredentials()
  {
    return null; //With ldap No credentials with stored ; Maybe forgotten the roles
  }

  public function equals(UserInterface $user)
  {
    if(!$user instanceOf LdapUser) {
      return false;
    }

    if($user->getUsername() !== $this->username) {
      return false;
    }
    if($user->getEmail() !== $this->email) {
      return false;
    }
    if($user->getRoles() !== $this->roles) {
      return false;
    }
      
    return true;
  }

  public function serialize()
  {
    return serialize(array(
      $this->username,
      $this->email,
      $this->roles,
    ));
  }

  public function unserialize($serialized)
  {
    list(
      $this->username,
      $this->email,
      $this->roles
    ) = unserialize($serialized);
  }
}