<?php

namespace IMAG\LdapBundle\User;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;

class LdapUser implements UserInterface, EquatableInterface, \Serializable
{
    protected $username;
    protected $email;
    protected $roles;
    protected $dn;
    protected $attributes;

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

    public function getDn()
    {
        return $this->dn;
    }

    public function setDn($dn)
    {
        $this->dn = $dn;

        return $this;
    }

    public function setAttributes(array $attributes)
    {
        $this->attributes = $attributes;

        return $this;
    }

    public function getAttributes()
    {
        return $this->attributes;
    }

    public function getAttribute($name)
    {
        return isset($this->attributes[$name]) ? $this->attributes[$name] : null;
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

    public function addRole($role)
    {
        $this->roles[] = $role;

        return $this;
    }

    public function eraseCredentials()
    {
        return null; //With ldap No credentials with stored ; Maybe forgotten the roles
    }

    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof LdapUser
            || $user->getUsername() !== $this->username
            || $user->getEmail() !== $this->email
            || count(array_diff($user->getRoles(), $this->roles)) > 0
            || $user->getDn() !== $this->dn
        ) {
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
            $this->dn,
        ));
    }

    public function unserialize($serialized)
    {
        list(
            $this->username,
            $this->email,
            $this->roles,
            $this->dn,
        ) = unserialize($serialized);
    }
}
