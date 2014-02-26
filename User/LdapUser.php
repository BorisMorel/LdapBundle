<?php

namespace IMAG\LdapBundle\User;

class LdapUser implements LdapUserInterface
{
    protected 
        $username,
        $givenname,
        $surname,
        $displayname,
        $email,
        $dn,
        $cn,
        $roles = array(),
        $attributes = array()        
        ;

    public function getDisplayname()
    {
        return $this->displayname;
    }

    public function setDisplayname($displayname)
    {
        $this->displayname = $displayname;
        return $this;
    }

    public function getGivenname()
    {
        return $this->givenname;
    }

    public function setGivenname($givenname)
    {
        $this->givenname = $givenname;
        return $this;
    }

    public function getSurname()
    {
        return $this->surname;
    }

    public function setSurname($surname)
    {
        $this->surname = $surname;
        return $this;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function getUsername()
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

    public function getCn()
    {
        return $this->cn;
    }

    public function setCn($cn)
    {
        $this->cn = $cn;

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

    public function isEqualTo(\Symfony\Component\Security\Core\User\UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface
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

    /**
     * Return username when converting class to string
     *
     * @return string
     */
    public function __toString()
    {
        return $this->getUserName();
    }
}
