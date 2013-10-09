<?php

namespace IMAG\LdapBundle\Manager;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class LdapManagerUser implements LdapManagerUserInterface
{
    private
        $ldapConnection,
        $username,
        $password,
        $params,
        $ldapUser
        ;

    public function __construct(LdapConnectionInterface $conn)
    {
        $this->ldapConnection = $conn;
        $this->params = $this->ldapConnection->getParameters();
    }

    public function exists($username)
    {
        return (bool) $this
            ->setUsername($username)
            ->addLdapUser()
            ;
    }

    public function auth()
    {
        if (strlen($this->password) === 0) {
            return false;
        }
        
        if (null === $this->ldapUser) {
            return ($this->bindByUsername() && $this->doPass());
        }

        return ($this->doPass() && $this->bindByDn());
    }

    public function doPass()
    {
        try {
            $this->addLdapUser();
            $this->addLdapRoles();
        } catch (\InvalidArgumentException $e) {
            if (false === $this->params['client']['skip_roles']) {
                throw $e;
            }
        }

        return $this;
    }

    public function getDn()
    {
        return $this->ldapUser['dn'];
    }

    public function getCn()
    {
        return $this->ldapUser['cn'][0];
    }

    public function getEmail()
    {
        return isset($this->ldapUser['mail'][0]) ? $this->ldapUser['mail'][0] : '';
    }

    public function getAttributes()
    {
        $attributes = array();
        foreach ($this->params['user']['attributes'] as $attrName) {
            if (isset($this->ldapUser[$attrName][0])) {
                $attributes[$attrName] = $this->ldapUser[$attrName][0];
            }
        }

        return $attributes;
    }

    public function getLdapUser()
    {
        return $this->ldapUser;
    }

    public function getDisplayName()
    {
        if (isset($this->ldapUser['displayname'][0])) {
            return $this->ldapUser['displayname'][0];
        } else {
            return false;
        }
    }

    public function getGivenName()
    {
        if (isset($this->ldapUser['givenname'][0])) {
            return $this->ldapUser['givenname'][0];
        } else {
            return false;
        }
    }

    public function getSurname()
    {
        if (isset($this->ldapUser['sn'][0])) {
            return $this->ldapUser['sn'][0];
        } else {
            return false;
        }
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getRoles()
    {
        return $this->ldapUser['roles'];
    }

    public function setUsername($username)
    {
        if ($username === "*") {
            throw new \InvalidArgumentException("Invalid username given.");
        }

        $this->username = $username;

        return $this;
    }

    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    private function addLdapUser()
    {
        if (!$this->username) {
            throw new \InvalidArgumentException('User is not defined, please use setUsername');
        }

        $filter = isset($this->params['user']['filter'])
            ? $this->params['user']['filter']
            : '';

        $entries = $this->ldapConnection
            ->search(array(
                'base_dn' => $this->params['user']['base_dn'],
                'filter' => sprintf('(&%s(%s=%s))',
                                    $filter,
                                    $this->params['user']['name_attribute'],
                                    $this->ldapConnection->escape($this->username)
                )
            ));

        if ($entries['count'] > 1) {
            throw new \RuntimeException("This search can only return a single user");
        }

        if ($entries['count'] == 0) {
            return false;
        }

        $this->ldapUser = $entries[0];

        return $this;
    }

    private function addLdapRoles()
    {
        if (null === $this->ldapUser) {
            throw new \RuntimeException('Cannot assign LDAP roles before authenticating user against LDAP');
        }

        $this->ldapUser['roles'] = array();

        if (!isset($this->params['role'])) {
            throw new \InvalidArgumentException("If you want to skip getting the roles, set config option imag_ldap:client:skip_roles to true");
        }

        $tab = array();

        $filter = isset($this->params['role']['filter'])
            ? $this->params['role']['filter']
            : '';

        $entries = $this->ldapConnection
            ->search(array(
                'base_dn'  => $this->params['role']['base_dn'],
                'filter'   => sprintf('(&%s(%s=%s))',
                                      $filter,
                                      $this->params['role']['user_attribute'],
                                      $this->ldapConnection->escape($this->getUserId())
                ),
                'attrs'    => array(
                    $this->params['role']['name_attribute']
                )
            ));

        for ($i = 0; $i < $entries['count']; $i++) {
            array_push($tab, sprintf('ROLE_%s',
                                     self::slugify($entries[$i][$this->params['role']['name_attribute']][0])
            ));
        }

        $this->ldapUser['roles'] = $tab;

        return $this;
    }

    private function bindByDn()
    {
        return $this->ldapConnection
            ->bind($this->ldapUser['dn'], $this->password);
    }

    private function bindByUsername()
    {
        return $this->ldapConnection
            ->bind($this->username, $this->password);
    }

    private static function slugify($role)
    {
        $role = preg_replace('/\W+/', '_', $role);
        $role = trim($role, '_');
        $role = strtoupper($role);

        return $role;
    }

    private function getUserId()
    {
        switch ($this->params['role']['user_id']) {
            case 'dn':
                return $this->ldapUser['dn'];
                break;

            case 'username':
                return $this->username;
                break;

            default:
                throw new \Exception(sprintf("The value can't be retrieved for this user_id : %s",$this->params['role']['user_id']));
        }
    }
}
