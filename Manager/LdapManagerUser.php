<?php

namespace IMAG\LdapBundle\Manager;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use IMAG\LdapBundle\Exception\ConnectionException;

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

    /**
     * @throws inherit
     */
    public function exists($username)
    {
        $this
            ->setUsername($username)
            ->addLdapUser()
            ;
    }

    /**
     * return true
     */
    public function auth()
    {
        if (strlen($this->password) === 0) {
            throw new ConnectionException('Password can\'t be empty');
        }
        
        if (null === $this->ldapUser) {
            $this->bindByUsername();
            $this->doPass();
        } else {
            $this->doPass();
            $this->bindByDn();
        }        
    }

    /**
     * @throws inherit
     */
    public function doPass()
    {
        $this
            ->addLdapUser()
            ->addLdapGroups()
            ->addLdapRoles()
            ;

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

    public function getGroups()
    {
        return $this->ldapUser['groups'];
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

    /**
     * @return mixed $this
     * @throws \Symfony\Component\Security\Core\Exception\UsernameNotFoundException | Username not found
     * @throws \RuntimeException | Inconsistent Fails
     * @throws \IMAG\LdapBundle\Exception\ConnectionException | Connection error
     */
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
            throw new UsernameNotFoundException(sprintf('Username "%s" doesn\'t exists', $this->username));
        }

        $this->ldapUser = $entries[0];

        return $this;
    }

    /**
     * @return mixed $this
     * @throws \RuntimeException | Inconsistent Fails
     * @throws \InvalidArgumentException | Configuration exception
     * @throws \IMAG\LdapBundle\Exception\ConnectionException | Connection error
     */
    private function addLdapGroups()
    {
        if (null === $this->ldapUser) {
            throw new \RuntimeException('Cannot get LDAP groups before authenticating user against LDAP');
        }

        $this->ldapUser['groups'] = array();

        if (true === $this->params['client']['skip_groups']) {
            return $this;
        }

        if (!isset($this->params['groups']) && false ===  $this->params['client']['skip_groups']) {
            throw new \InvalidArgumentException("If you want to skip getting the groups, set config option imag_ldap:client:skip_groups to true");
        }

        $tab = array();

        $filter = isset($this->params['groups']['filter'])
            ? $this->params['groups']['filter']
            : '';

        $entries = $this->ldapConnection
            ->search(array(
                'base_dn'  => $this->params['groups']['base_dn'],
                'filter'   => sprintf('(&%s(%s=%s))',
                                      $filter,
                                      $this->params['groups']['user_attribute'],
                                      $this->ldapConnection->escape($this->getUserId())
                ),
                'attrs'    => array(
                    $this->params['groups']['name_attribute']
                )
            ));

        for ($i = 0; $i < $entries['count']; $i++) {
            array_push($tab, $entries[$i][$this->params['groups']['name_attribute']][0]);
        }

        $this->ldapUser['groups'] = $tab;

        return $this;
    }

    /**
     * @return mixed $this
     * @throws \RuntimeException | Inconsistent Fails
     * @throws \InvalidArgumentException | Configuration exception
     */
    private function addLdapRoles()
    {
        if (null === $this->ldapUser) {
            throw new \RuntimeException('Cannot assign LDAP roles before authenticating user against LDAP');
        }

        $this->ldapUser['roles'] = array('ROLE_LDAP_USER');

        if (true === $this->params['client']['skip_roles']) {
            return $this;
        }

        if (!isset($this->params['roles']) && false ===  $this->params['client']['skip_roles']) {
            throw new \InvalidArgumentException("If you want to skip assigning the roles, set config option imag_ldap:client:skip_roles to true");
        }

        if (true === $this->params['client']['groups_as_roles']) {
            foreach ($this->ldapUser['groups'] as $group) {
                array_push($this->ldapUser['roles'], sprintf('ROLE_LDAP_GROUP_%s', self::slugify($group)));
            }
        }

        foreach ($this->params['roles'] as $role => $principals) {
            if (
                (isset($principals['users']) and in_array($this->username, $principals['users'])) or
                (isset($principals['groups'])) and !empty(array_intersect($this->ldapUser['groups'], $principals['groups']))
            ) {
                array_push($this->ldapUser['roles'], $role);
            }
        }

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
        $role = preg_replace('/\W+/u', '_', $role);
        $role = trim($role, '_');
        $role = mb_strtoupper($role, 'UTF-8');

        return $role;
    }

    private function getUserId()
    {
        switch ($this->params['groups']['user_id']) {
        case 'dn':
            return $this->ldapUser['dn'];
            break;

        case 'username':
            return $this->username;
            break;

        default:
            throw new \Exception(sprintf("The value can't be retrieved for this user_id : %s",$this->params['groups']['user_id']));
        }
    }
}
