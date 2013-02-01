<?php

namespace IMAG\LdapBundle\Manager;

use Symfony\Component\Security\Core\Exception\AuthenticationException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException
    ;


class LdapManagerUser implements LdapManagerUserInterface
{
    private
        $ldapConnection,
        $username = null,
        $password,
        $params = array(),
        $_ldapUser = null
        ;

    public function __construct(LdapConnectionInterface $conn)
    {
        $this->ldapConnection = $conn;
        $this->params = $this->ldapConnection
            ->getParameters();
    }
    
    public function exists($username)
    {
        try {
            $this
                ->setUsername($username)
                ->addLdapUser()
                ;
        } catch (AuthenticationException $e) {
            return false;

        }

        return true;
    }

    public function auth()
    {
        return (bool) ($this->doPass() && $this->bind());
    }

    public function authNoAnonSearch()
    {
        return (bool) ($this->bindUser() && $this->doPass());
    }

    public function doPass()
    {
        try {
            $this->addLdapUser();
            $this->addLdapRoles();

        } catch(\InvalidArgumentException $e) {
            if (false === $this->params['client']['skip_roles']) {
                throw $e;
            }

        }
        
        return $this;
    }

    public function getDn()
    {
        return $this->_ldapUser['dn'];
    }

    public function getEmail()
    {
        return isset($this->_ldapUser[$this->params['user']['email_attribute']][0]) 
            ? $this->_ldapUser[$this->params['user']['email_attribute']][0] 
            : '';
    }

    public function getAttributes()
    {
        $attributes = array();
        foreach ($this->params['user']['attributes'] as $attrName) {
            if (isset($this->_ldapUser[$attrName][0])) {
                $attributes[$attrName] = $this->_ldapUser[$attrName][0];
            }
        }

        return $attributes;
    }

    public function getLdapUser()
    {
        return $this->_ldapUser;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getRoles()
    {
        return $this->_ldapUser['roles'];
    }
    
    public function setUsername($username)
    {
        // TODO improved this ; Move detection of wrong username on a dedicated function and throw an Exception ...
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
            throw new \Exception('username must be defined prior to calling addLdapUser()');
        }

        $error = null;
        $count= null;

        foreach($this->params['user']['search_by'] as $method) {
            try {
                $fct = 'getBy'.$method;
                $entries = $this->{$fct}();

            } catch (UsernameNotFoundException $e) {
                $count++;
                $error = new AuthenticationException($e->getMessage(), $e->getExtraInformation(), $e->getCode(), $error);
                
            }
        }

        if ($count >= count($this->params['user']['search_by'])) {
            throw new AuthenticationException("username cannot be loaded by any methods", $error->getExtraInformation(), $error->getCode(), $error);
        }

        // Store the LDAP user for later use
        $this->_ldapUser = $entries[0];
        
        return $this;

    }

    private function getByLogin()
    {
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
            throw new \Exception("This search can only return a single user");
        }

        if ($entries['count'] == 0) {
            throw new UsernameNotFoundException(sprintf('Username "%s" not found by login', $this->username));
        }
        
        return $entries;
    }

    private function getByEmail()
    {
        $filter = isset($this->params['user']['email_filter'])
        	? $this->params['user']['email_filter']
        	: '';
        
        $entries = $this->ldapConnection
        	->search(array(
                'base_dn' => $this->params['user']['base_dn'],
                'filter' => sprintf('(&%s(%s=%s))',
                                    $filter,
                                    $this->params['user']['email_attribute'],
                                    $this->ldapConnection->escape($this->username)
                )
        	));
        
        if ($entries['count'] > 1) {
            throw new \Exception("This search can only return a single user");
        }
        
        if ($entries['count'] == 0) {
            throw new UsernameNotFoundException(sprintf('Username "%s" not found by email', $this->username));
        }

        return $entries;
    }
    
    private function addLdapRoles()
    {
        if (null === $this->_ldapUser) {
            throw new \RuntimeException('AddRoles() can be involved only when addUser() have return an user');
        }
        
        $this->_ldapUser['roles'] = array();

        if (!isset($this->params['role'])) {
            throw new \InvalidArgumentException("If you want skip the roles getting, please set skip_roles to true under client key");
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

        $this->_ldapUser['roles'] = $tab;

        return $this;
    }

    private function bind()
    {
        return $this->ldapConnection
            ->bind($this->_ldapUser['dn'], $this->password);
    }

    private function bindUser()
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
            return $this->_ldapUser['dn'];
            break;

        case 'username':
            return $this->username;
            break;

        default:
            throw new \Exception(sprintf('The value can\'t be retrieve for this user_id : %s',$this->params['role']['user_id']));
        }
    }
}
