<?php

namespace IMAG\LdapBundle\Manager;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class LdapManagerUser implements LdapManagerUserInterface
{
    private
        $ldapConnection,
        $username,
        $email,
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
    
    public function emailExists($email) {
    	return (bool) $this
            ->setUsername(NULL)
    	    ->setEmail($email)
    	    ->addLdapUser()
    	    ;
    }

    public function exists($username)
    {
        return (bool) $this
            ->setUsername($username)
            ->setEmail(NULL)
            ->addLdapUser()
            ;
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
        return $this->email;
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
    
    public function setEmail($email)
    {
    	$this->email = $email;
    	
    	return $this;
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
        if (!$this->username && !$this->email) {
            throw new \Exception('Email or user must be defined prior to calling addLdapUser()');
        }
        
        if ($this->username) {
        	// If the username is set, search using the username
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
        } else if ($this->email) {
        	// Username was not set - check using email filter instead
        	$filter = isset($this->params['user']['emailfilter'])
        	? $this->params['user']['emailfilter']
        	: '';
        	
        	$entries = $this->ldapConnection
        	->search(array(
        			'base_dn' => $this->params['user']['base_dn'],
        			'filter' => sprintf('(&%s(%s=%s))',
        					$filter,
        					$this->params['user']['email_attribute'],
        					$this->ldapConnection->escape($this->email)
        			)
        	));
        }

        if ($entries['count'] > 1) {
            throw new \Exception("This search can only return a single user");
        }

        if ($entries['count'] == 0) {
            return false;
        }

        // Store the LDAP user for later use
        $this->_ldapUser = $entries[0];
        
        // Set the email (if present)
        $this->email = isset($this->_ldapUser[$this->params['user']['email_attribute']][0]) ? $this->_ldapUser[$this->params['user']['email_attribute']][0] : '';

        // Set the username (if not present)
        if (!$this->username) {
            $this->username = isset($this->_ldapUser[$this->params['user']['name_attribute']][0]) ? $this->_ldapUser[$this->params['user']['name_attribute']][0] : '';
        }

        return $this;
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
