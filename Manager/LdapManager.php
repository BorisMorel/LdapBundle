<?php

namespace IMAG\LdapBundle\Manager;

class LdapManager implements LdapManagerInterface
{
  private
    $params = array(),
    $user,
    $pass,
    $_ress,
    $_ldapUser;
  
  public function __construct(array $params)
  {
    $this->params = $params;
    $this->connect();
  }

  public function exists($username)
  {
    return (bool)
      $this
      ->setUsername($username)
      ->addUser();
  }

  public function auth()
  {    
    return (bool)
      $this
      ->addUser()
      ->addRoles()
      ->bind();
  }
 
  public function getMail()
  {
    return $this->_ldapUser['mail'][0];
  }

  public function getUsername()
  {
    return $this->user;
  }

  public function getRoles()
  {
    $tab = array();
    $roles = $this->_ldapUser['roles'];
    
    for($i = 0 ; $i < $roles['count'] ; $i++) {
      array_push($tab,$roles[$i][$this->params['role']['name_attribute']][0]);
    }
 
    return $tab;
  }

  public function setUsername($username)
  {
    $this->user = $username;

    return $this;
  }

  public function setPassword($password)
  {
    $this->pass = $password;

    return $this;
  } 

  private function connect()
  {
    $port = isset($this->params['client']['port']) ? $this->params['client']['port'] : '389';
   
    $ress = @ldap_connect($this->params['client']['host'], $port);
    
    if(!$ress || !@ldap_bind($ress))
      {
        throw new \Exception('unable connect to Ldap');
      }
    
    $this->_ress = $ress;
    
    return $this;
  }

  private function search(array $params)
  {
    if(!$params)
      throw new \Exception('$params must be define');
    
    $search = ldap_search($this->_ress, $params['base_dn'], $params['filter']);
  
    if($search) {
      $entries = ldap_get_entries($this->_ress, $search);
    
      if(is_array($entries)) {
        return $entries;
      } else {
        return false;
      }
    }
  }

  private function bind()
  {
    if(!$this->pass)
      throw new \Exception('Password is not defined, pls use setPass');

    $bind = @ldap_bind($this->_ress, $this->_ldapUser['dn'], $this->pass);

    return (bool)$bind;
  }

  private function addRoles()
  {
    if(!$this->_ldapUser)
      throw new \Exception('AddRoles() must be involved only when addUser() have return an user');

    $entries = $this->search(array(
      'base_dn' => $this->params['role']['base_dn'],
      'filter'  => sprintf('%s=%s', $this->params['role']['user_attribute'], $this->_ldapUser['dn'])
    ));
  
    $this->_ldapUser['roles'] = $entries;
    
    return $this;
  }

  private function addUser()
  {
    if(!$this->user)
      throw new \Exception('User is not defined, pls use setUser');
    
    $filter = isset($this->params['user']['filter']) ? $this->params['user']['filter'] : '';
    
    $entries = $this->search(array(
      'base_dn' => $this->params['user']['base_dn'],
      'filter'  => sprintf('(&%s(%s=%s))', $filter, $this->params['user']['name_attribute'], $this->user)
    ));

    if($entries['count'] > 1)
      throw new \Exception("This search can only return a single user");
    
    if($entries['count'] == 0)
      return false;

    $this->_ldapUser = $entries[0];
    
    return $this;
  }
}