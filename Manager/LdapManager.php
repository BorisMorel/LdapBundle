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
      $this->setUsername($username)
      ->search();
  }

  public function auth()
  {    
    return (bool)$this->search()
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
    $port = isset($this->params['port']) ? $this->params['port'] : '389';
   
    $ress = @ldap_connect($this->params['host'], $port);
    
    if(!$ress || !@ldap_bind($ress))
      {
        throw new \Exception('unable connect to Ldap');
      }
    
    $this->_ress = $ress;
    
    return $this;
  }

  private function search()
  {
    if(!$this->user)
      throw new \Exception('User is not defined, pls use setUser');

    $filter = isset($this->params['user_filter']) ? $this->params['user_filter'] : '';

    $search = ldap_search($this->_ress,$this->params['user_base_dn'],sprintf('%s(%s=%s)', $filter, $this->params['user_attribute'], $this->user));
   
    if($search) 
      {
        $entries = ldap_get_entries($this->_ress,$search);
        if(is_array($entries) && $entries['count'] == 1)
          {
            $this->_ldapUser = $entries[0];
          }else
          {
            return false;
          }
      }

    return $this;    
  }

  private function bind()
  {
    if(!$this->pass)
      throw new \Exception('Pass is not defined, pls use setPass');

    $bind = @ldap_bind($this->_ress, $this->_ldapUser['dn'], $this->pass);

    return (bool)$bind;
  }
}