<?php

namespace IMAG\LdapBundle\Manager;

class LdapManagerUser implements LdapManagerUserInterface
{
  private
    $ldapConnection,
    $username,
    $password,
    $_ldapUser;

  public function __construct(LdapConnectionInterface $conn)
  {
    $this->ldapConnection = $conn;
    $this->params = $this->ldapConnection->getParameters();
  }

  public function exists($username)
  {
    return (bool)
      $this
      ->setUsername($username)
      ->addLdapUser();
  }

  public function auth()
  {
    return (bool)
      $this
      ->doPass()
      ->bind();
  }

  public function doPass()
  {
    $this
      ->addLdapUser()
      ->addLdapRoles()
      ;

    return $this;
  }

  public function setUsername($username)
  {
    $this->username = $username;

    return $this;
  }

  public function setPassword($password)
  {
    $this->password = $password;

    return $this;
  }

  public function getEmail()
  {
    return $this->_ldapUser['mail'][0];
  }

  public function getUsername()
  {
    return $this->username;
  }

  public function getRoles()
  {
    return $this->_ldapUser['roles'];
  }

  private function addLdapUser()
  {
    if(!$this->username)
      throw new \Exception('User is not defined, pls use setUsername');
       
    $filter = isset($this->params['user']['filter']) ? $this->params['user']['filter'] : '';
    
    $entries = $this->ldapConnection->search(array(
      'base_dn' => $this->params['user']['base_dn'],
      'filter'  => sprintf('(&%s(%s=%s))', $filter, $this->params['user']['name_attribute'], $this->username)
    ));

    if($entries['count'] > 1)
      throw new \Exception("This search can only return a single user");
    
    if($entries['count'] == 0)
      return false;

    $this->_ldapUser = $entries[0];
    
    return $this;
  }

  private function addLdapRoles()
  {
    if(!$this->_ldapUser)
      throw new \Exception('AddRoles() can be involved only when addUser() have return an user');

    $tab = array();
    
    $entries = $this->ldapConnection->search(array(
      'base_dn' => $this->params['role']['base_dn'],
      'filter'  => sprintf('%s=%s', $this->params['role']['user_attribute'], $this->getUserId())
    ));

    for($i = 0 ; $i < $entries['count'] ; $i++) {
      array_push($tab,sprintf('ROLE_%s',self::slugify($entries[$i][$this->params['role']['name_attribute']][0])));
    }
    $this->_ldapUser['roles'] = $tab;
   
    return $this;
  }

  private function bind()
  {
    if(!$this->password)
      throw new \Exception('Password is not defined, pls use setPassword');
    
    return (bool)
      $this->ldapConnection->bind($this->_ldapUser['dn'], $this->password);
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
    switch($this->params['role']['user_id'])
    {
    case 'dn':
      return $this->_ldapUser['dn'];
      break;
      
    case 'username':
      return $this->username;
      break;

    default:
      throw new \Exception(sprintf('The value can\'t be retrieve for this user_id : %s', $this->params['role']['user_id']));
    }
  }
}
