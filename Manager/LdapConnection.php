<?php

namespace IMAG\LdapBundle\Manager;
class LdapConnection implements LdapConnectionInterface
{
    private $params = array(), $_ress;

    public function __construct(array $params)
    {
        $this->params = $params;
        $this->connect();
    }

    public function search(array $params)
    {
        $ref = array(
            'base_dn' => '', 'filter' => ''
        );
        if (count($diff = array_diff_key($ref, $params))) {
            throw new \Exception(
                    sprintf('You must defined %s', print_r($diff, true)));
        }

        $search = @ldap_search($this->_ress, $params['base_dn'],
                $params['filter']);

        if ($search) {
            $entries = ldap_get_entries($this->_ress, $search);

            if (is_array($entries)) {
                return $entries;
            } else {
                return false;
            }
        } else {
            var_dump($params); exit();
        }
    }

    public function bind($user_dn, $password)
    {
        if (!$user_dn)
            throw new \Exception('You must bind with an ldap user_dn');
        if (!$password)
            throw new \Exception('Password can not be null to bind');

        return (bool) @ldap_bind($this->_ress, $user_dn, $password);
    }

    public function getParameters()
    {
        return $this->params;
    }

    public function getHost()
    {
        return $this->params['client']['host'];
    }

    public function getPort()
    {
        return $this->params['client']['port'];
    }

    public function getBaseDn($index)
    {
        return $this->params[$index]['base_dn'];
    }

    public function getFilter($index)
    {
        return $this->params[$index]['filter'];
    }

    public function getNameAttribute($index)
    {
        return $this->params[$index]['name_attribute'];
    }

    public function getUserAttribute($index)
    {
        return $this->params[$index]['user_attribute'];
    }

    private function connect()
    {
        $port = isset($this->params['client']['port']) ? $this->params['client']['port']
                : '389';

        $ress = @ldap_connect($this->params['client']['host'], $port);

        if (!$ress || !@ldap_bind($ress)) {
            throw new \Exception('unable connect to Ldap');
        }

        $this->_ress = $ress;

        if ($this->params['client']['username']) {
            $bindress = @ldap_bind($ress, $this->params['client']['username'],
                    $this->params['client']['password']);

            if (!$bindress) {
                throw new \Exception('The credentials you have configured are not valid');
            }
        }

        return $this;
    }

}
