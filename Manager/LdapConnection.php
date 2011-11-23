<?php

namespace IMAG\LdapBundle\Manager;

use Monolog\Logger;

class LdapConnection implements LdapConnectionInterface
{
    private 
        $params = array(), 
        $_ress,
        $logger
        ;

    public function __construct(array $params, Logger $logger)
    {
        $this->params = $params;
        $this->logger = $logger;
        $this->connect();
    }

    public function search(array $params)
    {
        $ref = array(
            'base_dn' => '',
            'filter' => '',
        );

        if (count($diff = array_diff_key($ref, $params))) {
            throw new \Exception(sprintf('You must defined %s', print_r($diff, true)));
        }

        $attrs = array();
        
        if (isset($params['attrs'])) {
            $attrs = $params['attrs'];
        }
        
        $this->info(
            sprintf('ldap_search base_dn %s, filter %s',
                    print_r($params['base_dn'], true),
                    print_r($params['filter'], true)
            ));
        
        $search = ldap_search($this->_ress, $params['base_dn'], $params['filter'], $attrs);

        if ($search) {
            $entries = ldap_get_entries($this->_ress, $search);
            
            if (is_array($entries)) {
                return $entries;
            } else {
                return false;
            }
        } 
    }

    public function bind($user_dn, $password)
    {
        if (!$user_dn) {
            throw new \Exception('You must bind with an ldap user_dn');
        }

        if (!$password) {
            throw new \Exception('Password can not be null to bind');
        }

        return (bool) 
            @ldap_bind($this->_ress, $user_dn, $password);
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
        $port = isset($this->params['client']['port']) 
            ? $this->params['client']['port'] 
            : '389';

        $ress = @ldap_connect($this->params['client']['host'], $port);

        if (isset($this->params['client']['version']) && $this->params['client']['version'] !== null) {
            ldap_set_option($ress, LDAP_OPT_PROTOCOL_VERSION, $this->params['client']['version']);
        }
        
        if (isset($this->params['client']['referrals_enabled']) && $this->params['client']['referrals_enabled'] !== null) {
            ldap_set_option($ress, LDAP_OPT_REFERRALS, $this->params['client']['referrals_enabled']);
        }

        if (isset($this->params['client']['username']) && $this->params['client']['version'] !== null) {
            if(!isset($this->params['client']['password'])) {
                throw new \Exception('You must uncomment password key');
            }
            $bindress = @ldap_bind($ress, $this->params['client']['username'], $this->params['client']['password']);
        
            if (!$bindress) {
                throw new \Exception('The credentials you have configured are not valid');
            }
        } else {
            $bindress = @ldap_bind($ress);
        
            if (!$bindress) {
                throw new \Exception('Unable to connect Ldap');
            }
        }
    
        $this->_ress = $ress;
    
        return $this;
    }
 
    private function info($message)
    {
        if (!$this->logger) {
            return;
        }

        $this->logger
            ->info($message);
    }

    private function err($message)
    {
        if (!$this->logger) {
            return;
        }

        $this->logger
            ->err($message);
    }

}
