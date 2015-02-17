<?php

namespace IMAG\LdapBundle\Manager;

use Monolog\Logger;

use IMAG\LdapBundle\Exception\ConnectionException;

class LdapConnection implements LdapConnectionInterface
{
    private $params,
        $logger,
        $lastuse
        ;

    protected $ress;

    public function __construct(array $params, Logger $logger)
    {
        if (!array_key_exists('reconnect_delay', $params)) {
            $params['reconnect_delay'] = '5';
        }
        $this->params = $params;
        $this->logger = $logger;
    }

    public function search(array $params)
    {
        $this->connect();

        $ref = array(
            'base_dn' => '',
            'filter' => '',
        );

        if (count($diff = array_diff_key($ref, $params))) {
            throw new \Exception(sprintf('You must defined %s', print_r($diff, true)));
        }

        $attrs = isset($params['attrs']) ? $params['attrs'] : array();

        $this->info(
            sprintf('ldap_search base_dn %s, filter %s',
                print_r($params['base_dn'], true),
                print_r($params['filter'], true)
            ));

        $search = @ldap_search(
            $this->ress,
            $params['base_dn'],
            $params['filter'],
            $attrs
        );

        if (false !== $search) {
            $this->lastuse = new \DateTime();
            $this->lastuse->add(new \DateInterval('PT'.$params['reconnect_delay'].'M'));

            $entries = ldap_get_entries($this->ress, $search);

            @ldap_free_result($search);

            return is_array($entries) ? $entries : false;
        }
        $this->logger->error("LDAP ERROR : ".ldap_errno($this->ress).' '.ldap_error($this->ress));
        return false;
    }

    public function bind($user_dn, $password='')
    {
        if (empty($user_dn) || ! is_string($user_dn)) {
            throw new ConnectionException("LDAP user's DN (user_dn) must be provided (as a string).");
        }

        $this->connect();

        $this->lastuse = new \DateTime();
        $this->lastuse->add(new \DateInterval('PT'.$params['reconnect_delay'].'M'));

        // According to the LDAP RFC 4510-4511, the password can be blank.
        return @ldap_bind($this->ress, $user_dn, $password);
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
        $now = new \DateTime();

        if (null !== $this->ress and null !== $this->lastuse
            and $this->lastuse > $now) {
            return $this;
        }

        $port = isset($this->params['client']['port'])
            ? $this->params['client']['port']
            : '389';

        $ress = @ldap_connect($this->params['client']['host'], $port);

        if (isset($this->params['client']['version'])) {
            ldap_set_option($ress, LDAP_OPT_PROTOCOL_VERSION, $this->params['client']['version']);
        }

        if (isset($this->params['client']['referrals_enabled'])) {
            ldap_set_option($ress, LDAP_OPT_REFERRALS, $this->params['client']['referrals_enabled']);
        }

        if (isset($this->params['client']['network_timeout'])) {
            ldap_set_option($ress, LDAP_OPT_NETWORK_TIMEOUT, $this->params['client']['network_timeout']);
        }

        if (isset($this->params['client']['username'])) {
            if (!isset($this->params['client']['password'])) {
                throw new \Exception('You must uncomment password key');
            }

            $bindress = @ldap_bind($ress, $this->params['client']['username'], $this->params['client']['password']);

            if (!$bindress) {
                throw new \Exception('The credentials you have configured are not valid');
            }
        }

        $this->ress = $ress;
        $this->lastuse = new \DateTime();
        $this->lastuse->add(new \DateInterval('PT'.$params['reconnect_delay'].'M'));
        return $this;
    }

    private function info($message)
    {
        if ($this->logger) {
            $this->logger->info($message);
        }
    }

    private function err($message)
    {
        if ($this->logger) {
            $this->logger->err($message);
        }
    }

    /**
     * Checks if there were an error during last ldap call
     *
     * @throws \IMAG\LdapBundle\Exception\ConnectionException
     */
    private function checkLdapError($ress = null)
    {
        if (0 != $code = $this->getErrno($ress)) {
            $message = $this->getError($ress);
            $this->err('LDAP returned an error with code ' . $code . ' : ' . $message);
            throw new ConnectionException($message, $code);
        }
    }


    /**
     * @param resource|null $resource
     *
     * @return null|string
     *
     * @see https://wiki.servicenow.com/index.php?title=LDAP_Error_Codes
     */
    public function getErrno($resource = null)
    {
        $resource = $resource ?: $this->ress;
        if (!$resource) {
            return null;
        }

        return ldap_errno($resource);
    }

    /**
     * @param resource|null $resource
     *
     * @return null|string
     */
    public function getError($resource = null)
    {
        $resource = $resource ?: $this->ress;
        if (!$resource) {
            return null;
        }

        return ldap_error($resource);
    }

    /**
     * Escape string for use in LDAP search filter.
     *
     * @link http://www.php.net/manual/de/function.ldap-search.php#90158
     * See RFC2254 for more information.
     * @link http://msdn.microsoft.com/en-us/library/ms675768(VS.85).aspx
     * @link http://www-03.ibm.com/systems/i/software/ldap/underdn.html
     */
    public function escape($str)
    {
        $metaChars = array('*', '(', ')', '\\', chr(0));

        $quotedMetaChars = array();

        foreach ($metaChars as $key => $value) {
            $quotedMetaChars[$key] = '\\'.str_pad(dechex(ord($value)), 2, '0');
        }

        $str = str_replace($metaChars, $quotedMetaChars, $str);

        return ($str);
    }
}
