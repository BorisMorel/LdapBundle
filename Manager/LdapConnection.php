<?php

namespace IMAG\LdapBundle\Manager;

use Monolog\Logger;

use IMAG\LdapBundle\Exception\ConnectionException;
use Symfony\Component\HttpFoundation\Session\Session;

class LdapConnection implements LdapConnectionInterface
{
    private $params;
    private $logger;
    private $session;

    protected $ress;
    protected $con;

    const LDAP_SEARCH_CACHE = 'ldap_search_cache';

    public function __construct(array $params, Logger $logger)
    {
        $this->params = $params;
        $this->logger = $logger;
    }

    public function setSession(Session $session)
    {
        $this->session = $session;
    }

    public function search(array $searchParams)
    {
        $attrs = isset($searchParams['attrs']) ? $searchParams['attrs'] : array();

        if ($this->isSearchCacheEnabled() && $this->session->isStarted()) {
            $cacheId = md5($searchParams['base_dn'] . '-' . $searchParams['filter'] . ' - ' . print_r($attrs, true));
            $cache = $this->session->get(self::LDAP_SEARCH_CACHE, []);
            if (array_key_exists($cacheId, $cache)) {
                return json_decode($cache[$cacheId], true);
            }
        }

        $this->connect();

        $ref = array(
            'base_dn' => '',
            'filter' => '',
        );

        if (count($diff = array_diff_key($ref, $searchParams))) {
            throw new \Exception(sprintf('You must define %s', print_r($diff, true)));
        }

        $this->info(
            sprintf(
                'ldap_search base_dn %s, filter %s',
                print_r($searchParams['base_dn'], true),
                print_r($searchParams['filter'], true)
            )
        );

        $search = @ldap_search($this->ress, $searchParams['base_dn'], $searchParams['filter'], $attrs);
        $this->checkLdapError($this->ress);

        if ($search) {
            $entries = ldap_get_entries($this->ress, $search);

            @ldap_free_result($search);


            $result = is_array($entries) ? $entries : false;

            if ($result && $this->isSearchCacheEnabled() && $this->session->isStarted()) {
                $cache[$cacheId] = json_encode($result);
                $this->session->set(self::LDAP_SEARCH_CACHE, $cache);
            }

            return $result;
        }

        return false;
    }

    /**
     * @param string $user_dn
     * @param string $password
     * @param connection $ress
     * @return true
     * @throws ConnectionException
     * @throws \Exception
     */
    public function bind($user_dn, $password = '', $ress = null)
    {
        if (null === $ress) {
            if ($this->ress === null) {
                $this->connect();
            }

            $ress = $this->ress;
        }

        if (empty($user_dn) || !is_string($user_dn)) {
            throw new ConnectionException("LDAP user's DN (user_dn) must be provided (as a string).");
        }

        // According to the LDAP RFC 4510-4511, the password can be blank.
        @ldap_bind($ress, $user_dn, $password);
        $this->checkLdapError($ress);

        return true;
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

    public function isTLSEnabled()
    {
        return $this->params['client']['tls'];
    }

    public function isSearchCacheEnabled()
    {
        return $this->params['client']['cache_search'];
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
        $port = isset($this->params['client']['port']) ? $this->params['client']['port'] : '389';

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

        if ($this->isTLSEnabled()) {
            @ldap_start_tls($ress);
            $this->checkLdapError($ress);
        }

        if (isset($this->params['client']['username'])) {
            if (!isset($this->params['client']['password'])) {
                throw new \Exception('You must uncomment password key');
            }

            @ldap_bind($ress, $this->params['client']['username'], $this->params['client']['password']);
            $this->checkLdapError($ress);
        }

        $this->ress = $ress;

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
            $quotedMetaChars[$key] = '\\' . str_pad(dechex(ord($value)), 2, '0');
        }

        $str = str_replace($metaChars, $quotedMetaChars, $str);

        return ($str);
    }
}
