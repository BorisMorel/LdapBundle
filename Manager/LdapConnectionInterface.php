<?php

namespace IMAG\LdapBundle\Manager;

use Monolog\Logger;

interface LdapConnectionInterface
{
    function __construct(array $params, Logger $logger);
    function search(array $searchParams);
    function bind($user_dn, $password);
    function getParameters();
    function getHost();
    function getPort();
    function getBaseDn($index);
    function getFilter($index);
    function getNameAttribute($index);
    function getUserAttribute($index);
    function getErrno($resource = null);
    function getError($resource = null);
}
