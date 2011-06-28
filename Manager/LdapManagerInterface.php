<?php

namespace IMAG\LdapBundle\Manager;

interface LdapManagerInterface
{
  function __construct(array $params);
  function exists($username);
  function auth();
  function getMail();
  function getUsername();
  function setUsername($username);
  function setPassword($password);
}
