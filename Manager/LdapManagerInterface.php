<?php

namespace IMAG\LdapBundle\Manager;

interface LdapManagerInterface
{
  function __construct(array $params);
  function exists($username);
  function auth();
  function getEmail();
  function getUsername();
  function getRoles();
  function setUsername($username);
  function setPassword($password);
}
