<?php

namespace IMAG\LdapBundle\Manager;

interface LdapManagerUserInterface
{
  function __construct(LdapConnectionInterface $conn, $rolePrefix);
  function exists($username);
  function auth();
  function doPass();
  function getDn();
  function getCn();
  function getEmail();
  function getAttributes();
  function getLdapUser();
  function getDisplayName();
  function getGivenName();
  function getSurname();
  function getUsername();
  function getRoles();
  function setUsername($username);
  function setPassword($password);
}
