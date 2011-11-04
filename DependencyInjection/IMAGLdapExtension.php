<?php

namespace IMAG\LdapBundle\DependencyInjection;

use Symfony\Component\HttpKernel\DependencyInjection\Extension,
  Symfony\Component\DependencyInjection\ContainerBuilder,
  Symfony\Component\DependencyInjection\Loader\XmlFileLoader,
  Symfony\Component\Config\FileLocator;

class IMAGLdapExtension extends Extension
{
  public function load(array $configs, ContainerBuilder $container)
  {
    $loader = new XMLFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
    $loader->load('security_ldap.xml');

    $configuration = new Configuration();

    $config = $this->processConfiguration($configuration, $configs);
    $container->setParameter('imag_ldap.ldap_connection.params', $config);
  }

  public function getAlias()
  {
    return "imag_ldap";
  }
}