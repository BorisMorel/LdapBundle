<?php

namespace IMAG\LdapBundle\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory,
  Symfony\Component\DependencyInjection\ContainerBuilder,
  Symfony\Component\Config\Definition\Builder\NodeDefinition,
  Symfony\Component\DependencyInjection\DefinitionDecorator,
  Symfony\Component\DependencyInjection\Reference;

class LdapFactory extends AbstractFactory
{
  public function __construct()
  {
    $this->addOption('username_parameter', '_username');
    $this->addOption('password_parameter', '_password');
    $this->addOption('csrf_parameter', '_csrf_token');
    $this->addOption('intention', 'ldap_authenticate');
    $this->addOption('post_only', true);
  }

  public function getPosition()
  {
    return 'form';
  }

  public function getKey()
  {
    return 'imag_ldap';
  }

  public function addConfiguration(NodeDefinition $node)
  {
    parent::addConfiguration($node);
    
    $node
      ->children()
        ->scalarNode('csrf_provider')->cannotBeEmpty()->end()
      ->end()
      ;
  }

  protected function getListenerId()
  {
    return 'imag_ldap.security.authentication.listener';
  }

  protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
  {
    $provider = 'imag_ldap.security.authentication.provider.'.$id;

    $container
      ->setDefinition($provider, new DefinitionDecorator('imag_ldap.security.authentication.provider'))
      ->replaceArgument(0, new Reference($userProviderId))
      ->replaceArgument(3, $id)
      ;

    return $provider;
  }
  
  protected function createlistener($container, $id, $config, $userProvider)
  {
    $listenerId = parent::createListener($container, $id, $config, $userProvider);

    if (isset($config['csrf_provider'])) {
      $container
        ->getDefinition($listenerId)
        ->addArgument(new Reference($config['csrf_provider']))
        ;
    }
    
    return $listenerId;
  }

  protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
  {
    $entryPointId = 'imag_ldap.security.authentication.form_entry_point.'.$id;
    $container
      ->setDefinition($entryPointId, new DefinitionDecorator('imag_ldap.security.authentication.form_entry_point'))
      ->addArgument($config['login_path'])
      ->addArgument($config['use_forward'])
      ;

    return $entryPointId;
  }
}