<?php

namespace IMAG\LdapBundle\DependencyInjection;

use Symfony\Component\Config\Definition\ConfigurationInterface,
  Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Configuration implements ConfigurationInterface
{
  public function getConfigTreeBuilder()
  {
    $treeBuilder = new TreeBuilder();
    $rootNode = $treeBuilder->root('imag_ldap');
    $rootNode
        ->children()
            ->append($this->addClientNode())
            ->scalarNode('user_class')
              ->defaultValue("IMAG\LdapBundle\User\LdapUser")
            ->end()
        ->end()
        ;
    
    $this->addUserNode($rootNode);
    $this->addRoleNode($rootNode);
    
    return $treeBuilder;
  }

  private function addClientNode()
  {
      $treeBuilder = new TreeBuilder();
      $node = $treeBuilder->root('client');

      $node
          ->isRequired()
          ->children()
              ->scalarNode('host')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('port')->defaultValue(389)->end()
              ->scalarNode('version')->end()
              ->scalarNode('username')->end()
              ->scalarNode('password')->end()
              ->booleanNode('bind_username_before')->defaultFalse()->end()
              ->scalarNode('referrals_enabled')->end()
              ->scalarNode('network_timeout')->end()
              ->booleanNode('skip_roles')->defaultFalse()->end()
           ->end()
          ;

      return $node;
  }

  private function addUserNode(\Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition $rootNode)
  {
      $rootNode
          ->fixXmlConfig('user', 'users')
          ->children()
              ->arrayNode('users')
                  ->isRequired()
                  ->prototype('array')
                      ->children()
                      ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
                      ->scalarNode('filter')->end()
                      ->scalarNode('name_attribute')->defaultValue('uid')->end()
                      ->variableNode('attributes')->defaultValue(array())->end()
                  ->end()
                ->end()
          ->end()
          ;
  }

  private function addRoleNode(\Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition $rootNode)
  {
      $rootNode
          ->fixXmlConfig('role', 'roles')
          ->children()
              ->arrayNode('roles')
                  ->isRequired()
                  ->prototype('array')
                      ->children()
                      ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
                      ->scalarNode('filter')->end()
                      ->scalarNode('name_attribute')->defaultValue('cn')->end()
                      ->scalarNode('user_attribute')->defaultValue('member')->end()
                      ->scalarNode('user_id')->defaultValue('dn')
                        ->validate()
                          ->ifNotInArray(array('dn', 'username'))
                          ->thenInvalid('Only dn or username')
                        ->end()
                      ->end()
                  ->end()
                ->end()
          ->end()
          ;
  }

}
