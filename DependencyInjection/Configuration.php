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
            ->append($this->addUserNode())
            ->append($this->addRoleNode())
            ->scalarNode('user_class')
              ->defaultValue("IMAG\LdapBundle\User\LdapUser")
            ->end()
        ->end()
        ;

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

  private function addUserNode()
  {
      $treeBuilder = new TreeBuilder();
      $node = $treeBuilder->root('user');

      $node
          ->isRequired()
          ->children()
              ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('filter')->end()
              ->scalarNode('name_attribute')->defaultValue('uid')->end()
              ->variableNode('attributes')->defaultValue(array())->end()
          ->end()
          ;

      return $node;
  }

  private function addRoleNode()
  {
      $treeBuilder = new TreeBuilder();
      $node = $treeBuilder->root('role');

      $node
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
          ;

      return $node;
  }

}
