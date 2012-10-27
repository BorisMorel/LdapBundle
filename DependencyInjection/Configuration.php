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
          ->arrayNode('client')
            ->children()
              ->scalarNode('host')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('port')->defaultValue(389)->end()
              ->scalarNode('version')->end()
              ->scalarNode('username')->end()
              ->scalarNode('password')->end()
              ->scalarNode('referrals_enabled')->end()
              ->scalarNode('network_timeout')->end()
            ->end()
          ->end()
          ->arrayNode('user')
            ->children()
              ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('filter')->end()
              ->scalarNode('name_attribute')->defaultValue('uid')->end()
              ->variableNode('attributes')->defaultValue(array())->end()
            ->end()
          ->end()
          ->arrayNode('role')
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

    return $treeBuilder;      
  }
}
