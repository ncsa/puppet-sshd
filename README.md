# sshd

Manage base sshd_config settings and allow_ssh access for users and groups from
specified sources.

## Dependencies
- [MiamiOH/pam_access](https://forge.puppet.com/MiamiOH/pam_access)
- [herculesteam/augeasproviders](https://forge.puppet.com/herculesteam/augeasproviders)
- [ncsa/puppet-sssd](https://github.com/ncsa/puppet-sssd)
- [puppetlabs/firewall](https://forge.puppet.com/puppetlabs/firewall)
- [sharumpe/tcpwrappers](https://forge.puppet.com/sharumpe/tcpwrappers)
- [woodsbw/augeasfacter](https://github.com/woodsbw/augeasfacter)

## Reference

### define sshd::allow_from (
-    Array[ String, 1 ]   $hostlist,
-    Array[ String ]      $users                   = [],
-    Array[ String ]      $groups                  = [],
-    Hash[ String, Data ] $additional_match_params = {},
### class sshd (
-    Array             $trusted_subnets,
-    Hash              $config,
-    Hash[String,Hash] $config_matches,
-    Array[String]     $revoked_keys,

-    # Module defaults should be sufficient
-    Array[String] $required_packages,   #per OS
-    String        $revoked_keys_file,   #per OS

[REFERENCE.md](REFERENCE.md)
