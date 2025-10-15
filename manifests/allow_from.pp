# @summary Enable incoming ssh for a given set of hosts
#
# Enable incoming ssh for a given set of hosts
#
# Update iptables firewall
#
# Update sshd_config with a Match directive and associated settings
#
# Update access.conf
#
# @param users
#   List of users to allow (from hostlist)
#
#   Note: If both "users" and "groups" are empty, error is raised.
#
# @param groups
#   List of groups to allow (from hostlist)
#
#   Note: If both "users" and "groups" are empty, error is raised.
#
# @param hostlist
#   List of IPs or Hostnames that (users/groups) are allowed to ssh from
#
# @param additional_match_params
#   Sshd config keywords and values.
#   Format:
#   additional_match_params = { 'keyword1' => 'value1',
#                               'keyword2' => 'value2',
#                               'keyword3' => [ 'val3_1','val3_2' ],
#                             }
#
# @example
#   sshd::allow_from { 'namevar': }
#
# @example
#   ssh::allow_from { 'allow incoming ssh by users 1,2,3 from hosts X,Y,Z':
#       'users'                   => Array,
#       'groups'                  => Array,
#       'hostlist'                => Array,
#       'additional_match_params' => Hash,
#   }
define sshd::allow_from (
  Array[String, 1]   $hostlist,
  Array[String]      $users                   = [],
  Array[String]      $groups                  = [],
  Hash[String, Data] $additional_match_params = {},
) {
  # CHECK INPUT
  if empty( $users ) and empty( $groups ) {
    fail( "'users' and 'groups' cannot both be empty" )
  }

  # ACCESS.CONF
  ### This sets up the pam access.conf file to allow incoming ssh
  $groups.each |String $group| { $hostlist.each |String $host| {
      pam_access::entry { "Allow group ${group} ssh from ${host}":
        group      => $group,
        origin     => $host,
        permission => '+',
        position   => '-1',
      }
  } }

  $users.each |String $user| { $hostlist.each |String $host| {
      pam_access::entry { "Allow user ${user} ssh from ${host}":
        user       => $user,
        origin     => $host,
        permission => '+',
        position   => '-1',
      }
  } }

  ### FIREWALL
  $hostlist.each | $host | {
    firewall { "22 allow SSH from ${host} for ${name}":
      dport  => 22,
      proto  => tcp,
      source => $host,
      jump   => accept,
    }
  }

  ### SSSD
  # Requires custom fact 'sssd_domains'
  # See: lib/augeasfacter/sssd_info.conf
  # See also: https://github.com/herculesteam/augeasfacter
  ###
  # convert sssd domains from csv string to a puppet array
  $domains = $facts['sssd_domains'] ? {
    String[1] => $facts['sssd_domains'].regsubst(/ +/, '', 'G').split(','),
    default   => [],
  }
  $domains.each |$domain| {
    if $users =~ Array[String,1] {
      $user_csv = $users.join(',')
      ::sssd::domain::append_array { "${name} users '${user_csv}' for sssd domain '${domain}'" :
        domain  => $domain,
        setting => 'simple_allow_users',
        items   => $users,
      }
    }
    if $groups =~ Array[String,1] {
      $group_csv = $groups.join(',')
      ::sssd::domain::append_array { "${name} groups '${group_csv}' for sssd domain '${domain}'" :
        domain  => $domain,
        setting => 'simple_allow_groups',
        items   => $groups,
      }
    }
  }

  ### SSHD_CONFIG
  # Defaults
  if ( $sshd::manage_service ) {
    $config_defaults = {
      'notify' => Service[$sshd::service_name],
    }
  } else {
    $config_defaults = {
      'ensure' => 'present',
    }
  }
  $config_match_defaults = $config_defaults + {
    'position' => 'before first match'
  }

  # Create cfg_match_params for Users and Groups
  $user_params = $users ? {
    Array[String, 1] => { 'AllowUsers' => $users },
    default            => {}
  }
  $group_params = $groups ? {
    Array[String, 1] => { 'AllowGroups' => $groups },
    default            => {}
  }

  # Combine all cfg_match_params into a single hash
  $cfg_match_params = $additional_match_params + $user_params + $group_params

  # Create Host and/or Address match criteria
  # Hostnames require "Match Host"
  # IPs/CIDRs require "Match Address"
  # Create separate lists and make two separate match blocks in sshd_config
  # Criteria will be either "Host" or "Address"
  # Pattern will be the CSV string of hostnames or IPs
  # See also: "sshd_config" man page, for details of "criteria-pattern pairs"
  $name_list = $hostlist.filter | $elem | { $elem =~ /[a-zA-Z]/ }
  $ip_list   = $hostlist.filter | $elem | { $elem !~ /[a-zA-Z]/ }
  #associate the correct criteria with each list, filter empty lists
  $host_data = {
    'Host'    => $name_list,
    'Address' => $ip_list,
  }.filter | $criteria, $list | {
    size( $list ) > 0
  }

  # Create User match criteria (empty if user list is empty)
  $user_csv = $users ? {
    Array[String, 1] => join( $users, ',' ),
    default            => '',
  }
  $user_criteria = $user_csv ? {
    String[1] => "User ${user_csv}",
    default   => '',
  }
  # Create Group match criteria (empty if group list is empty)
  $group_csv = $groups ? {
    Array[String, 1] => join( $groups, ',' ),
    default            => '',
  }
  $group_criteria = $group_csv ? {
    String[1] => "Group ${group_csv}",
    default   => '',
  }

  #loop through host_data creating a match block for each criteria-pattern
  $host_data.each | $criteria, $list | {
    $pattern = join( $list, ',' )
    $match_condition = "${criteria} ${pattern} ${user_criteria} ${group_criteria}"

    #ensure match block exists
    # $match_data = { $match_condition => {} }
    ensure_resource( 'sshd_config_match', $match_condition, $config_match_defaults )
    # sshd_config_match {
    #   $match_condition :
    #   ;
    #   default:
    #     * => $config_match_defaults,
    #   ;
    # }

    #add parameters to the match block
    $config_data = $cfg_match_params.reduce({}) | $memo, $kv | {
      $key = $kv[0]
      $val = $kv[1]
      $memo + {
        "${match_condition} ${key}" => {
          'key'       => $key,
          'value'     => $val,
          'condition' => $match_condition,
        }
      }
    }
    ensure_resources( 'sshd_config', $config_data, $config_defaults )
    # $cfg_match_params.each | $key, $val | {
    #   sshd_config {
    #     "${match_condition} ${key}" :
    #       key       => $key,
    #       value     => $val,
    #       condition => $match_condition,
    #     ;
    #     default:
    #       * => $config_defaults,
    #     ;
    #   }
    # }
  }
}
