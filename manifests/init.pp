# @summary Configure default sshd settings
#
# Configure default sshd settings
#
# @param allow_list
#   Hash to pass to allow_from.pp, where top level key is the name
#   and the values under that is the hash to pass to allow_from.pp
#
#   See allow_from.pp for allowed values
#
#   Example:
#   ```
#   sshd::allow_list:
#     "dummyuser":
#       hostlist:
#         - "1.1.1.1"
#       users:
#         - "dummyuser"
#       additional_match_params:
#         PubkeyAuthentication: "yes"
#         AuthenticationMethods: "publickey"
#         Banner: "none"
#         MaxAuthTries: "6"
#         MaxSessions: "10"
#         X11Forwarding: "no"
#         AuthorizedKeysFile: "/delta/home/keys/%u"
#     "dummygroup":
#       hostlist:
#         - "2.2.2.2"
#       groups:
#         - "dummygroup"
#       additional_match_params:
#         PubkeyAuthentication: "yes"
#         AuthenticationMethods: "publickey"
#         Banner: "none"
#         MaxAuthTries: "6"
#         MaxSessions: "10"
#         X11Forwarding: "no"
#         AuthorizedKeysFile: "/delta/home/keys/%u"
#   ```
#
# @param banner
#   A string to create a banner to display before login.
#   Use to display before authentication.
#   Defining this automatically sets the sshd_config option.
#   If you define the Banner config in hiera, the Puppet agent will not run.
#   Example of hiera data:
#   ```
#   sshd::banner: |2+
#
#     Login with NCSA Kerberos + NCSA Duo multi-factor.
#
#     DUO Documentation:  https://go.ncsa.illinois.edu/2fa
#   ```
#
# @param banner_ignore
#   Disable setting banner in sshd even if banner content is set
#
# @param config
#   Hash of global config settings
#   Defaults provided by this module
#   Values from multiple sources are merged
#   Key collisions are resolved in favor of the higher priority value
#
# @param config_file
#   Full path to sshd_config file
#
# @param config_matches
#   Hash of config "match" conditions and settings.
#   Keys are match condition.
#   Vals are a hash of sshd_config settings for the match condition.
#   Expected format:
#   ```
#   ---
#   sshd::config_matches:
#     Unique condition one:
#       SettingOne: val
#       SettingTwo:
#         - val2
#         - val3
#     Unique condition two:
#       SettingOne: val
#       SettingTwo:
#         - val2
#         - val3
#
#   # Example
#   sshd::config_matches:
#     "Address 1.1.1.1,2.2.2.2 Group groupname User user1,user2":
#       PubkeyAuthentication: "yes"
#       AuthenticationMethods: "publickey"
#       Banner: "none"
#       MaxAuthTries: "6"
#       MaxSessions: "10"
#       X11Forwarding: "no"
#       AuthorizedKeysFile: "/cluster/home/keys/%u"
#     "Address 3.3.3.3 Group groupname2":
#       PubkeyAuthentication: "yes"
#       AuthenticationMethods: "publickey"
#       Banner: "none"
#       MaxAuthTries: "6"
#       MaxSessions: "10"
#       X11Forwarding: "no"
#       AuthorizedKeysFile: "/cluster/home/groupname2/%u"
#
#   Note that condition strings must be valid sshd_config criteria-pattern pairs
#   Values from multiple sources are merged
#   Key collisions are resolved in favor of the higher priority value
#   Merges are deep to allow use of the knockout_prefix '-' (to remove a key
#   from the final result).
#
#   Also note that unlike the allow_list parameter, adding match blocks using
#   this param will not edit iptables/sssd/access.conf configs. This might be
#   preferred if you need to add a match block with a negated user like:
#   User *,!wa0*
#   If you tried to use allow_list for a list of users like that it would attempt
#   to create access.conf/sssd allows for the user !wa0*, which doesn't make sense
#   and will actually cause puppet errors
#
#   This param is also useful for adding a match block where the match line is more
#   customized than what allow_list can accept
#   ```
#
# @param config_subsystems
#   Hash of sshd subsystems to enable and configure
#
# @param manage_service
#   Flag of whether to manage sshd service
#
# @param required_packages
#   List of package names to be installed (OS specific).
#   (Defaults provided by module should be sufficient).
#
# @param revoked_keys
#   List of ssh public keys to disallow.
#   Values from multiple sources are merged.
#
# @param revoked_keys_file
#   Full path to name of revoked keys file
#
# @param service_name
#   Name os sshd service
#
# @param trusted_subnets
#   Array of IPs and CIDRs to be allowed through the firewall
#   Values from multiple sources are merged
#
# @example
#   include sshd
class sshd (
  Hash              $allow_list,
  Boolean           $banner_ignore,
  Hash              $config,
  String            $config_file,
  Hash[String,Hash] $config_matches,
  Hash              $config_subsystems,
  Boolean           $manage_service,
  Array[String]     $required_packages,   #per OS
  Array[String]     $revoked_keys,
  String            $revoked_keys_file,   #per OS
  String            $service_name,
  Array             $trusted_subnets,
  Optional[String]  $banner = undef,
) {
  # PACKAGES
  stdlib::ensure_packages( $required_packages, { 'ensure' => 'present' })

  # SERVICE
  if ( $manage_service ) {
    service { $service_name :
      ensure     => running,
      enable     => true,
      hasstatus  => true,
      hasrestart => true,
      require    => Package[$required_packages],
    }
    # SET DEFAULTS TO NOTIFY SERVICE
    $config_defaults = {
      'notify' => Service[$service_name],
    }
  } else {
    # SET DEFAULTS TO SKIP NOTIFY SERVICE
    # THE ENSURE => PRESENT IS A DEFAULT, BUT SETTING IT SO THAT WE CAN SET SOME DEFAULT
    $config_defaults = {
      'ensure' => present,
    }
  }

  # FIREWALL
  each($trusted_subnets) | $index, $sshd_subnet | {
    firewall { "022 allow SSH from ${sshd_subnet}":
      dport  => 22,
      proto  => tcp,
      source => $sshd_subnet,
      jump   => accept,
    }
  }

  # SSHD CONFIG SETTINGS
#  if ( $config_defaults ) {
  $config_match_defaults = $config_defaults + { 'position' => 'before first match' }
#  } else {
#    $config_match_defaults = { 'position' => 'before first match' }
#  }

  # REVOKED KEYS
  file { $revoked_keys_file :
    ensure  => file,
    owner   => root,
    group   => root,
    mode    => '0644',
    content => join( $revoked_keys, "\n" ),
  }
  sshd_config {
    'RevokedKeys' :
      value => $revoked_keys_file,
      ;
    default:
      * => $config_defaults,
      ;
  }

  $puppet_file_header = '# This file is managed by Puppet - Changes may be overwritten'
  exec { 'add puppet header to sshd_config':
    command => "sed -i '1s/^/${puppet_file_header}\\n/' '${config_file}'",
    unless  => "grep '${puppet_file_header}' ${config_file}",
    path    => ['/bin', '/usr/bin'],
  }

  # Apply global sshd_config settings
  $config.each | $key, $val | {
    sshd_config {
      $key :
        value => $val,
        ;
      default:
        * => $config_defaults,
        ;
    }
  }

  # Process config match settings from Hiera
  $config_matches.each | $condition, $data | {
    # Create config match section
    sshd_config_match {
      $condition :
        ;
      default:
        * => $config_match_defaults,
        ;
    }
    # Set each setting inside the match section
    $data.each | $key, $val | {
      sshd_config {
        "${condition} ${key}" :
          key       => $key,
          value     => $val,
          condition => $condition,
          ;
        default:
          * => $config_defaults,
          ;
      }
    }
  }

  # Process allow_list from Hiera
  $allow_list.each | $name, $v | {
    sshd::allow_from { $name: * => $v }
  }

  #SSH Banner creation
  if ($banner != undef ) {
    file { '/etc/sshbanner':
      ensure  => file,
      content => $banner,
      mode    => '0644',
      owner   => '0',
      group   => '0',
    }
    if ( ! $banner_ignore ) {
      sshd_config {
        'Banner' :
          value => '/etc/sshbanner',
          ;
        default:
          * => $config_defaults,
          ;
      }
    }
  }

  # SSHD SUBSYSTEMS, e.g. sftp
  $config_subsystems.each | $key, $val | {
    sshd_config_subsystem {
      $key :
        command => $val,
        ;
      default:
        * => $config_defaults,
        ;
    }
  }
}
