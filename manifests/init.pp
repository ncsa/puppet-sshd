# @summary Configure default sshd settings
#
# Configure default sshd settings
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
#   Note that condition strings must be valid sshd_config criteria-pattern pairs
#   Values from multiple sources are merged
#   Key collisions are resolved in favor of the higher priority value
#   Merges are deep to allow use of the knockout_prefix '-' (to remove a key
#   from the final result).
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
  ensure_packages( $required_packages, {'ensure' => 'present'} )

  # SERVICE
  if ( $manage_service ) {
    service { $service_name :
      ensure     => running,
      enable     => true,
      hasstatus  => true,
      hasrestart => true,
      require    => Package[ $required_packages ],
    }
    # SET DEFAULTS TO NOTIFY SERVICE
    $config_defaults = {
      'notify' => Service[$service_name] ,
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
      action => accept,
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
    ensure  => present,
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
    path    => [ '/bin', '/usr/bin' ],
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
