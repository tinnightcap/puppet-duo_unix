# == Class: duo_unix::pam
#
# Provides duo_unix functionality for SSH via PAM
#
# === Authors
#
# Mark Stanislav <mstanislav@duosecurity.com>
#
class duo_unix::pam inherits duo_unix {
  $aug_pam_path = "/files${duo_unix::pam_file}"
  $aug_match    = "${aug_pam_path}/*/module[. = '${duo_unix::pam_module}']"

  file { '/etc/duo/pam_duo.conf':
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('duo_unix/duo.conf.erb'),
    require => Package[$duo_unix::duo_package];
  }

  if $duo_unix::manage_ssh {
    augeas { 'Duo Security SSH Configuration' :
      changes => [
        'set /files/etc/ssh/sshd_config/UsePAM yes',
        'set /files/etc/ssh/sshd_config/UseDNS no',
        'set /files/etc/ssh/sshd_config/ChallengeResponseAuthentication yes',
        'set /files/etc/ssh/sshd_config/PubkeyAuthentication yes',
        'set /files/etc/ssh/sshd_config/PasswordAuthentication no',
        'set /files/etc/ssh/sshd_config/AuthenticationMethods publickey,keyboard-interactive',
        'set /files/etc/ssh/sshd_config/PermitRootLogin no'
    ],
      require => Package[$duo_unix::duo_package],
      notify  => Service[$duo_unix::ssh_service];
    }
    case $::osfamily {
      'RedHat': {
        augeas { 'Duo Security SSH PAM Configuration' :
          changes => [
            'rm /files/etc/pam.d/sshd/*[type = "auth"][module = "password-auth"]',
            'ins 100 after /files/etc/pam.d/sshd/*[type = "auth"][module = "pam_sepermit.so"]',
            'set /files/etc/pam.d/sshd/100/type auth',
            'set /files/etc/pam.d/sshd/100/control required',
            "set /files/etc/pam.d/sshd/100/module ${duo_unix::pam_module}"
        ],
          require => Package[$duo_unix::duo_package],
          onlyif => "match /files/etc/pam.d/sshd/*[module = '${duo_unix::pam_module}'] size == 0";
        }
      }
      'Debian': {
        augeas { 'Duo Security SSH PAM Configuration' :
          changes => [
            'ins 100 after /files/etc/pam.d/sshd/include[1]',
            'set /files/etc/pam.d/sshd/100/type auth',
            'set /files/etc/pam.d/sshd/100/control "[success=1 default=ignore]"',
            "set /files/etc/pam.d/sshd/100/module ${duo_unix::pam_module}",
            "ins 200 after /files/etc/pam.d/sshd/*[type = 'auth'][module = '${duo_unix::pam_module}']",
            'set /files/etc/pam.d/sshd/200/type auth',
            'set /files/etc/pam.d/sshd/200/control requisite',
            'set /files/etc/pam.d/sshd/200/module pam_deny.so',
            'ins 300 after /files/etc/pam.d/sshd/*[type = "auth"][module = "pam_deny.so"]',
            'set /files/etc/pam.d/sshd/300/type auth',
            'set /files/etc/pam.d/sshd/300/control required',
            'set /files/etc/pam.d/sshd/300/module pam_permit.so',
            'rm /files/etc/pam.d/sshd/include[1]'
        ],
          require => Package[$duo_unix::duo_package],
          onlyif => "match /files/etc/pam.d/sshd/*[module = '${duo_unix::pam_module}'] size == 0";
        }
      }
      default: {
        fail("Module ${module_name} does not support ${::osfamily}")
      }
    }
  }

  if $duo_unix::manage_pam {
    if $::osfamily == 'RedHat' {
      augeas { 'PAM Configuration':
        changes => [
          "set ${aug_pam_path}/2/control ${duo_unix::pam_unix_control}",
          "ins 100 after ${aug_pam_path}/2",
          "set ${aug_pam_path}/100/type auth",
          "set ${aug_pam_path}/100/control sufficient",
          "set ${aug_pam_path}/100/module ${duo_unix::pam_module}"
        ],
        require => Package[$duo_unix::duo_package],
        onlyif  => "match ${aug_match} size == 0";
      }

    } else {
      augeas { 'PAM Configuration':
        changes => [
          "set ${aug_pam_path}/1/control ${duo_unix::pam_unix_control}",
          "ins 100 after ${aug_pam_path}/1",
          "set ${aug_pam_path}/100/type auth",
          "set ${aug_pam_path}/100/control '[success=1 default=ignore]'",
          "set ${aug_pam_path}/100/module ${duo_unix::pam_module}"
        ],
        require => Package[$duo_unix::duo_package],
        onlyif  => "match ${aug_match} size == 0";
      }
    }
  }
}
