{ pkgs, config, lib, ... }:
{
    options.stig = {
        enable = lib.mkEnableOption "Enable STIG compliance";
    };

    config = lib.mkIf config.stig.enable {
        # V-268168, V-268092, V-268093: FIPS mode and Kernel parameters for auditing
        boot.kernelParams = [ "fips=1" "audit=1" "audit_backlog_limit=8192" ];

        # V-268160, V-268161: Kernel hardening sysctl settings
        boot.kernel.sysctl = {
            "kernel.kptr_restrict" = 1;
            "kernel.randomize_va_space" = 2;
            "net.ipv4.tcp_syncookies" = 1; # V-268141: Protect against SYN flood attacks
        };

        # V-268078: Enable the firewall
        networking.firewall.enable = true;

        # V-268158: Firewall rate-limiting
        networking.firewall.extraCommands = ''
            ip46tables --append INPUT --protocol tcp --dport 22 --match hashlimit --hashlimit-name stig_byte_limit --hashlimit-mode srcip --hashlimit-above 1000000b/second --jump nixos-fw-refuse
            ip46tables --append INPUT --protocol tcp --dport 80 --match hashlimit --hashlimit-name stig_conn_limit --hashlimit-mode srcip --hashlimit-above 1000/minute --jump nixos-fw-refuse
            ip46tables --append INPUT --protocol tcp --dport 443 --match hashlimit --hashlimit-name stig_conn_limit --hashlimit-mode srcip --hashlimit-above 1000/minute --jump nixos-fw-refuse
        '';


        # V-268146: Disable Wireless
        networking.wireless.enable = false;

        # V-268147: Disable Bluetooth
        hardware.bluetooth.enable = false;

        # V-268149, V-268150, V-268151: Time synchronization
        services.timesyncd.enable = true;
        networking.timeServers = [
            "tick.usnogps.navy.mil"
            "tock.usnogps.navy.mil"
        ];
        services.timesyncd.extraConfig = ''
            PollIntervalMaxSec=60
        '';

        # V-268082: Set Login Banner (TTY)
        services.getty.helpLine = ''
            You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

            By using this IS (which includes any device attached to this IS), you consent to the following conditions:

            -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
            -At any time, the USG may inspect and seize data stored on this IS.

            -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

            -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

            -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
        '';


        # V-268159: Enable SSHD
        services.openssh.enable = true;

        # V-268083: Set SSH Banner
        services.openssh.banner = ''
            You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

            By using this IS (which includes any device attached to this IS), you consent to the following conditions:

            -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
            -At any time, the USG may inspect and seize data stored on this IS.

            -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

            -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

            -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
        '';


        # SSHD Settings for STIG Compliance
        services.openssh.permitRootLogin = "no"; # V-268137
        services.openssh.logLevel = "VERBOSE"; # V-268088
        # V-268089: FIPS-approved ciphers
        services.openssh.ciphers = [
            "aes256-ctr"
            "aes192-ctr"
            "aes128-ctr"
        ];
        # V-268157: FIPS-approved MACs
        services.openssh.macs = [
            "hmac-sha2-512"
            "hmac-sha2-256"
        ];

        # V-268142, V-268143: SSH client timeout
        services.openssh.extraConfig = ''
            ClientAliveInterval 600
            ClientAliveCountMax 1
        '';


        # V-268173: Enable AppArmor
        security.apparmor.enable = true;

        # Auditing Configuration
        security.auditd.enable = true; # V-268080, V-268148
        security.audit.enable = true;  # V-268080, V-268148

        # V-268096, V-268091, V-268094, V-268095, V-268097, V-268098, V-268099, V-268100, V-268119, V-268163, V-268164, V-268165, V-268166, V-268167
        security.audit.rules = [
            "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k module_chng"
            "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k module_chng"
            "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
            "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv"
            "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv"
            "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"
            "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
            "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
            "-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
            "-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
            "-w /var/cron/tabs/ -p wa -k services"
            "-w /var/cron/cron.allow -p wa -k services"
            "-w /var/cron/cron.deny -p wa -k services"
            "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
            "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
            "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
            "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
            "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
            "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
            "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
            "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
            "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod"
            "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
            "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod"
            "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
            "-a always,exit -F path=/run/current-system/sw/bin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"
            "-a always,exit -F path=/run/current-system/sw/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"
            "-a always,exit -F path=/run/current-system/sw/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
            "-w /var/log/lastlog -p wa -k logins"
            "-w /etc/sudoers -p wa -k identity"
            "-w /etc/passwd -p wa -k identity"
            "-w /etc/shadow -p wa -k identity"
            "-w /etc/gshadow -p wa -k identity"
            "-w /etc/group -p wa -k identity"
            "-w /etc/security/opasswd -p wa -k identity"
            "--loginuid-immutable"
        ];

        # V-268101, V-268102, V-268103, V-268104, V-268105, V-268106, V-268110: auditd.conf settings
        environment.etc."audit/auditd.conf".text = ''
            log_group = root
            space_left_action = syslog
            admin_space_left_action = syslog
            space_left = 25%
            admin_space_left = 10%
            disk_full_action = HALT
            disk_error_action = HALT
        '';


        # V-268081: PAM configuration for faillock
        security.pam.services = let pamfile = ''
            auth required pam_faillock.so preauth silent audit deny=3 fail_interval=900 unlock_time=0
            auth sufficient pam_unix.so nullok try_first_pass
            auth [default=die] pam_faillock.so authfail audit deny=3 fail_interval=900 unlock_time=0
            auth sufficient pam_faillock.so authsucc
            account required pam_faillock.so
        '';
        in {
            login.text = pkgs.lib.mkDefault pamfile;
            sshd.text = pkgs.lib.mkDefault pamfile;
        };


        # V-268170: Enable pwquality
        security.pam.services.passwd.text = pkgs.lib.mkDefault (pkgs.lib.mkBefore "password requisite ${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so");
        security.pam.services.chpasswd.text = pkgs.lib.mkDefault (pkgs.lib.mkBefore "password requisite ${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so");
        security.pam.services.sudo.text = pkgs.lib.mkDefault (pkgs.lib.mkBefore "password requisite ${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so");

        # V-268126, V-268127, V-268128, V-268129, V-268134, V-268145, V-268169: Password complexity
        environment.etc."/security/pwquality.conf".text = ''
            minlen=15
            dcredit=-1
            ucredit=-1
            lcredit=-1
            ocredit=-1
            difok=8
            dictcheck=1
        '';


        # V-268130, V-268132, V-268133, V-268171, V-268181: Login definitions
        environment.etc."login.defs".text = ''
            ENCRYPT_METHOD SHA512
            PASS_MIN_DAYS 1
            PASS_MAX_DAYS 60
            FAIL_DELAY 4
            UMASK 077
            DEFAULT_HOME yes
            SYS_UID_MIN 400
            SYS_UID_MAX 999
            UID_MIN 1000
            UID_MAX 29999
            SYS_GID_MIN 400
            SYS_GID_MAX 999
            GID_MIN 1000
            GID_MAX 29999
            TTYGROUP tty
            TTYPERM 0620
        '';

        # V-268174: Disable inactive accounts
        environment.etc."/default/useradd".text = ''
            INACTIVE=35
        '';


        # V-268085: Limit concurrent sessions
        security.pam.loginLimits = [
            {
                domain = "*";
                item = "maxlogins";
                type = "hard";
                value = "10";
            }
        ];

        # V-268155, V-268156: Sudo reauthentication
        security.sudo.wheelNeedsPassword = true;
        security.sudo.extraConfig = ''
            Defaults timestamp_timeout=0
        '';

        # V-268138: Disallow mutable users (locks root account)
        users.mutableUsers = false;

        # V-268139: USBGuard
        services.usbguard.enable = true;
        # services.usbguard.rules = '' ... ''; # Generate and add your own ruleset

        # V-268152: Restrict nix to privileged users
        nix.settings.allowed-users = [ "root" "@wheel" ];

        # V-268154: Require signatures for packages
        nix.settings.require-sigs = true;

        # List packages installed in system profile. To search, run:
        # $ nix search wget
        environment.systemPackages = with pkgs; [
            vlock # V-268087
            audit # V-268090
            opencryptoki # V-268136
            aide # V-268153
        ];
    };

}