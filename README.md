# STIG-Compliant NixOS Module

This repository provides a NixOS module designed to help bring a NixOS system into compliance with the Anduril NixOS Security Technical Implementation Guide (STIG). The configurations are based on the security requirements for operating systems as specified by NIST 800, DOD 8500, and JSIG.

This module automates the setup of many STIG controls, including:

- Advanced auditing with auditd
- Strict password complexity and lifecycle policies with pwquality
- Firewall hardening and rate-limiting with iptables
- Secure SSH server configuration
- Kernel hardening via sysctl parameters
- Filesystem and user permission hardening
- Disabling of vulnerable services (Bluetooth, wireless)
- Enabling security features like AppArmor and USBGuard

References
- https://ncp.nist.gov/checklist/1260
- https://stigviewer.com/stigs/anduril_nixos

## Usage

You can integrate this STIG compliance module into your own NixOS configuration using Nix Flakes.

### 1. Add the Flake as an Input

In your system's flake.nix, add this repository as an input:
```
# flake.nix
{
  description = "My STIG-Compliant NixOS Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Add the STIG module flake here
    nixos-stig.url = "github:kthorne/nixos-stig";
  };

  outputs = { self, nixpkgs, nixos-stig }: {
    nixosConfigurations.my-server = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        # Import your main configuration.nix
        ./configuration.nix

        # Import the STIG module from the flake input
        nixos-stig.nixosModules.nixos-stig
      ];
    };
  };
}
```

### 2. Import the Module

In your main `configuration.nix`, you can now use the settings from the STIG module. You still need to configure system-specific details like your user accounts, hardware, and network settings.
```
# configuration.nix
{ config, pkgs, ... }:

{
  imports = [
    # It's recommended to keep your hardware-specific configuration separate.
    ./hardware-configuration.nix
  ];

  # Networking
  networking.hostName = "my-secure-server";
  networking.interfaces.enp1s0.useDHCP = true; # Example network config

  # Define your user account(s)
  users.users.my-admin = {
    isNormalUser = true;
    description = "Admin User";
    extraGroups = [ "wheel" ]; # Gives sudo access
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAA..." # Replace with your public key
    ];
  };

  # Set your time zone
  time.timeZone = "America/New_York";

  # The STIG module will handle the rest of the security settings.
  # You can still override specific settings if needed, for example:
  # services.openssh.port = 2222;

  system.stateVersion = "23.11";
}
```

### 3. Apply the Configuration

After setting up your flake.nix and configuration.nix, apply the configuration to your system:

```bash
sudo nixos-rebuild switch --flake '.#my-server'
```

## Important Considerations & Manual Controls

This module is a **tool to assist with, but does not guarantee, full STIG compliance.** System administrators are responsible for verifying that all controls are correctly implemented and for addressing any procedural or environmental requirements that cannot be fully automated declaratively.

Below is a summary of key STIG controls that require manual configuration or verification.

### High-Severity Findings

    V-268144: Encryption at Rest (LUKS)

        Requirement: All information at rest must be encrypted.

        Action: This module does not handle disk partitioning or encryption. Full-disk encryption using LUKS should be configured during the initial NixOS installation.

    V-268131: Telnet Client Installation

        Requirement: The telnet package must not be installed.

        Action: While this module does not install telnet, it does not explicitly prevent its installation either. Ensure that only trusted users have privileges to install packages.

### Medium-Severity Findings & Procedural Checks

    V-268153: Incomplete AIDE Configuration

        Requirement: AIDE (Advanced Intrusion Detection Environment) must be configured to notify personnel of unauthorized baseline changes.

        Action: The aide package is included, but a complete configuration (the aide.conf file, a Nixpkgs overlay, and a cron job for automated checks) is required for full compliance.

    V-268124, V-268178: PKI Authentication (SSSD)

        Requirement: The system must validate certificates against a DOD trust anchor and properly cache credentials.

        Action: The System Security Services Daemon (sssd) is not configured by this module. This requires fetching DOD CA certificates and configuring sssd.conf for PKI and caching policies.

    V-268177, V-268179: Multifactor Authentication (Smart Card/PKCS11)

        Requirement: Enforce multifactor authentication using a separate hardware device (e.g., CAC/PIV).

        Action: The PAM modules for PKCS11 (security.pam.p11.enable) and the associated certificate policies in pam_pkcs11.conf must be manually configured.

    V-268107, V-268108, V-268109: Remote Log Offloading (syslog-ng)

        Requirement: Audit logs must be offloaded to a different, centralized system.

        Action: This requires enabling and configuring syslog-ng to securely forward logs to a remote server, which is an environment-specific setup.

    V-268084, V-268086: Graphical User Interface (GUI) Controls

        Requirement: Display login banners and enforce session locking for graphical environments.

        Action: These settings are not included as this module assumes a server (headless) environment. If a GUI (like GDM) is installed, these settings must be added.

    ---

    V-268125: Private Key Passphrases

        Requirement: Private keys used for authentication must be protected.

        Action: This is a procedural control. You must ensure all SSH private keys stored on the system are encrypted with a strong passphrase.

    V-268140: Sticky Bit on Public Directories

        Requirement: Prevent unintended information transfer in shared directories.

        Action: Run a post-deployment script to find all world-writable directories and apply the sticky bit (chmod +t).

    File Permissions and Ownership Verification

        Requirement: Various audit and configuration files must have specific ownership (root:root) and permissions.

        Action: While NixOS manages permissions, it is a STIG requirement to verify these on the live system to ensure compliance.