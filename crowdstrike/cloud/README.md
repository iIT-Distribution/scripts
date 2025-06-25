# CrowdStrike Falcon Sensor — Kubernetes Helper

A comprehensive interactive utility to install, upgrade, and manage the CrowdStrike Falcon Sensor in Kubernetes. It automates prerequisite checks, image handling, and configuration generation, letting you stay in control of the final deployment.

## Quick Start

The script can be run with a single command. To pass arguments like `--no-sensitive` or `--uninstall`, append them after a `--`:

```bash
# Install or upgrade
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)

# Execute without saving sensitive data
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh) -- --no-sensitive

# Uninstall the sensor
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh) -- --uninstall
```

## Features

- **Install, Upgrade & Uninstall:** A full lifecycle management tool for the Falcon Sensor.
- **Automated Workflow:** Detects existing installations to seamlessly switch between install and upgrade modes.
- **Prerequisites check:** Verifies Python ≥ 3.8, Helm ≥ 3, `kubectl` ≥ 1.20, and Docker.
- **Connectivity test:** Checks network access to the required CrowdStrike cloud region endpoints.
- **Automated image handling:** Pulls the latest sensor image from the CrowdStrike registry and pushes it to your specified local registry.
- **Configuration wizard:** Interactively collects required values (CID, API credentials, etc.).
- **Persistent configuration:** Saves your settings to speed up subsequent runs.
- **Command generation:** Produces the exact `kubectl` and `helm` commands for you to review and execute.
- **Cleanup Utility:** An interactive uninstaller to remove the Helm release, namespace, and configuration files.

## Requirements

Tool | Minimum Version | Notes
--- | --- | ---
Python | 3.8 | Standard on most modern systems
Helm | 3.x |
`kubectl` | 1.20 |
Docker | any | Required for image operations

You will also need:
- CrowdStrike API credentials (Client ID & Secret) with `Falcon Images Download: Read` scope.
- Your CrowdStrike CID (Customer ID).
- A local Docker registry that you have permission to push images to.
- Configured `kubectl` access to your target Kubernetes cluster.

## Configuration & Security

The script saves the configuration from the wizard to make reruns easier.

- **Location:** `~/.config/iitd/csf/falcon-sensor-config.json`
- **Behavior:** By default, the script **saves the `client_secret`** to the configuration file for convenience on trusted workstations. The registry token is never saved.
- **Disabling:** To prevent the `client_secret` from being written to disk, run the script with the `--no-sensitive` flag. This is recommended for shared systems or CI/CD environments.

```bash
python3 sensor-helm-install.py --no-sensitive
```

## Usage

1.  Run the one-liner from the Quick Start section or clone the repository and run `python3 sensor-helm-install.py`.
2.  The script will automatically detect if this is a new installation or an upgrade. Follow the interactive wizard.
3.  To uninstall, run the script with the `--uninstall` flag.
4.  After the script finishes, it will print the `kubectl` and `helm` commands. Review them, then copy and execute them to deploy or manage the sensor.

## Files generated

Path | Purpose
--- | ---
`~/.config/iitd/csf/falcon-sensor-config.json` | Saved wizard answers (no secrets)
`falcon-values.yml` | Helm values to pass with `-f`

## Directory

```
crowdstrike/cloud/
├── deploy-sensors.sh      # curl wrapper
├── sensor-helm-install.py # main script
└── README.md
```

---
Licensed under the Apache 2.0 License. All trademarks belong to their respective owners.