# iIT Distribution Scripts

A collection of curated, reusable scripts for system administration and DevOps tasks, designed to automate common workflows and improve efficiency.

## 🚀 Featured: CrowdStrike Falcon Kubernetes Helper

Quickly prepare a CrowdStrike Falcon Sensor deployment for your Kubernetes cluster with our interactive helper. It handles the full lifecycle: installation, upgrades, and uninstallation.

```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

This script automates image handling, configuration, and command generation. For detailed information, see the [CrowdStrike Cloud README](./crowdstrike/cloud/README.md).

## Available Scripts

### 🛡️ CrowdStrike Falcon

A set of utilities for managing the CrowdStrike Falcon Sensor.

| Path | Purpose |
| --- | --- |
| `crowdstrike/cloud/` | An interactive helper to install, upgrade, and uninstall the Falcon Sensor on Kubernetes via Helm. It handles image mirroring, configuration, and generates the necessary commands. See its [README](./crowdstrike/cloud/README.md) for full details. |
| `crowdstrike/check-usermode.sh` | A shell script to verify that the CrowdStrike user-mode sensor is loaded and healthy on a Linux host. |

## License

This repository is licensed under the Apache 2.0 License. See the [LICENSE](./LICENSE) file for details.

---
© 2025 iIT Distribution