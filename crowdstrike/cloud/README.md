# CrowdStrike Falcon Sensor Helm Installation Script

Interactive helper for preparing CrowdStrike Falcon sensor Helm deployment in Kubernetes cluster.

## Quick Start (One Command)

```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

This command:
- Automatically downloads the latest script version to `/tmp/iitd-csf/`
- Installs all required Python dependencies
- Launches an interactive configuration wizard
- All temporary files are stored in `/tmp/iitd-csf/`

## Features

✅ **Compliant with official CrowdStrike documentation**
- Automatically adds CrowdStrike Helm repository
- Automatically downloads image from CrowdStrike registry to local registry
- Generates correct values.yaml structure
- Creates commands for namespace setup with pod security labels

✅ **Image automation**
- Automatically obtains OAuth token from CrowdStrike API
- Downloads latest Falcon sensor image version
- Re-tags and uploads to your local registry
- Generates pull secrets for Kubernetes

✅ **Prerequisites checks**
- Python ≥3.8, Helm ≥3.0, kubectl ≥1.20, Docker
- Kubernetes cluster access
- Automatic version checking
- Network access to CrowdStrike services (selected region)

✅ **Security and convenience**
- Does NOT perform actual deployment automatically
- Generates commands for review and approval
- Supports environment variables for automation
- Saves configuration in `/tmp/iitd-csf/` for error recovery
- Automatically cleans up saved data after successful completion

## Prerequisites

1. **Installed tools:**
   ```bash
   python3 --version  # ≥3.8
   helm version       # ≥3.0
   kubectl version    # ≥1.20
   docker --version   # any version
   curl              # for script download
   ```

2. **API credentials from CrowdStrike:**
   - Client ID and Secret with scopes: `Falcon Images Download (read)`, `Sensor Download (read)`
   - CID with checksum from Falcon console

3. **Local Docker registry:**
   - Configured and accessible (e.g., Harbor, localhost:5000, etc.)
   - Docker must have push access

4. **Kubernetes cluster access:**
   ```bash
   kubectl get nodes  # should work
   ```

## Usage Options

### 1. Quick start (recommended):
```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

### 2. With environment variables:
```bash
export FALCON_CID="YOUR_CID_WITH_CHECKSUM"
export FALCON_CLIENT_ID="your_client_id" 
export FALCON_CLIENT_SECRET="your_client_secret"
export LOCAL_REGISTRY="harbor.company.com"
export FALCON_IMAGE_TAG="latest"

bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

### 3. Local usage (for development):
```bash
# Clone repository
git clone https://github.com/iIT-Distribution/scripts.git
cd scripts/crowdstrike/cloud

# Run directly
python3 sensor-helm-install.py

# Or through wrapper
./deploy-sensors.sh
```

## What the script does

1. **Checks system requirements** and cluster access
2. **Adds CrowdStrike Helm repository**
3. **Checks saved configuration** from previous runs
4. **Collects configuration** through interactive prompts (or uses saved)
5. **Checks network access** for selected region (critical!)
6. **Automatically downloads image:**
   - Obtains OAuth token from CrowdStrike API
   - Logs into CrowdStrike registry
   - Downloads latest Falcon sensor version
   - Re-tags and uploads to your local registry
7. **Generates values.yaml** file with correct structure
8. **Outputs deployment commands:**
   - Namespace creation with pod security labels
   - Helm install command with all necessary parameters
   - Verification commands to check installation status
9. **Cleans up temporary files** after successful completion

## Example Output

The script generates commands according to documentation:

```bash
# Step 1: Create namespace and set pod security labels
kubectl create namespace falcon-system
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/enforce=privileged
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/audit=privileged
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/warn=privileged

# Step 2: Deploy the Falcon sensor  
helm install falcon-sensor crowdstrike/falcon-sensor -n falcon-system --create-namespace -f /tmp/iitd-csf/falcon-values.yml

# Step 3: Verify installation
# kubectl get pods -n falcon-system
# kubectl get daemonset -n falcon-system
# kubectl logs -n falcon-system -l app.kubernetes.io/name=falcon-sensor --tail=50
```

## Generated values.yaml Structure

```yaml
falcon:
  cid: "YOUR_CID_WITH_CHECKSUM"
node:
  enabled: true
  image:
    repository: "harbor.company.com/falcon-sensor"
    tag: "7.14.0-15300-1.falcon-linux.Release.EU-1"
    pullPolicy: "Always"
    registryConfigJSON: "YOUR_BASE64_DOCKER_CONFIG"
  backend: "bpf"  # or "kernel"
```

## Files in `/tmp/iitd-csf/`

All temporary files are stored in `/tmp/iitd-csf/`:
- **`sensor-helm-install.py`** - main Python script
- **`.falcon-venv/`** - Python virtual environment (if needed)
- **`falcon-sensor-config.json`** - saved configuration
- **`falcon-values.yml`** - generated Helm values file

## Supported Cloud Regions

- `us-1` - api.crowdstrike.com
- `us-2` - api.us-2.crowdstrike.com  
- `eu-1` - api.eu-1.crowdstrike.com
- `us-gov-1` - api.laggar.gcw.crowdstrike.com
- `us-gov-2` - api.us-gov-2.crowdstrike.mil

## Documentation Compliance

The script fully complies with official CrowdStrike documentation:
- ✅ Step 1: API client creation (manual)
- ✅ Step 2: CID retrieval (manual) 
- ✅ Step 3: Image retrieval (automated)
- ✅ Step 4: Helm chart repository setup (automated)
- ✅ Step 5: Sensor installation (command generation)

## Security

- Script does **NOT** perform deployment automatically
- All commands are generated for review and approval
- Clipboard support for convenience
- Input data validation
- OAuth tokens are used only for image downloads
- All files in `/tmp/iitd-csf/` are automatically cleaned by the system

## Troubleshooting

### Script download error
```
curl: (6) Could not resolve host
```
Check internet connection and GitHub access.

### Authentication error
```
❌ Failed to get OAuth token
```
Check Client ID and Secret correctness, and that they have required scopes.

### Image download error
```
❌ Failed to download image
```
Check internet access and that CrowdStrike registry is accessible.

### Local registry upload error
```
❌ Failed to push image to local registry
```
Check that:
- Docker is running
- You are logged into local registry (`docker login`)
- Registry is accessible and has push permissions

### Network issues
```
❌ Network connectivity issues detected for EU-1:
• ts01-lanner-lion.cloudsink.net: Connection timeout
• falcon.eu-1.crowdstrike.com: DNS resolution failed
Cannot proceed without access to CrowdStrike services.

❌ Network connectivity issues prevent proceeding.
```
**Script automatically exits** on network issues.

Check that:
- Firewall allows TLS traffic on port 443
- Proxy is properly configured (if used)
- DNS resolution works for CrowdStrike domains
- Static IP addresses are allowed (if network is restricted)

**Required domains by region:**
- **US-1**: `*.crowdstrike.com`, `*.cloudsink.net`
- **US-2**: `*.us-2.crowdstrike.com`, `*-maverick.cloudsink.net`
- **EU-1**: `*.eu-1.crowdstrike.com`, `*-lion.cloudsink.net`
- **US-GOV-1**: `*.laggar.gcw.crowdstrike.com`, `*.us-gov-west-1.elb.amazonaws.com`
- **US-GOV-2**: `*.crowdstrike.mil`

## Configuration Persistence

The script automatically saves configuration in `/tmp/iitd-csf/falcon-sensor-config.json` after completing the wizard. On next run:

1. **Automatically finds saved configuration** and shows its details
2. **Offers to use saved data** instead of re-entering
3. **Asks to re-enter client_secret** for security reasons
4. **Automatically deletes configuration** after successful completion

### Example of working with saved configuration:

```
╭─ Saved Configuration Found ─╮
│ CID: 1234567890ABCDEF...     │
│ Client ID: falcon-client-id  │
│ Cloud Region: eu-1           │
│ Local Registry: harbor.local │
│ Image Tag: latest            │
│ Namespace: falcon-system     │
│ Backend: bpf                 │
│ Note: Client secret will     │
│ need to be re-entered...     │
╰─────────────────────────────────╯

Use saved configuration? [Y/n]: y

Please re-enter sensitive information:
Falcon API client_secret: [hidden]
```

### Benefits:
- ✅ **Quick recovery** after errors
- ✅ **Security** - sensitive data is not stored
- ✅ **Convenience** - no need to remember all parameters
- ✅ **Automatic cleanup** after successful completion

## Project Structure

```
crowdstrike/cloud/
├── deploy-sensors.sh          # Wrapper script for curl usage
├── sensor-helm-install.py     # Main Python script
├── falcon-values.yml          # Example values file
└── README.md                  # This documentation
```