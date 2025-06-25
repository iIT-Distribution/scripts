#!/usr/bin/env python3
# Copyright 2025 iIT Distribution
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Interactive helper for preparing CrowdStrike Falcon sensor Helm deployment.

Features:
- Checks prerequisites and cluster connectivity
- Downloads sensor image from CrowdStrike registry to local registry  
- Generates Helm values file and deployment commands
- Supports configuration persistence for error recovery
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional
from subprocess import DEVNULL

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()
CONFIG_DIR = Path.home() / ".config" / "iitd" / "csf"
CONFIG_FILE = CONFIG_DIR / "falcon-sensor-config.json"


@dataclass
class FalconConfig:
    cid: str
    client_id: str
    client_secret: str
    cloud_region: str
    image_repo: str
    image_tag: str
    registry_token: str
    local_registry: str
    namespace: str = "falcon-system"
    backend: str = "bpf"
    extra_values: Dict[str, Any] = field(default_factory=dict)

    def to_values_dict(self) -> Dict[str, Any]:
        values = {
            "falcon": {"cid": self.cid},
            "node": {
                "enabled": True,
                "image": {
                    "repository": self.image_repo,
                    "tag": self.image_tag,
                    "pullPolicy": "Always"
                },
                "backend": self.backend,
            },
        }
        
        if self.registry_token:
            values["node"]["image"]["registryConfigJSON"] = self.registry_token
            
        values.update(self.extra_values)
        return values


def version_to_tuple(v: str) -> tuple[int, ...]:
    """Converts a version string to a tuple of integers for comparison."""
    try:
        # Handle potential version suffixes like "-rev1" by splitting them off
        return tuple(map(int, v.split('-')[0].split('.')))
    except (ValueError, AttributeError):
        # Return a low version number if parsing fails
        return (0,)


def run(cmd: list[str] | str, capture: bool = True) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = cmd.split()
    return subprocess.run(cmd, check=True, text=True, capture_output=capture)


def check_binary(name: str, min_version: str | None = None) -> None:
    if shutil.which(name) is None:
        console.print(f"\n[red bold]❌ {name} not found in PATH.[/red bold]")
        sys.exit(1)
    
    if min_version:
        try:
            cp = run([name, "version"], capture=True)
            output = cp.stdout + cp.stderr
            import re
            m = re.search(r"(\d+\.\d+\.\d+)", output)
            if m and tuple(map(int, m.group(1).split("."))) < tuple(map(int, min_version.split("."))):
                console.print(f"\n[red bold]❌ {name} {m.group(1)} detected, but ≥{min_version} required.[/red bold]")
                sys.exit(1)
        except Exception:
            console.print(f"\n[yellow]⚠️  Unable to verify {name} version – continuing.[/yellow]")


def check_cluster() -> None:
    try:
        run(["kubectl", "version", "--client"], capture=True)
        run(["kubectl", "get", "nodes"], capture=True)
    except subprocess.CalledProcessError as exc:
        console.print(f"\n{Panel(str(exc), title='kubectl output')}")
        console.print("\n[red bold]❌ Unable to reach the cluster. Check KUBECONFIG.[/red bold]")
        sys.exit(1)


def get_network_requirements() -> Dict[str, list[str]]:
    return {
        "us-1": [
            "ts01-b.cloudsink.net", "lfodown01-b.cloudsink.net", "lfoup01-b.cloudsink.net",
            "falcon.crowdstrike.com", "assets.falcon.crowdstrike.com", 
            "assets-public.falcon.crowdstrike.com", "api.crowdstrike.com", "firehose.crowdstrike.com"
        ],
        "us-2": [
            "ts01-gyr-maverick.cloudsink.net", "lfodown01-gyr-maverick.cloudsink.net",
            "lfoup01-gyr-maverick.cloudsink.net", "falcon.us-2.crowdstrike.com",
            "assets.falcon.us-2.crowdstrike.com", "assets-public.falcon.us-2.crowdstrike.com",
            "api.us-2.crowdstrike.com", "firehose.us-2.crowdstrike.com"
        ],
        "eu-1": [
            "ts01-lanner-lion.cloudsink.net", "lfodown01-lanner-lion.cloudsink.net",
            "lfoup01-lanner-lion.cloudsink.net", "falcon.eu-1.crowdstrike.com", 
            "assets.falcon.eu-1.crowdstrike.com", "assets-public.falcon.eu-1.crowdstrike.com",
            "api.eu-1.crowdstrike.com", "firehose.eu-1.crowdstrike.com"
        ],
        "us-gov-1": [
            "ts01-laggar-gcw.cloudsink.net", "sensorproxy-laggar-g-524628337.us-gov-west-1.elb.amazonaws.com",
            "lfodown01-laggar-gcw.cloudsink.net", "lfoup01-laggar-gcw.cloudsink.net",
            "ELB-Laggar-P-LFO-DOWNLOAD-1265997121.us-gov-west-1.elb.amazonaws.com",
            "falcon.laggar.gcw.crowdstrike.com", "laggar-falconui01-g-245478519.us-gov-west-1.elb.amazonaws.com",
            "api.laggar.gcw.crowdstrike.com", "firehose.laggar.gcw.crowdstrike.com",
            "falconhose-laggar01-g-720386815.us-gov-west-1.elb.amazonaws.com"
        ],
        "us-gov-2": [
            "ts01-us-gov-2.cloudsink.crowdstrike.mil", "lfodown01-us-gov-2.cloudsink.crowdstrike.mil",
            "lfoup01-us-gov-2.cloudsink.crowdstrike.mil", "falcon.us-gov-2.crowdstrike.mil",
            "api.us-gov-2.crowdstrike.mil", "firehose.us-gov-2.crowdstrike.mil"
        ]
    }


def check_network_connectivity(region: str) -> bool:
    import socket
    import concurrent.futures
    
    network_reqs = get_network_requirements()
    if region not in network_reqs:
        console.print(f"[red]❌ Unknown region: {region}[/red]")
        return False
    
    def check_host(hostname: str, port: int = 443, timeout: int = 5) -> tuple[str, bool, str]:
        try:
            sock = socket.create_connection((hostname, port), timeout)
            sock.close()
            return hostname, True, "OK"
        except socket.gaierror as e:
            return hostname, False, f"DNS resolution failed: {e}"
        except socket.timeout:
            return hostname, False, "Connection timeout"
        except Exception as e:
            return hostname, False, f"Connection failed: {e}"
    
    hosts = network_reqs[region]
    failed_hosts = []
    
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task(f"Checking network connectivity for {region.upper()}", total=len(hosts))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(futures):
                hostname, success, message = future.result()
                if not success:
                    failed_hosts.append((hostname, message))
                progress.advance(task)
        
        progress.update(task, description=f"✅ Network check completed for {region.upper()}")
        progress.stop_task(task)
    
    console.print()
    
    if failed_hosts:
        console.print(f"[red]❌ Network connectivity issues detected for {region.upper()}:[/red]")
        for hostname, error in failed_hosts:
            console.print(f"  [red]• {hostname}: {error}[/red]")
        console.print(f"[red]Cannot proceed without access to CrowdStrike services.[/red]")
        return False
    else:
        console.print(f"[green]✅ Network connectivity OK for {region.upper()}[/green]")
        return True


def setup_helm_repo() -> None:
    try:
        run(["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"], capture=True)
        run(["helm", "repo", "update"], capture=True)
        console.print("[green]✅ CrowdStrike Helm repository added successfully[/green]")
    except subprocess.CalledProcessError as exc:
        console.print(f"[yellow]⚠️  Helm repo setup failed (might already exist): {exc}[/yellow]")


def get_cloud_api_config(cloud_region: str) -> tuple[str, str, str]:
    configs = {
        "us-1": ("api.crowdstrike.com", "us-1", "registry.crowdstrike.com"),
        "us-2": ("api.us-2.crowdstrike.com", "us-2", "registry.crowdstrike.com"),
        "eu-1": ("api.eu-1.crowdstrike.com", "eu-1", "registry.crowdstrike.com"),
        "us-gov-1": ("api.laggar.gcw.crowdstrike.com", "gov1", "registry.laggar.gcw.crowdstrike.com"),
        "us-gov-2": ("api.us-gov-2.crowdstrike.mil", "gov2", "registry.us-gov-2.crowdstrike.mil"),
    }
    return configs.get(cloud_region, configs["us-1"])


def get_oauth_token(client_id: str, client_secret: str, api_base: str) -> str:
    try:
        response = requests.post(f"https://{api_base}/oauth2/token", data={"client_id": client_id, "client_secret": client_secret})
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.HTTPError as e:
        console.print(f"[red]❌ Failed to get OAuth token: HTTP {e.response.status_code}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]Client ID: {client_id}[/red]")
        console.print(f"[red]Response: {e.response.text}[/red]")
        console.print(f"[yellow]Hint: Check your client credentials and API scopes[/yellow]")
        sys.exit(1)
    except KeyError as e:
        console.print(f"[red]❌ Unexpected API response format: {e}[/red]")
        console.print(f"[red]Response: {response.text}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Failed to get OAuth token: {e}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]Client ID: {client_id}[/red]")
        sys.exit(1)


def get_registry_token(oauth_token: str, api_base: str, cid: str, cs_registry: str, cloud_tag: str) -> str:
    try:
        cid_first_part = cid.split('-')[0].lower()
        username = f"fc-{cid_first_part}"
        
        response = requests.get(f"https://{api_base}/container-security/entities/image-registry-credentials/v1", headers={"Authorization": f"Bearer {oauth_token}"})
        response.raise_for_status()
        
        data = response.json()
        if "resources" not in data or not data["resources"]:
            console.print(f"[red]❌ No resources in API response: {data}[/red]")
            sys.exit(1)
            
        password = data["resources"][0]["token"]
        
        scope = f"repository:falcon-sensor/{cloud_tag}/release/falcon-sensor:pull"
        registry_token_url = f"https://{cs_registry}/v2/token"
        
        token_response = requests.get(
            registry_token_url,
            params={"service": cs_registry, "scope": scope},
            auth=(username, password)
        )
        
        if token_response.status_code == 200:
            return token_response.json().get("token", "")
        else:
            console.print(f"[yellow]⚠️  Failed to get registry token (HTTP {token_response.status_code}): {token_response.text}[/yellow]")
            return ""
            
    except requests.HTTPError as e:
        console.print(f"[red]❌ Failed to get registry credentials: HTTP {e.response.status_code}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]Response: {e.response.text}[/red]")
        console.print(f"[yellow]Hint: Check your OAuth token and API access[/yellow]")
        sys.exit(1)
    except (KeyError, IndexError) as e:
        console.print(f"[red]❌ Unexpected API response format: {e}[/red]")
        console.print(f"[red]Response: {data}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Failed to get registry credentials: {e}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]CID: {cid}[/red]")
        sys.exit(1)


def get_registry_credentials(oauth_token: str, api_base: str, cid: str) -> tuple[str, str]:
    try:
        cid_first_part = cid.split('-')[0].lower()
        username = f"fc-{cid_first_part}"
        
        response = requests.get(f"https://{api_base}/container-security/entities/image-registry-credentials/v1", headers={"Authorization": f"Bearer {oauth_token}"})
        response.raise_for_status()
        
        data = response.json()
        if "resources" not in data or not data["resources"]:
            console.print(f"[red]❌ No resources in API response: {data}[/red]")
            sys.exit(1)
            
        password = data["resources"][0]["token"]
        return username, password
    except requests.HTTPError as e:
        console.print(f"[red]❌ Failed to get registry credentials: HTTP {e.response.status_code}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]Response: {e.response.text}[/red]")
        console.print(f"[yellow]Hint: Check your OAuth token and API access[/yellow]")
        sys.exit(1)
    except (KeyError, IndexError) as e:
        console.print(f"[red]❌ Unexpected API response format: {e}[/red]")
        console.print(f"[red]Response: {data}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Failed to get registry credentials: {e}[/red]")
        console.print(f"[red]API Base: {api_base}[/red]")
        console.print(f"[red]CID: {cid}[/red]")
        sys.exit(1)


def get_latest_image_tag(cs_registry: str, cloud_tag: str, cs_username: str, cs_password: str) -> Optional[str]:
    """Queries the CrowdStrike registry to find the latest versioned sensor tag."""
    tags_url = f"https://{cs_registry}/v2/falcon-sensor/{cloud_tag}/release/falcon-sensor/tags/list"
    console.print(f"🔍 Querying for latest sensor version...")
    try:
        tag_response = requests.get(tags_url, auth=(cs_username, cs_password), timeout=30)
        
        if tag_response.status_code != 200:
            console.print(f"[yellow]⚠️  Failed to get image tags (HTTP {tag_response.status_code})[/yellow]")
            return None

        tags_data = tag_response.json()
        tags = tags_data.get("tags", [])
        if not tags:
            console.print("[yellow]⚠️  No tags found in registry response.[/yellow]")
            return None

        versioned_tags = sorted(
            [t for t in tags if t != "latest" and t[0].isdigit()], 
            key=version_to_tuple, 
            reverse=True
        )
        
        if versioned_tags:
            return versioned_tags[0]
        else:
            console.print("[yellow]⚠️  No versioned tags found.[/yellow]")
            return None
            
    except requests.RequestException as e:
        console.print(f"[yellow]⚠️  Failed to fetch image tags: {e}[/yellow]")
        return None
    except Exception as e:
        console.print(f"[yellow]⚠️  Unexpected error getting tags: {e}[/yellow]")
        return None


def check_helm_release_exists(release_name: str, namespace: str) -> bool:
    """Checks if a Helm release exists in a given namespace."""
    try:
        subprocess.run(
            ["helm", "status", release_name, "-n", namespace],
            check=True, stdout=DEVNULL, stderr=DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_installed_image_tag(release_name: str, namespace: str) -> Optional[str]:
    """Gets the deployed image tag from a Helm release."""
    try:
        cp = run(["helm", "get", "values", release_name, "-n", namespace, "-o", "json"], capture=True)
        values = json.loads(cp.stdout)
        return values.get("node", {}).get("image", {}).get("tag")
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
        console.print(f"[yellow]⚠️  Could not retrieve installed image tag for {release_name}[/yellow]")
        return None


def download_and_push_image(config: 'FalconConfig', oauth_token: str, cs_username: str, cs_password: str) -> tuple[str, str]:
    api_base, cloud_tag, cs_registry = get_cloud_api_config(config.cloud_region)
    
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task("Downloading and pushing image", total=4)
        
        progress.update(task, description="Getting registry API token...")
        registry_token = get_registry_token(oauth_token, api_base, config.cid, cs_registry, cloud_tag)
        progress.advance(task)
        
        progress.update(task, description="Logging into CrowdStrike registry...")
        try:
            result = run(["docker", "login", cs_registry, "-u", cs_username, "-p", cs_password], capture=True)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[red]❌ Failed to login to CrowdStrike registry {cs_registry}[/red]")
            console.print(f"[red]Username: {cs_username}[/red]")
            console.print(f"[red]Error: {e}[/red]")
            if e.stdout:
                console.print(f"[red]STDOUT: {e.stdout}[/red]")
            if e.stderr:
                console.print(f"[red]STDERR: {e.stderr}[/red]")
            sys.exit(1)
        progress.advance(task)
        
        cs_image = f"{cs_registry}/falcon-sensor/{cloud_tag}/release/falcon-sensor"
        progress.update(task, description=f"Downloading image [bold]{config.image_tag}[/bold] from CrowdStrike...")
        try:
            full_cs_image = f"{cs_image}:{config.image_tag}"
            run(["docker", "pull", full_cs_image], capture=True)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[red]❌ Failed to download image {full_cs_image}[/red]")
            console.print(f"[red]Registry: {cs_registry}[/red]")
            console.print(f"[red]Image path: {cs_image}[/red]")
            console.print(f"[red]Tag: {config.image_tag}[/red]")
            console.print(f"[red]Error: {e}[/red]")
            if e.stdout:
                console.print(f"[red]STDOUT: {e.stdout}[/red]")
            if e.stderr:
                console.print(f"[red]STDERR: {e.stderr}[/red]")
            console.print(f"[yellow]Hint: Check if the image exists and you have access to it[/yellow]")
            sys.exit(1)
        except requests.RequestException as e:
            console.print(f"\n[red]❌ Failed to get image tags from API[/red]")
            console.print(f"[red]Tags URL: {tags_url}[/red]")
            console.print(f"[red]API Error: {e}[/red]")
            console.print(f"[yellow]Hint: Check network connectivity to CrowdStrike registry[/yellow]")
            sys.exit(1)
        progress.advance(task)
        
        local_image = f"{config.local_registry}/falcon-sensor"
        local_full_image = f"{local_image}:{config.image_tag}"
        progress.update(task, description="Pushing to local registry...")
        try:
            run(["docker", "tag", full_cs_image, local_full_image], capture=True)
            run(["docker", "push", local_full_image], capture=True)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[red]❌ Failed to push image to local registry[/red]")
            console.print(f"[red]Source image: {full_cs_image}[/red]")
            console.print(f"[red]Target image: {local_full_image}[/red]")
            console.print(f"[red]Local registry: {config.local_registry}[/red]")
            console.print(f"[red]Error: {e}[/red]")
            if e.stdout:
                console.print(f"[red]STDOUT: {e.stdout}[/red]")
            if e.stderr:
                console.print(f"[red]STDERR: {e.stderr}[/red]")
            console.print(f"[yellow]Hint: Check if you're logged into the local registry and have push permissions[/yellow]")
            sys.exit(1)
        progress.advance(task)
        
        progress.update(task, description="✅ Image download and push completed", completed=4)
        progress.stop_task(task)
    
    console.print(f"[green]✅ Image successfully downloaded and pushed to {local_full_image}[/green]")
    return local_image, config.image_tag


def generate_pull_token(local_registry: str) -> str:
    try:
        docker_config_path = Path.home() / ".docker" / "config.json"
        if docker_config_path.exists():
            with open(docker_config_path, 'r') as f:
                docker_config = json.load(f)
                
            if "auths" in docker_config and local_registry in docker_config["auths"]:
                config_json = json.dumps(docker_config)
                return base64.b64encode(config_json.encode()).decode()
        
        registry_config = {"auths": {local_registry: {}}}
        config_json = json.dumps(registry_config)
        encoded_config = base64.b64encode(config_json.encode()).decode()
        
        console.print(f"[yellow]⚠️  No authentication found for local registry {local_registry}[/yellow]")
        console.print(f"[yellow]You may need to create image pull secrets manually if your local registry requires authentication[/yellow]")
        
        return encoded_config
        
    except Exception as e:
        console.print(f"[yellow]⚠️  Failed to generate pull token: {e}[/yellow]")
        return ""


def save_config_to_file(config: FalconConfig, save_sensitive: bool = True) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config_dict = asdict(config)
        
        if not save_sensitive:
            config_dict["client_secret"] = ""
        
        # Registry token is always cleared for security
        config_dict["registry_token"] = ""
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        if save_sensitive:
            console.print(f"[green]✅ Configuration saved to {CONFIG_FILE} (including sensitive data)[/green]")
        else:
            console.print(f"[green]✅ Configuration saved to {CONFIG_FILE} (sensitive data excluded)[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️  Failed to save configuration: {e}[/yellow]")


def load_config_from_file() -> Optional[FalconConfig]:
    try:
        if not CONFIG_FILE.exists():
            return None
            
        with open(CONFIG_FILE, 'r') as f:
            config_dict = json.load(f)
        
        config = FalconConfig(**config_dict)
        return config
    except Exception as e:
        console.print(f"[yellow]⚠️  Failed to load configuration: {e}[/yellow]")
        return None


def display_saved_config(config: FalconConfig) -> None:
    console.print(Panel("Saved Configuration Found", style="bold blue"))
    console.print(f"[cyan]CID:[/cyan] {config.cid[:20]}..." if len(config.cid) > 20 else f"[cyan]CID:[/cyan] {config.cid}")
    console.print(f"[cyan]Client ID:[/cyan] {config.client_id}")
    console.print(f"[cyan]Cloud Region:[/cyan] {config.cloud_region}")
    console.print(f"[cyan]Local Registry:[/cyan] {config.local_registry}")
    console.print(f"[cyan]Image Tag:[/cyan] {config.image_tag}")
    console.print(f"[cyan]Namespace:[/cyan] {config.namespace}")
    console.print(f"[cyan]Backend:[/cyan] {config.backend}")
    
    if config.client_secret:
        console.print(f"[green]✅ Client secret is saved[/green]")
    else:
        console.print(f"[yellow]⚠️  Client secret is not saved (will need to be entered)[/yellow]")


def check_and_load_existing_config() -> Optional[FalconConfig]:
    saved_config = load_config_from_file()
    if saved_config is None:
        return None
    
    console.print()
    display_saved_config(saved_config)
    console.print()
    
    use_saved = Confirm.ask("Use saved configuration?", default=True)
    if not use_saved:
        try:
            CONFIG_FILE.unlink()
            console.print(f"[yellow]Removed old configuration file[/yellow]")
        except:
            pass
        return None
    
    # Check if client_secret is already saved
    if not saved_config.client_secret:
        console.print("\n[yellow]Please enter the client secret (not saved in configuration):[/yellow]")
        saved_config.client_secret = Prompt.ask(
            "Falcon API [bold]client_secret[/]", 
            default=os.getenv("FALCON_CLIENT_SECRET", ""), 
            password=True
        ).strip()
        
        if not saved_config.client_secret:
            console.print("[red]❌ Client secret is required[/red]")
            return None
    else:
        console.print("[green]✅ Using saved client secret[/green]")
    
    return saved_config


def wizard() -> FalconConfig:
    console.print(Panel("Installation wizard", style="bold cyan"))
    console.print(f"[dim]Configuration will be saved to: {CONFIG_FILE}[/dim]")
    console.print()

    cid = Prompt.ask("CrowdStrike [bold]CID[/] (with checksum)", default=os.getenv("FALCON_CID", "")).strip()
    if not cid:
        console.print("[red]❌ CID is required. Get it from Falcon console → Sensor downloads[/red]")
        sys.exit(1)
        
    client_id = Prompt.ask("Falcon API [bold]client_id[/]", default=os.getenv("FALCON_CLIENT_ID", "")).strip()
    if not client_id:
        console.print("[red]❌ Client ID is required[/red]")
        sys.exit(1)
        
    client_secret = Prompt.ask(
        "Falcon API [bold]client_secret[/]", default=os.getenv("FALCON_CLIENT_SECRET", ""), password=True
    ).strip()
    if not client_secret:
        console.print("[red]❌ Client secret is required[/red]")
        sys.exit(1)

    cloud_region = Prompt.ask(
        "Falcon cloud region",
        choices=["us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2"],
        default="eu-1",
    )

    local_registry = Prompt.ask(
        "Local registry [bold]URL[/] (e.g., localhost:5000, harbor.company.com)",
        default=os.getenv("LOCAL_REGISTRY", "localhost:5000")
    ).strip()
    if not local_registry:
        console.print("[red]❌ Local registry is required[/red]")
        sys.exit(1)

    image_tag = Prompt.ask("Sensor image [bold]tag[/] (leave empty for latest)", default=os.getenv("FALCON_IMAGE_TAG", "latest"))
    namespace = Prompt.ask("Kubernetes namespace", default="falcon-system")
    backend = Prompt.ask("Sensor backend", choices=["bpf", "kernel"], default="bpf")

    return FalconConfig(
        cid=cid, client_id=client_id, client_secret=client_secret, cloud_region=cloud_region,
        image_repo="", image_tag=image_tag, registry_token="", local_registry=local_registry,
        namespace=namespace, backend=backend,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactive helper for preparing CrowdStrike Falcon sensor Helm deployment",
        epilog=f"Configuration is stored in: {CONFIG_FILE}"
    )
    parser.add_argument(
        "--no-sensitive",
        action="store_true",
        help="Do not save sensitive information (client_secret) to configuration file. "
             "Use this for shared systems or CI/CD environments."
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the Falcon sensor and clean up resources."
    )
    return parser.parse_args()


def uninstall_wizard() -> None:
    """Interactive wizard to uninstall the Falcon sensor and related resources."""
    console.print(Panel("Falcon Sensor Uninstaller", style="bold red"))

    cfg = load_config_from_file()
    namespace = "falcon-system"
    if cfg:
        namespace = cfg.namespace
        console.print(f"Loaded configuration. Using namespace: [cyan]{namespace}[/cyan]")
    else:
        console.print("[yellow]No saved configuration found.[/yellow]")
        namespace = Prompt.ask("Please enter the namespace where the sensor is installed", default="falcon-system")

    if not check_helm_release_exists("falcon-sensor", namespace):
        console.print(f"[red]❌ No active 'falcon-sensor' release found in namespace '{namespace}'.[/red]")
        sys.exit(1)

    console.print(f"\nThis will uninstall the 'falcon-sensor' Helm release from the '[bold]{namespace}[/bold]' namespace.")
    if not Confirm.ask("Are you sure you want to proceed?", default=False):
        console.print("Uninstall cancelled.")
        sys.exit(0)

    try:
        console.print(f"🗑️ Uninstalling Helm release 'falcon-sensor' from namespace '{namespace}'...")
        run(["helm", "uninstall", "falcon-sensor", "-n", namespace], capture=False)
        console.print("[green]✅ Helm release uninstalled successfully.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Failed to uninstall Helm release: {e}[/red]")
        sys.exit(1)

    if Confirm.ask(f"\nDo you want to delete the Kubernetes namespace '[bold]{namespace}[/bold]'?", default=False):
        try:
            console.print(f"🗑️ Deleting namespace '{namespace}'...")
            run(["kubectl", "delete", "namespace", namespace], capture=False)
            console.print(f"[green]✅ Namespace '{namespace}' deleted.[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Failed to delete namespace: {e}[/red]")

    if CONFIG_FILE.exists():
        if Confirm.ask(f"\nDo you want to remove the configuration file at '[bold]{CONFIG_FILE}[/bold]'?", default=False):
            try:
                CONFIG_FILE.unlink()
                console.print("[green]✅ Configuration file removed.[/green]")
            except OSError as e:
                console.print(f"[red]❌ Failed to remove configuration file: {e}[/red]")

    console.print("\n[bold]Uninstallation complete.[/bold]")


def main() -> None:
    args = parse_args()

    if args.uninstall:
        uninstall_wizard()
        sys.exit(0)
    
    if shutil.which("docker") is None:
        console.print("\n[red bold]❌ Docker is required for image operations.[/red bold]")
        sys.exit(1)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task("Checking prerequisites", total=3)
        
        progress.update(task, description="Checking Helm version...")
        check_binary("helm", "3.0.0")
        progress.advance(task)
        
        progress.update(task, description="Checking kubectl version...")
        check_binary("kubectl", "1.20.0")
        progress.advance(task)

        progress.update(task, description="Checking cluster access...")
        check_cluster()
        progress.advance(task)
        
        progress.update(task, description="✅ Prerequisites check completed")
        progress.stop_task(task)

    console.print()

    console.print("[yellow]Setting up CrowdStrike Helm repository...[/yellow]")
    setup_helm_repo()
    console.print()
    
    # --- Load config or run wizard ---
    cfg = check_and_load_existing_config()
    if cfg:
        is_new_install = not check_helm_release_exists("falcon-sensor", cfg.namespace)
        if is_new_install:
            console.print("[yellow]⚠️  Config file found, but no release in cluster. Treating as new install.[/yellow]")
    else:
        cfg = wizard()
        is_new_install = True

    # --- Authenticate with CrowdStrike API ---
    api_base, cloud_tag, cs_registry = get_cloud_api_config(cfg.cloud_region)
    oauth_token = get_oauth_token(cfg.client_id, cfg.client_secret, api_base)
    cs_username, cs_password = get_registry_credentials(oauth_token, api_base, cfg.cid)
    
    target_tag = cfg.image_tag

    # --- Installation vs. Update Logic ---
    if is_new_install:
        console.print("\n[cyan]🚀 Starting new installation...[/cyan]")
        if target_tag == "latest":
            latest_tag = get_latest_image_tag(cs_registry, cloud_tag, cs_username, cs_password)
            if latest_tag:
                target_tag = latest_tag
                console.print(f"Using latest version: [bold green]{target_tag}[/bold green]")
            else:
                console.print("[red]❌ Could not resolve 'latest' tag. Please specify a version manually.[/red]")
                sys.exit(1)
    else:  # Update path
        console.print("\n[cyan]🔄 Checking for updates to existing installation...[/cyan]")
        installed_tag = get_installed_image_tag("falcon-sensor", cfg.namespace)
        if not installed_tag:
            console.print("[red]❌ Could not determine installed version. Exiting.[/red]")
            sys.exit(1)
        
        console.print(f"Installed version: [bold]{installed_tag}[/bold]")
        latest_tag = get_latest_image_tag(cs_registry, cloud_tag, cs_username, cs_password)
        if not latest_tag:
            console.print("[yellow]⚠️  Could not determine latest available version. Cannot check for updates.[/yellow]")
            sys.exit(1)
            
        console.print(f"Latest available version: [bold green]{latest_tag}[/bold green]")
        
        if version_to_tuple(latest_tag) <= version_to_tuple(installed_tag):
             console.print("\n[green]✅ You are running the latest version.[/green]")
             sys.exit(0)
             
        update = Confirm.ask(f"Do you want to upgrade from [bold yellow]{installed_tag}[/bold yellow] to [bold green]{latest_tag}[/bold green]?", default=True)
        if not update:
            console.print("Update cancelled by user.")
            sys.exit(0)
        
        target_tag = latest_tag

    # --- Common logic for both install and update ---
    cfg.image_tag = target_tag
    
    network_ok = check_network_connectivity(cfg.cloud_region)
    if not network_ok:
        console.print(f"\n[red bold]❌ Network connectivity issues prevent proceeding.[/red bold]")
        console.print(f"[yellow]Please check your firewall, proxy settings, and network access to CrowdStrike services.[/yellow]")
        console.print(f"[yellow]Required domains for {cfg.cloud_region.upper()} region are listed above.[/yellow]")
        sys.exit(1)

    local_image_repo, actual_tag = download_and_push_image(cfg, oauth_token, cs_username, cs_password)
    cfg.image_repo = local_image_repo
    cfg.image_tag = actual_tag

    console.print()
    save_config_to_file(cfg, save_sensitive=not args.no_sensitive)
    console.print()
    
    cfg.registry_token = generate_pull_token(cfg.local_registry)

    values_yaml = yaml.dump(cfg.to_values_dict(), default_flow_style=False)

    out_path = Path(Prompt.ask("Write [bold]values.yml[/] to", default=str(CONFIG_DIR / "falcon-values.yml")))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(values_yaml)
    console.print(Panel(f"values.yml written to [green]{out_path}[/green]", title="✅ Success", style="green"))

    helm_cmd = f"helm upgrade --install falcon-sensor crowdstrike/falcon-sensor -n {cfg.namespace} --create-namespace -f {out_path}"

    verification_commands = [
        f"kubectl get pods -n {cfg.namespace}",
        f"kubectl get daemonset -n {cfg.namespace}",
        f"kubectl logs -n {cfg.namespace} -l app.kubernetes.io/name=falcon-sensor --tail=50"
    ]

    all_commands = []
    step = 1

    if is_new_install:
        namespace_commands = [
            f"kubectl create namespace {cfg.namespace}",
            f"kubectl label ns --overwrite {cfg.namespace} pod-security.kubernetes.io/enforce=privileged",
            f"kubectl label ns --overwrite {cfg.namespace} pod-security.kubernetes.io/audit=privileged", 
            f"kubectl label ns --overwrite {cfg.namespace} pod-security.kubernetes.io/warn=privileged"
        ]
        console.print(f"\n[bold blue]Step {step}: Create namespace and set pod security labels[/bold blue]")
        for cmd in namespace_commands:
            console.print(f"{cmd}")
        all_commands.extend(namespace_commands)
        all_commands.append("")
        step += 1

    deploy_verb = "Deploy" if is_new_install else "Upgrade"
    console.print(f"\n[bold blue]Step {step}: {deploy_verb} the Falcon sensor[/bold blue]")
    console.print(f"{helm_cmd}")
    all_commands.append(helm_cmd)
    all_commands.append("")
    step += 1

    console.print(f"\n[bold blue]Step {step}: Verify installation[/bold blue]")
    for cmd in verification_commands:
        console.print(f"{cmd}")

    all_commands.extend(["# " + cmd for cmd in verification_commands])

    all_commands_str = "\n".join(all_commands)
    if shutil.which("pbcopy"):
        subprocess.run("pbcopy", input=all_commands_str, text=True)
        console.print("\n[grey]All commands copied to clipboard.[/grey]")
    elif shutil.which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"], input=all_commands_str, text=True)
        console.print("\n[grey]All commands copied to clipboard.[/grey]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
