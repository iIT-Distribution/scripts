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
Interactive helper for preparing CrowdStrike Falcon products Helm deployment.

Features:
- Manages Falcon Sensor and Kubernetes Admission Controller (KAC) in a single run.
- Checks prerequisites and cluster connectivity.
- Downloads product images from CrowdStrike registry to a local registry.
- Generates Helm values files and deployment commands.
- Supports a unified, persistent configuration for error recovery.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from subprocess import DEVNULL
from typing import Any, Dict, List, Optional, Type

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, InvalidResponse, Prompt
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()
CONFIG_DIR = Path.home() / ".config" / "iitd" / "csf"
CONFIG_FILE = CONFIG_DIR / "falcon-deployment-config.json"


def print_banner() -> None:
    """Prints the iITD banner."""
    banner = r"""
[white]  ███ [red] █████ ███████████[white] ██████████  
[white] ░░░  [red]░░███ ░█░░░███░░░█[white]░░███░░░░███ 
[white] ████ [red] ░███ ░   ░███  ░ [white] ░███   ░░███
[white]░░███ [red] ░███     ░███    [white] ░███    ░███
[white] ░███ [red] ░███     ░███    [white] ░███    ░███
[white] ░███ [red] ░███     ░███    [white] ░███    ███ 
[white] █████[red] █████    █████   [white] ██████████  
[white]░░░░░ [red]░░░░░    ░░░░░    [white]░░░░░░░░░░   
    """
    console.print(banner)
    console.print("[bold]Copyright 2025 (c) iIT Distribution - iitd.ua[/bold]")
    console.print("[bold]All rights reserved.[/bold]")
    console.print()
    console.print("CrowdStrike Cloud Security Deployment Helper")


class FalconComponent(Enum):
    SENSOR = "Falcon Sensor"
    KAC = "Kubernetes Admission Controller"
    IAR = "Image Assessment at Runtime"

    @property
    def release_name(self) -> str:
        return {
            "SENSOR": "falcon-sensor",
            "KAC": "falcon-kac",
            "IAR": "falcon-imageanalyzer"
        }[self.name]

    @property
    def image_name(self) -> str:
        return self.release_name

    @property
    def chart_name(self) -> str:
        if self == FalconComponent.IAR:
            return "crowdstrike/falcon-image-analyzer"
        return f"crowdstrike/{self.release_name}"

    @property
    def default_namespace(self) -> str:
        return {
            "SENSOR": "falcon-system",
            "KAC": "falcon-kac",
            "IAR": "falcon-imageanalyzer"
        }[self.name]

    def get_image_path(self, cloud_tag: str) -> str:
        """Returns the full image path in the registry, without the registry URL."""
        return f"{self.image_name}/{cloud_tag}/release/{self.image_name}"

    def to_values_dict(self, cfg: "ComponentConfig", parent_cfg: "DeploymentConfig", no_sensitive: bool) -> Dict[str, Any]:
        """Generates the Helm values dictionary for this component."""
        values: Dict[str, Any] = {}
        if self == FalconComponent.SENSOR:
            values = {
                "falcon": {"cid": parent_cfg.cid},
                "node": {
                    "enabled": True,
                    "image": {"repository": cfg.image_repo, "tag": cfg.image_tag, "pullPolicy": "Always"},
                    "backend": cfg.backend,
                },
            }
            if parent_cfg.registry_token:
                values["node"]["image"]["registryConfigJSON"] = parent_cfg.registry_token
        elif self == FalconComponent.KAC:
            values = {
                "falcon": {"cid": parent_cfg.cid},
                "image": {"repository": cfg.image_repo, "tag": cfg.image_tag, "pullPolicy": "Always"},
                "clusterName": cfg.cluster_name,
            }
            if parent_cfg.registry_token:
                values["image"]["registryConfigJSON"] = parent_cfg.registry_token
        elif self == FalconComponent.IAR:
            # IAR chart has a different values structure compared to Sensor/KAC
            values = {
                "image": {"repository": cfg.image_repo, "tag": cfg.image_tag, "pullPolicy": "Always"},
                "crowdstrikeConfig": {
                    "cid": parent_cfg.cid,
                    "clientID": parent_cfg.client_id,
                    "agentRegion": parent_cfg.cloud_region,
                    "clusterName": cfg.cluster_name,
                }
            }
            if not no_sensitive:
                values["crowdstrikeConfig"]["clientSecret"] = parent_cfg.client_secret

            if cfg.iar_mode == 'watcher':
                values["deployment"] = {"enabled": True}
                values["daemonset"] = {"enabled": False}
            elif cfg.iar_mode == 'socket':
                values["deployment"] = {"enabled": False}
                values["daemonset"] = {"enabled": True}
                values["crowdstrikeConfig"]["agentRuntime"] = cfg.iar_runtime

            if parent_cfg.registry_token:
                values["image"]["registryConfigJSON"] = parent_cfg.registry_token

        values.update(cfg.extra_values)
        return values


@dataclass
class Command:
    component: FalconComponent
    description: str
    cmd_list: List[str]
    is_verification: bool = False
    capture_output: bool = True
    can_fail: bool = False


@dataclass
class ComponentConfig:
    namespace: str
    image_tag: str
    image_repo: str = ""
    # Sensor-specific
    backend: Optional[str] = None
    # KAC-specific
    cluster_name: Optional[str] = None
    # IAR-specific
    iar_mode: Optional[str] = None
    iar_runtime: Optional[str] = None
    extra_values: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentConfig:
    cid: str
    client_id: str
    client_secret: str
    cloud_region: str
    local_registry: str
    components: Dict[str, ComponentConfig] = field(default_factory=dict)
    registry_token: str = ""  # Session-only, not saved


def version_to_tuple(v: str) -> tuple[int, ...]:
    """Converts a version string to a tuple of integers for comparison."""
    try:
        return tuple(map(int, v.split('-')[0].split('.')))
    except (ValueError, AttributeError):
        return (0,)


def run(cmd: list[str] | str, capture: bool = True, stdin_input: Optional[str] = None) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = cmd.split()
    return subprocess.run(cmd, check=True, text=True, capture_output=capture, input=stdin_input)


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
        "us-1": ["ts01-b.cloudsink.net", "falcon.crowdstrike.com", "api.crowdstrike.com"],
        "us-2": ["ts01-gyr-maverick.cloudsink.net", "falcon.us-2.crowdstrike.com", "api.us-2.crowdstrike.com"],
        "eu-1": ["ts01-lanner-lion.cloudsink.net", "falcon.eu-1.crowdstrike.com", "api.eu-1.crowdstrike.com"],
        "us-gov-1": ["ts01-laggar-gcw.cloudsink.net", "falcon.laggar.gcw.crowdstrike.com", "api.laggar.gcw.crowdstrike.com"],
        "us-gov-2": ["ts01-us-gov-2.cloudsink.crowdstrike.mil", "falcon.us-gov-2.crowdstrike.mil", "api.us-gov-2.crowdstrike.mil"],
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
        except (socket.gaierror, socket.timeout, Exception) as e:
            return hostname, False, str(e)
    
    hosts = network_reqs[region]
    failed_hosts = []
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console, transient=True) as progress:
        task = progress.add_task(f"Checking network connectivity for {region.upper()}", total=len(hosts))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_host, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                hostname, success, message = future.result()
                if not success:
                    failed_hosts.append((hostname, message))
                progress.advance(task)
    
    if failed_hosts:
        console.print(f"[red]❌ Network connectivity issues detected for {region.upper()}:[/red]")
        for hostname, error in failed_hosts:
            console.print(f"  [red]• {hostname}: {error}[/red]")
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
    except Exception as e:
        console.print(f"[red]❌ Failed to get OAuth token: {e}[/red]")
        sys.exit(1)


def get_registry_credentials(oauth_token: str, api_base: str, cid: str) -> tuple[str, str]:
    try:
        cid_first_part = cid.split('-')[0].lower()
        username = f"fc-{cid_first_part}"
        response = requests.get(f"https://{api_base}/container-security/entities/image-registry-credentials/v1", headers={"Authorization": f"Bearer {oauth_token}"})
        response.raise_for_status()
        data = response.json()
        password = data["resources"][0]["token"]
        return username, password
    except Exception as e:
        console.print(f"[red]❌ Failed to get registry credentials: {e}[/red]")
        sys.exit(1)


def get_latest_image_tag(component: FalconComponent, cs_registry: str, cloud_tag: str, cs_username: str, cs_password: str) -> Optional[str]:
    image_path = component.get_image_path(cloud_tag)
    tags_url = f"https://{cs_registry}/v2/{image_path}/tags/list"
    console.print(f"🔍 Querying for latest {component.value} version...")
    try:
        tag_response = requests.get(tags_url, auth=(cs_username, cs_password), timeout=30)
        if tag_response.status_code != 200: return None
        tags_data = tag_response.json()
        tags = tags_data.get("tags", [])
        versioned_tags = sorted([t for t in tags if t != "latest" and t[0].isdigit()], key=version_to_tuple, reverse=True)
        return versioned_tags[0] if versioned_tags else None
    except Exception:
        return None


def check_helm_release_exists(release_name: str, namespace: str) -> bool:
    try:
        subprocess.run(["helm", "status", release_name, "-n", namespace], check=True, stdout=DEVNULL, stderr=DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def get_installed_image_tag(release_name: str, namespace: str, component: FalconComponent) -> Optional[str]:
    try:
        cp = run(["helm", "get", "values", release_name, "-n", namespace, "-o", "json"], capture=True)
        values = json.loads(cp.stdout)
        if component == FalconComponent.SENSOR:
            return values.get("node", {}).get("image", {}).get("tag")
        else: # KAC and IAR use the same path for the image tag
            return values.get("image", {}).get("tag")
    except Exception:
        return None


def download_and_push_image(component: FalconComponent, cfg: DeploymentConfig, component_cfg: ComponentConfig) -> tuple[str, str]:
    api_base, cloud_tag, cs_registry = get_cloud_api_config(cfg.cloud_region)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console, transient=True) as progress:
        task = progress.add_task(f"Downloading & Pushing {component.value}", total=3)
        cs_image_path = component.get_image_path(cloud_tag)
        cs_image = f"{cs_registry}/{cs_image_path}"
        full_cs_image = f"{cs_image}:{component_cfg.image_tag}"
        
        progress.update(task, description=f"Pulling {full_cs_image}...")
        try:
            run(["docker", "pull", full_cs_image], capture=True)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[red]❌ Failed to download image {full_cs_image}[/red]")
            if e.stderr: console.print(f"[red]STDERR: {e.stderr}[/red]")
            sys.exit(1)
        progress.advance(task)
        
        local_image = f"{cfg.local_registry}/{component.image_name}"
        local_full_image = f"{local_image}:{component_cfg.image_tag}"
        
        progress.update(task, description=f"Tagging as {local_full_image}...")
        run(["docker", "tag", full_cs_image, local_full_image], capture=True)
        progress.advance(task)

        progress.update(task, description=f"Pushing to {cfg.local_registry}...")
        try:
            run(["docker", "push", local_full_image], capture=True)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[red]❌ Failed to push image to local registry {cfg.local_registry}[/red]")
            if e.stderr: console.print(f"[red]STDERR: {e.stderr}[/red]")
            sys.exit(1)
        progress.advance(task)
    
    console.print(f"[green]✅ Image successfully downloaded and pushed to {local_full_image}[/green]")
    return local_image, component_cfg.image_tag


def generate_pull_token(local_registry: str) -> str:
    docker_config_path = Path.home() / ".docker" / "config.json"
    if docker_config_path.exists():
        with open(docker_config_path, 'r') as f:
            docker_config = json.load(f)
        if "auths" in docker_config and local_registry in docker_config["auths"]:
            return base64.b64encode(json.dumps(docker_config).encode()).decode()
    console.print(f"[yellow]⚠️ No authentication found for local registry {local_registry}. Manual pull secrets may be needed.[/yellow]")
    return ""


def _config_serializer(obj):
    if isinstance(obj, Enum): return obj.name
    if isinstance(obj, Path): return str(obj)
    if dataclasses.is_dataclass(obj): return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def save_config_to_file(config: DeploymentConfig, save_sensitive: bool = True) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config_dict = asdict(config)
        
        if not save_sensitive:
            config_dict["client_secret"] = ""
        config_dict.pop("registry_token", None)
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        console.print(f"[green]✅ Configuration saved to {CONFIG_FILE}[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️ Failed to save configuration: {e}[/yellow]")


def load_config_from_file() -> Optional[DeploymentConfig]:
    if not CONFIG_FILE.exists(): return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
        
        component_configs = {}
        if "components" in data:
            for comp_name, comp_data in data["components"].items():
                component_configs[comp_name] = ComponentConfig(**comp_data)
        
        return DeploymentConfig(
            cid=data.get("cid", ""),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret", ""),
            cloud_region=data.get("cloud_region", "eu-1"),
            local_registry=data.get("local_registry", ""),
            components=component_configs,
        )
    except Exception as e:
        console.print(f"[yellow]⚠️ Failed to load configuration: {e}[/yellow]")
        return None


def wizard(selected_components: List[FalconComponent], existing_cfg: Optional[DeploymentConfig] = None) -> DeploymentConfig:
    console.print(Panel("Deployment Configuration Wizard", style="bold cyan"))
    
    # Use existing values as defaults if available
    defaults = asdict(existing_cfg) if existing_cfg else {}
    
    cid = Prompt.ask("CrowdStrike [bold]CID[/]", default=defaults.get("cid", os.getenv("FALCON_CID", ""))).strip()
    client_id = Prompt.ask("Falcon API [bold]client_id[/]", default=defaults.get("client_id", os.getenv("FALCON_CLIENT_ID", ""))).strip()
    client_secret = Prompt.ask("Falcon API [bold]client_secret[/]", default=defaults.get("client_secret", os.getenv("FALCON_CLIENT_SECRET", "")), password=True).strip()
    cloud_region = Prompt.ask("Falcon cloud region", choices=["us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2"], default=defaults.get("cloud_region", "eu-1"))
    local_registry = Prompt.ask("Local registry [bold]URL[/]", default=defaults.get("local_registry", "localhost:5000")).strip()

    components_config = {}
    for comp in selected_components:
        console.print(Panel(f"Configure: {comp.value}", style="bold blue"))
        comp_defaults = defaults.get("components", {}).get(comp.name, {})
        
        namespace = Prompt.ask("Kubernetes namespace", default=comp_defaults.get("namespace", comp.default_namespace))
        image_tag = Prompt.ask("Image [bold]tag[/] (or leave for latest)", default=comp_defaults.get("image_tag", "latest"))
        
        backend, cluster_name, iar_mode, iar_runtime = None, None, None, None
        if comp == FalconComponent.SENSOR:
            backend = Prompt.ask("Sensor backend", choices=["bpf", "kernel"], default=comp_defaults.get("backend", "bpf"))
        
        if comp in [FalconComponent.KAC, FalconComponent.IAR]:
            cluster_name = Prompt.ask("Kubernetes [bold]cluster name[/]", default=comp_defaults.get("cluster_name", "")).strip()

        if comp == FalconComponent.IAR:
            iar_mode = Prompt.ask("IAR deployment mode", choices=["watcher", "socket"], default=comp_defaults.get("iar_mode", "watcher"))
            if iar_mode == "socket":
                iar_runtime = Prompt.ask("Container runtime", choices=["docker", "podman", "containerd", "crio"], default=comp_defaults.get("iar_runtime", "containerd"))

            
        components_config[comp.name] = ComponentConfig(
            namespace=namespace, image_tag=image_tag, backend=backend, cluster_name=cluster_name,
            iar_mode=iar_mode, iar_runtime=iar_runtime
        )

    return DeploymentConfig(
        cid=cid, client_id=client_id, client_secret=client_secret, cloud_region=cloud_region,
        local_registry=local_registry, components=components_config
    )


def parse_args():
    parser = argparse.ArgumentParser(description="CrowdStrike Falcon Product Helm Deployment Helper")
    parser.add_argument("--component", nargs='+', choices=[c.name.lower() for c in FalconComponent], help="Specify one or more components to manage.")
    parser.add_argument("--no-sensitive", action="store_true", help="Do not save client_secret to configuration.")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall specified components.")
    return parser.parse_args()


def choose_components(action: str) -> List[FalconComponent]:
    """Interactively ask the user to choose one or more components."""
    console.print(Panel(f"Choose Components to {action.capitalize()}", style="bold blue"))
    choices = {str(i + 1): comp for i, comp in enumerate(FalconComponent)}
    for i, comp in choices.items():
        console.print(f"[cyan]{i}[/cyan]: {comp.value}")

    while True:
        try:
            prompt_text = "Select component(s). Enter one or more numbers separated by a comma (e.g., 1, 2)"
            raw_input = Prompt.ask(prompt_text)

            # Process the input to get unique indices
            selected_indices = {idx.strip() for idx in raw_input.split(',') if idx.strip()}

            if not selected_indices:
                raise InvalidResponse("You must select at least one component.")

            # Validate and map indices to components
            selected_components = []
            for index in selected_indices:
                if index not in choices:
                    raise InvalidResponse(f"'{index}' is not a valid choice. Please choose from {list(choices.keys())}.")
                selected_components.append(choices[index])

            # Return a unique list of components, maintaining the original enum order
            unique_selected = sorted(list(set(selected_components)), key=lambda c: list(FalconComponent).index(c))
            return unique_selected

        except InvalidResponse as e:
            console.print(f"[red]Invalid input: {e}. Please try again.[/red]")
        except KeyError:
            console.print(f"[red]An unexpected error occurred during selection. Please try again.[/red]")


def generate_uninstall_plan(components: List[FalconComponent]) -> List[Command]:
    """Generates a list of commands for uninstalling components."""
    commands = []
    cfg = load_config_from_file()

    for comp in components:
        namespace = comp.default_namespace
        if cfg and comp.name in cfg.components:
            namespace = cfg.components[comp.name].namespace

        if not check_helm_release_exists(comp.release_name, namespace):
            console.print(f"[yellow]⚠️ No active '{comp.release_name}' release found in namespace '{namespace}'. Skipping.[/yellow]")
            continue

        commands.append(Command(
            component=comp,
            description=f"Uninstall Helm release '{comp.release_name}'",
            cmd_list=["helm", "uninstall", comp.release_name, "-n", namespace],
            capture_output=False
        ))
        commands.append(Command(
            component=comp,
            description=f"Delete namespace '{namespace}'",
            cmd_list=["kubectl", "delete", "namespace", namespace, "--ignore-not-found"],
            capture_output=False,
            can_fail=True
        ))
    return commands


def main() -> None:
    print_banner()
    args = parse_args()
    action = "uninstall" if args.uninstall else "install/upgrade"
    
    if args.component:
        selected_components = [FalconComponent[c.upper()] for c in args.component]
    else:
        selected_components = choose_components(action)

    if args.uninstall:
        console.print(Panel("Falcon Product Uninstaller", style="bold red"))
        uninstall_commands = generate_uninstall_plan(selected_components)
        if uninstall_commands:
            execute_commands_wizard(uninstall_commands, plan_title="Uninstallation Plan")
        
        if Confirm.ask("\nDo you want to remove the unified configuration file?", default=False):
            CONFIG_FILE.unlink(missing_ok=True)
            console.print("[green]✅ Configuration file removed.[/green]")
        sys.exit(0)
    
    if shutil.which("docker") is None:
        console.print("\n[red bold]❌ Docker is required for image operations.[/red bold]")
        sys.exit(1)

    console.print("\n[yellow]Checking prerequisites and setting up Helm repository...[/yellow]")
    check_binary("helm", "3.0.0")
    check_binary("kubectl", "1.20.0")
    check_cluster()
    setup_helm_repo()

    cfg = load_config_from_file()
    if not cfg or Confirm.ask("\nAn existing configuration was found. Do you want to re-configure?", default=False):
        cfg = wizard(selected_components, existing_cfg=cfg)
    
        save_config_to_file(cfg, save_sensitive=not args.no_sensitive)
    
    console.print("\n[yellow]Authenticating with CrowdStrike and checking network...[/yellow]")
    if not cfg.client_secret:
        cfg.client_secret = Prompt.ask("Please enter Falcon API [bold]client_secret[/]", password=True).strip()
        if not cfg.client_secret:
            console.print("[red]❌ Client secret is required.[/red]")
        sys.exit(1)

    api_base, cloud_tag, cs_registry = get_cloud_api_config(cfg.cloud_region)
    oauth_token = get_oauth_token(cfg.client_id, cfg.client_secret, api_base)
    cs_username, cs_password = get_registry_credentials(oauth_token, api_base, cfg.cid)
    cfg.registry_token = generate_pull_token(cfg.local_registry)

    try:
        run(["docker", "login", cs_registry, "-u", cs_username, "--password-stdin"], capture=True, stdin_input=cs_password)
    except subprocess.CalledProcessError:
        console.print(f"\n[red]❌ Failed to login to CrowdStrike registry {cs_registry}[/red]")
        sys.exit(1)

    if not check_network_connectivity(cfg.cloud_region):
        sys.exit(1)

    all_commands: List[Command] = []

    # --- Process each component ---
    for component in selected_components:
        console.print(Panel(f"Processing: {component.value}", style="bold green"))
        
        comp_cfg = cfg.components.get(component.name)
        if not comp_cfg:
            console.print(f"[yellow]⚠️ No configuration for {component.value} found. Skipping.[/yellow]")
            continue
            
        is_new_install = not check_helm_release_exists(component.release_name, comp_cfg.namespace)
        
        target_tag = comp_cfg.image_tag
        if target_tag == "latest":
            latest_tag = get_latest_image_tag(component, cs_registry, cloud_tag, cs_username, cs_password)
            if latest_tag:
                target_tag = latest_tag
                console.print(f"Resolved 'latest' to version: [bold green]{target_tag}[/bold green]")
            else:
                console.print(f"[red]❌ Could not resolve 'latest' tag for {component.value}. Please specify a version.[/red]")
                continue
        
        if not is_new_install:
            installed_tag = get_installed_image_tag(component.release_name, comp_cfg.namespace, component)
            console.print(f"Installed version: [bold]{installed_tag or 'unknown'}[/bold], Target version: [bold green]{target_tag}[/bold green]")
            if installed_tag and version_to_tuple(target_tag) <= version_to_tuple(installed_tag):
                console.print("[green]✅ Already running the latest target version. Nothing to do.[/green]")
                continue
            if not Confirm.ask(f"Upgrade from [yellow]{installed_tag}[/yellow] to [green]{target_tag}[/green]?", default=True):
                continue
        
        comp_cfg.image_tag = target_tag
        local_image_repo, actual_tag = download_and_push_image(component, cfg, comp_cfg)
        comp_cfg.image_repo = local_image_repo
        comp_cfg.image_tag = actual_tag
        
        values_yaml = yaml.dump(component.to_values_dict(comp_cfg, cfg, args.no_sensitive), default_flow_style=False)
        out_path = CONFIG_DIR / f"{component.release_name}-values.yml"
        out_path.write_text(values_yaml)
        console.print(f"✅ Helm values file written to [green]{out_path}[/green]")

        # --- Generate and store commands for later ---
        if is_new_install and component in [FalconComponent.SENSOR, FalconComponent.IAR]:
            all_commands.append(Command(component, "Create namespace", ["kubectl", "create", "namespace", comp_cfg.namespace], capture_output=False, can_fail=True))
            all_commands.append(Command(component, "Label namespace (enforce)", ["kubectl", "label", "ns", "--overwrite", comp_cfg.namespace, "pod-security.kubernetes.io/enforce=privileged"], capture_output=False))
            all_commands.append(Command(component, "Label namespace (audit)", ["kubectl", "label", "ns", "--overwrite", comp_cfg.namespace, "pod-security.kubernetes.io/audit=privileged"], capture_output=False))
            all_commands.append(Command(component, "Label namespace (warn)", ["kubectl", "label", "ns", "--overwrite", comp_cfg.namespace, "pod-security.kubernetes.io/warn=privileged"], capture_output=False))

        helm_cmd_list = ["helm", "upgrade", "--install", component.release_name, component.chart_name, "-n", comp_cfg.namespace, "--create-namespace", "-f", str(out_path)]
        all_commands.append(Command(component, f"Deploy {component.value} with Helm", helm_cmd_list, capture_output=False))

        # Verification commands
        workload_type = None
        if component == FalconComponent.SENSOR:
            workload_type = "daemonset"
        elif component == FalconComponent.KAC:
            workload_type = "deployment"
        elif component == FalconComponent.IAR:
            workload_type = "daemonset" if comp_cfg.iar_mode == 'socket' else 'deployment'
        
        if workload_type:
            all_commands.append(Command(
                component,
                f"Wait for {workload_type} to be ready",
                ["kubectl", "rollout", "status", f"{workload_type}/{component.release_name}", "-n", comp_cfg.namespace, "--timeout=120s"],
                is_verification=True,
                capture_output=False
            ))

        all_commands.append(Command(component, "Check container logs", ["kubectl", "logs", f"-n={comp_cfg.namespace}", "-l", f"app.kubernetes.io/name={component.release_name}", "--tail=50"], is_verification=True))

    # --- Save config and offer to execute commands ---
    save_config_to_file(cfg, save_sensitive=not args.no_sensitive)
    execute_commands_wizard(all_commands)

    console.print("\n[bold]✨ All selected components processed.[/bold]")


def execute_commands_wizard(commands: List[Command], plan_title: str = "Deployment Plan"):
    """Displays a plan and interactively executes a list of commands."""
    if not commands:
        console.print("\n[green]✅ All components are up-to-date. No actions needed.[/green]")
        return

    # Group commands by component for display and execution
    grouped_commands = {}
    for cmd in commands:
        if cmd.component not in grouped_commands:
            grouped_commands[cmd.component] = []
        grouped_commands[cmd.component].append(cmd)

    console.print(Panel(plan_title, style="bold green", expand=False))
    final_command_str_list = []
    for component, cmds in grouped_commands.items():
        console.print(f"\n[bold blue]Component: {component.value}[/bold blue]")
        for cmd in cmds:
            action_type = "Verification" if cmd.is_verification else "Deployment"
            cmd_str = ' '.join(cmd.cmd_list)
            console.print(f"  - {action_type}: {cmd.description} -> [dim]`{cmd_str}`[/dim]")
            if not cmd.is_verification:
                final_command_str_list.append(cmd_str)

    if not Confirm.ask("\nDo you want to execute this deployment plan now?", default=False):
        console.print("\nExecution cancelled. Below are the commands to run manually.")
        final_command_str = "\n".join(final_command_str_list)
        console.print(f"\n[yellow]--- Manual Commands ---[/yellow]")
        console.print(final_command_str)
        console.print(f"[yellow]-----------------------[/yellow]\n")
        # Copy to clipboard
        if shutil.which("pbcopy"):
            subprocess.run("pbcopy", input=final_command_str, text=True)
            console.print("\n[grey]Deployment commands copied to clipboard.[/grey]")
        elif shutil.which("xclip"):
            subprocess.run(["xclip", "-selection", "clipboard"], input=final_command_str, text=True)
            console.print("\n[grey]Deployment commands copied to clipboard.[/grey]")
        return

    for component, cmds in grouped_commands.items():
        console.print(f"\n--- Executing plan for [bold]{component.value}[/bold] ---")

        deployment_steps = [c for c in cmds if not c.is_verification]
        verification_steps = [c for c in cmds if c.is_verification]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console, transient=False) as progress:
            task = progress.add_task(f"Deploying {component.value}", total=len(deployment_steps))
            for cmd in deployment_steps:
                progress.update(task, description=f"Running: {cmd.description}")
                try:
                    # Execute and show live output
                    process = subprocess.Popen(cmd.cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in iter(process.stdout.readline, ''):
                        progress.console.print(f"[dim]  {line.strip()}[/dim]")
                    process.wait()
                    if process.returncode != 0:
                        if not cmd.can_fail:
                            raise subprocess.CalledProcessError(process.returncode, cmd.cmd_list)
                        else:
                            progress.console.print(f"[yellow]  ⚠️  Command failed but was marked as non-critical. Continuing.[/yellow]")
                except subprocess.CalledProcessError as e:
                    progress.stop()
                    console.print(f"\n[bold red]❌ Command failed with exit code {e.returncode}: {' '.join(cmd.cmd_list)}[/bold red]")
                    console.print("[bold red]Aborting deployment.[/bold red]")
                    return
                except FileNotFoundError:
                    progress.stop()
                    console.print(f"\n[bold red]❌ Command not found: {cmd.cmd_list[0]}. Is it installed and in your PATH?[/bold red]")
                    return
                progress.advance(task)
        
        if verification_steps:
            console.print(f"\n[green]✅ Plan for {component.value} executed successfully. Verifying...[/green]")
        else:
            console.print(f"\n[green]✅ Plan for {component.value} executed successfully.[/green]")

        all_verifications_passed = True
        for cmd in verification_steps:
            console.print(f"\n--- Verifying: {cmd.description} ---")
            try:
                if cmd.capture_output:
                    result = subprocess.run(cmd.cmd_list, capture_output=True, text=True, check=True, timeout=120)
                    console.print(result.stdout.strip() or "[dim](No output)[/dim]")
                    if result.stderr.strip():
                        console.print(f"[dim]STDERR: {result.stderr.strip()}[/dim]")
                else:
                    process = subprocess.Popen(cmd.cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in iter(process.stdout.readline, ''):
                        console.print(f"[dim]  {line.strip()}[/dim]")
                    process.wait()
                    if process.returncode != 0:
                        raise subprocess.CalledProcessError(process.returncode, cmd.cmd_list)

            except subprocess.CalledProcessError as e:
                all_verifications_passed = False
                console.print(f"\n[bold red]❌ Verification command failed: {' '.join(cmd.cmd_list)}[/bold red]")
                if hasattr(e, 'stdout') and e.stdout: console.print(f"[bold]STDOUT:[/bold]\n{e.stdout.strip()}")
                if hasattr(e, 'stderr') and e.stderr: console.print(f"[bold]STDERR:[/bold]\n{e.stderr.strip()}")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                all_verifications_passed = False
                if isinstance(e, FileNotFoundError):
                    console.print(f"\n[bold red]❌ Command not found: {cmd.cmd_list[0]}. Is it installed and in your PATH?[/bold red]")
                else:
                    console.print(f"\n[bold red]❌ Verification timed out: {' '.join(cmd.cmd_list)}[/bold red]")

        if not all_verifications_passed:
            console.print(f"\n[yellow]⚠️ Some verification steps for {component.value} failed. Please check the logs above manually.[/yellow]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red]\n{e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
