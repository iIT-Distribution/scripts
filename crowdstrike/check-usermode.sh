#!/usr/bin/env bash

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
#

# ================================================
# Script to verify kernel version and required CONFIG options
# for CrowdStrike Falcon sensor user mode on Linux.
# Exits with an error code if any check fails.
# ================================================

# Required minimum kernel version for user mode
MIN_MAJOR=5
MIN_MINOR=8

# Minimum kernel version for CONFIG_DEBUG_INFO_BTF_MODULES requirement
BTF_MODULES_MAJOR=5
BTF_MODULES_MINOR=11

# CONFIG options that must be built-in (=y)
builtin_flags=(
  CONFIG_BPF
  CONFIG_BPF_SYSCALL
  CONFIG_DEBUG_INFO_BTF
  CONFIG_TRACING
  CONFIG_KPROBE_EVENTS
  CONFIG_UPROBE_EVENTS
  CONFIG_BPF_JIT
  CONFIG_SECURITY
  CONFIG_KALLSYMS_ALL
  CONFIG_PROC_FS
  CONFIG_BSD_PROCESS_ACCT
  CONFIG_CGROUPS
  CONFIG_CGROUP_BPF
)

# CONFIG options that may be built-in (=y) or compiled as modules (=m)
module_or_builtin_flags=(
  CONFIG_NET_CLS_BPF
  CONFIG_NET_CLS_ACT
  CONFIG_NET_SCH_INGRESS
)

# CONFIG option required only if kernel version >= 5.11
btf_modules_flag="CONFIG_DEBUG_INFO_BTF_MODULES"

# Track if any check failed
failed=0

# Function to compare two version pairs: returns 0 if (a_major,a_minor) >= (b_major,b_minor)
version_at_least() {
  local a_major=$1
  local a_minor=$2
  local b_major=$3
  local b_minor=$4

  if (( a_major > b_major )); then
    return 0
  elif (( a_major < b_major )); then
    return 1
  else
    (( a_minor >= b_minor )) && return 0 || return 1
  fi
}

# Extract the kernel release (with possible suffix)
kernel_release=$(uname -r)
# Extract only numeric version part for comparison (e.g. "5.10.0")
kernel_version=${kernel_release%%-*}
IFS='.' read -r KVER_MAJOR KVER_MINOR KVER_PATCH <<< "$kernel_version"

echo "Detected kernel version: $kernel_version"

# Check minimum kernel version 5.8
if ! version_at_least "$KVER_MAJOR" "$KVER_MINOR" "$MIN_MAJOR" "$MIN_MINOR"; then
  echo "ERROR: Kernel version must be 5.8 or later for user-mode support."
  exit 1
fi

# Locate the kernel config file: either /proc/config.gz or /boot/config-<uname -r>
if [[ -r /proc/config.gz ]]; then
  config_file="/proc/config.gz"
  grepcmd="zgrep -q"
elif [[ -r "/boot/config-${kernel_release}" ]]; then
  config_file="/boot/config-${kernel_release}"
  grepcmd="grep -q"
else
  echo "ERROR: No kernel config file found (/proc/config.gz or /boot/config-${kernel_release})."
  exit 1
fi

echo "Using config file: $config_file"
echo

# Check builtin-only flags
echo "Checking that the following flags are built-in (=y):"
for flag in "${builtin_flags[@]}"; do
  if $grepcmd "^${flag}=y" "$config_file"; then
    echo "  ✔ $flag"
  else
    echo "  ✘ $flag is NOT set to =y"
    failed=1
  fi
done
echo

# Check flags that may be =y or =m
echo "Checking that the following flags are built-in (=y) or modules (=m):"
for flag in "${module_or_builtin_flags[@]}"; do
  if $grepcmd "^${flag}=[ym]" "$config_file"; then
    if $grepcmd "^${flag}=y" "$config_file"; then
      echo "  ✔ $flag is built-in (=y)"
    else
      echo "  ✔ $flag is compiled as module (=m)"
    fi
  else
    echo "  ✘ $flag is NOT set to =y or =m"
    failed=1
  fi
done
echo

# If kernel >= 5.11, check CONFIG_DEBUG_INFO_BTF_MODULES must be built-in
if version_at_least "$KVER_MAJOR" "$KVER_MINOR" "$BTF_MODULES_MAJOR" "$BTF_MODULES_MINOR"; then
  echo "Kernel >= 5.11 detected: verifying $btf_modules_flag is built-in (=y)"
  if $grepcmd "^${btf_modules_flag}=y" "$config_file"; then
    echo "  ✔ $btf_modules_flag"
  else
    echo "  ✘ $btf_modules_flag is NOT set to =y"
    failed=1
  fi
  echo
fi

if (( failed == 1 )); then
  echo "One or more checks FAILED."
  exit 1
else
  echo "All checks PASSED."
  exit 0
fi
