#!/usr/bin/env bash

# List of required flags
flags=(
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

# Find the config file: either /proc/config.gz or /boot/config-$(uname -r)
if [[ -r /proc/config.gz ]]; then
  config_file="/proc/config.gz"
  grepcmd="zgrep -q"
elif [[ -r "/boot/config-$(uname -r)" ]]; then
  config_file="/boot/config-$(uname -r)"
  grepcmd="grep -q"
else
  echo "No kernel config file found (/proc/config.gz or /boot/config-$(uname -r))."
  exit 1
fi

# Iterate over flags and check if they are set to =y
echo "Checking flags in $config_file..."
for flag in "${flags[@]}"; do
  if $grepcmd "^${flag}=y" "$config_file"; then
    echo "  ✔ $flag — set"
  else
    echo "  ✘ $flag — NOT set"
  fi
done
