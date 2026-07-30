#!/usr/bin/env python3
import json
import sys
import os

def get_ram_usage():
    try:
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
        mem_info = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                mem_info[parts[0].rstrip(':')] = int(parts[1])
        
        total = mem_info.get('MemTotal', 0)
        available = mem_info.get('MemAvailable', 0)
        if total > 0:
            used = total - available
            pct = (used / total) * 100
            used_gb = used / 1024 / 1024
            total_gb = total / 1024 / 1024
            return f"RAM: {used_gb:.1f}/{total_gb:.1f}GB ({pct:.1f}%)"
    except Exception:
        pass
    return "RAM: N/A"

def get_cpu_load():
    try:
        with open('/proc/loadavg', 'r') as f:
            load = f.read().strip().split()
        if len(load) >= 3:
            return f"CPU Load: {load[0]} {load[1]} {load[2]}"
    except Exception:
        pass
    return "CPU Load: N/A"

def main():
    try:
        input_data = sys.stdin.read().strip()
        if not input_data:
            data = {}
        else:
            data = json.loads(input_data)
    except Exception:
        data = {}

    # Extract state, model, token usage
    agent_state = data.get('agent_state', 'idle')
    
    # Model info
    model_obj = data.get('model', {})
    model_name = "N/A"
    if isinstance(model_obj, dict):
        model_name = model_obj.get('display_name') or model_obj.get('id') or "N/A"
    elif isinstance(model_obj, str):
        model_name = model_obj

    # Context window & tokens
    context_window = data.get('context_window', {})
    used_pct = "N/A"
    used_tokens = "N/A"
    if isinstance(context_window, dict):
        used_pct_val = context_window.get('used_percentage')
        if used_pct_val is not None:
            try:
                used_pct = f"{float(used_pct_val):.1f}%"
            except ValueError:
                pass
        
        tokens_val = context_window.get('tokens_used') or context_window.get('used')
        limit_val = context_window.get('limit') or context_window.get('total')
        if tokens_val is not None:
            if limit_val is not None:
                used_tokens = f"{tokens_val}/{limit_val}"
            else:
                used_tokens = f"{tokens_val}"

    # Active tasks / subagents if any
    subagent_count = len(data.get('subagents', [])) if isinstance(data.get('subagents'), list) else 0
    task_count = data.get('task_count', 0)

    # ANSI Colors
    # Blue: \033[34m, Green: \033[32m, Yellow: \033[33m, Cyan: \033[36m, Reset: \033[0m
    # Bold: \033[1m
    # We can use emoji or standard icons
    state_icon = "🟢" if agent_state == "idle" else "🌀" if agent_state == "thinking" else "⚙️"
    
    # Format tokens display
    tokens_display = f"Tokens: {used_pct}"
    if used_tokens != "N/A":
        tokens_display += f" ({used_tokens})"

    # Get system resources
    ram_usage = get_ram_usage()
    cpu_load = get_cpu_load()

    # Format the entire status line
    status_parts = [
        f"{state_icon} State: {agent_state}",
        f"🤖 Model: {model_name}",
        f"📊 {tokens_display}",
        f"💻 {cpu_load}",
        f"💾 {ram_usage}"
    ]
    
    if task_count > 0:
        status_parts.append(f"⏱️ Tasks: {task_count}")
    if subagent_count > 0:
        status_parts.append(f"👥 Subagents: {subagent_count}")

    # Output
    print(" | ".join(status_parts))

if __name__ == "__main__":
    main()
