import subprocess
import psutil
import os
import socket
import re
import getpass
import sys
import pwd
import random

FUZZY_TOLERANCE_PERCENT = 10.0  # Allow ±10% difference

OUTPUT_PATTERN = re.compile(r"(?P<prompt>.+?)>\s*(.*?)\s*\n(?P=prompt)>")

def run_smash_command(command):
    proc = None
    try:
        proc = subprocess.Popen([sys.argv[1]],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        stdout, stderr = proc.communicate(f"{command}\nquit\n")
        prompt_match = re.match(r"(.+?)>", stdout)
        prompt = re.escape(prompt_match.group(1)) + ">"
        stdout = re.sub(rf"^{prompt}\s*$", "", stdout, flags=re.MULTILINE)
        return stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        return None, f"Timeout expired on command: {command}"
    except Exception as e:
        return None, f"Error: {str(e)}"

def get_system_watchproc(pid):
    try:
        p = psutil.Process(int(pid))
        p.cpu_percent(interval=None)
        cpu_total = 0
        for _ in range(5):  # Average over 5 seconds
            cpu_total += p.cpu_percent(interval=0.2)
        cpu = cpu_total / 5
        mem = p.memory_info().rss / (1024 * 1024)
        return f"PID: {pid} | CPU Usage: {cpu:.1f}% | Memory Usage: {mem:.1f} MB"
    except Exception as e:
        return f"Error getting process info: {e}"

def get_system_du(folder):
    try:
        total = 0
        for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
            try:
                st_dir = os.lstat(dirpath)
                total += st_dir.st_blocks * 512
            except FileNotFoundError:
                continue

            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    st = os.lstat(fp)
                    total += st.st_blocks * 512
                except (FileNotFoundError, PermissionError):
                    continue
        total_kb = total // 1024
        return f"Total disk usage: {total_kb} KB"
    except Exception as e:
        return f"Error getting disk usage: {e}"

def get_system_whoami():
    try:
        username = getpass.getuser()
        home = pwd.getpwuid(os.getuid()).pw_dir
        return f"{username} {home}"
    except Exception as e:
        return f"Error getting user info: {e}"

def get_system_netinfo(interface):
    try:
        addrs = psutil.net_if_addrs()
        if interface not in addrs:
            return f"Interface {interface} not found"

        ip = 'N/A'
        mask = 'N/A'
        for addr in addrs[interface]:
            if addr.family == socket.AF_INET:
                ip = addr.address
                mask = addr.netmask

        try:
            route_output = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            default_gw = 'unknown'
            for line in route_output.splitlines():
                if line.startswith('default') and 'via' in line:
                    parts = line.split()
                    default_gw = parts[parts.index('via') + 1]
                    break
        except Exception as e:
            default_gw = f"error: {e}"

        dns_servers = []
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.strip().split()[1])
        except Exception as e:
            dns_servers.append(f"error: {e}")

        dns_str = ', '.join(dns_servers)
        return (f"IP Address: {ip}\nSubnet Mask: {mask}\n"
                f"Default Gateway: {default_gw}\nDNS Servers: {dns_str}")
    except Exception as e:
        return f"Error getting net info: {e}"

def fuzzy_compare_numbers(s1, s2, tolerance_percent):
    try:
        n1 = float(s1)
        n2 = float(s2)
        if n1 == 0 and n2 == 0:
            return True
        diff = abs(n1 - n2) / max(abs(n1), abs(n2)) * 100
        return diff <= tolerance_percent
    except:
        return False

def compare_outputs(smash_out, sys_out):
    smash_cpu = re.search(r'CPU Usage: ([\d.]+)%', smash_out)
    sys_cpu = re.search(r'CPU Usage: ([\d.]+)%', sys_out)
    smash_mem = re.search(r'Memory Usage: ([\d.]+) MB', smash_out)
    sys_mem = re.search(r'Memory Usage: ([\d.]+) MB', sys_out)

    if smash_cpu and sys_cpu:
        if not fuzzy_compare_numbers(smash_cpu.group(1), sys_cpu.group(1), FUZZY_TOLERANCE_PERCENT):
            return False

    if smash_mem and sys_mem:
        if not fuzzy_compare_numbers(smash_mem.group(1), sys_mem.group(1), FUZZY_TOLERANCE_PERCENT):
            return False

    smash_clean = smash_out.replace('\n', ' ').strip()
    sys_clean = sys_out.replace('\n', ' ').strip()
    return smash_clean == sys_clean or smash_out in sys_out or sys_out in smash_out

def find_heavy_process():
    heavy_proc = None
    max_cpu = 0

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            cpu = proc.cpu_percent(interval=0.2)
            if cpu > max_cpu:
                max_cpu = cpu
                heavy_proc = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if heavy_proc:
        print(f"Top CPU process: {heavy_proc.info['name']} (PID {heavy_proc.info['pid']}) using {max_cpu:.1f}% CPU")
        return heavy_proc.info['pid']
    else:
        print("No heavy process found.")
        return None

def get_available_interface():
    interfaces = psutil.net_if_addrs()
    for iface in interfaces:
        for addr in interfaces[iface]:
            if addr.family == socket.AF_INET:
                return iface
    return None

def main():
    if len(sys.argv) < 2:
        sys.argv.append('./skeleton_smash')
    current_pid = os.getpid()
    all_pids = psutil.pids()
    available_pids = [pid for pid in all_pids if pid != current_pid]
    test_pid = random.choice(available_pids)
    test_folder = '.'
    test_interface = get_available_interface()

    if not test_interface:
        print("No suitable network interface found for testing.")
        return

    try:
        checks = [
            (f"watchproc {test_pid}", get_system_watchproc(test_pid)),
            (f"du {test_folder}", get_system_du(test_folder)),
            ("whoami", get_system_whoami()),
            (f"netinfo {test_interface}", get_system_netinfo(test_interface))
        ]
    except Exception as e:
        print(f"Error while preparing checks: {e}")
        return

    for cmd, expected in checks:
        try:
            print(f"\n=== Checking: {cmd} ===")
            smash_out, smash_err = run_smash_command(cmd)
            if smash_err:
                print(f"smash error: {smash_err}")
                continue
            print(f"smash says:\n{smash_out}")
            print(f"system says:\n{expected}")

            if compare_outputs(smash_out, expected):
                print("MATCH")
            else:
                print("MISMATCH")
        except Exception as e:
            print(f"Unexpected error during check '{cmd}': {e}")

if __name__ == "__main__":
    main()