#!/usr/bin/python3 -I
# Copyright 2026 Nscale.
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

# Reports what a boot left behind, as JSON on stdout.

import hashlib
import json
import os
import re
import stat
import subprocess

ROOTS = ["/etc", "/opt", "/root", "/home", "/usr/local", "/var/lib", "/srv", "/tmp"]

# Differs between any two boots whatever the user-data; see the README.
NOISE = [
    r"^/etc/(hostname|hosts|resolv\.conf|shadow-?|gshadow-?|sudoers)$",
    r"^/etc/sudoers\.d/90-cloud-init-users$",
    r"^/etc/ssh/ssh_host_",
    r"^/var/lib/(cloud|apt|dpkg|systemd|ucf)/",
    r"^/tmp/ci/",
]


def files():
    found = {}
    for root in ROOTS:
        for directory, _, names in os.walk(root):
            for name in names:
                path = os.path.join(directory, name)
                if any(re.search(n, path) for n in NOISE):
                    continue
                info = os.lstat(path)
                entry = {"mode": oct(stat.S_IMODE(info.st_mode)), "uid": info.st_uid, "gid": info.st_gid}
                if stat.S_ISREG(info.st_mode):
                    with open(path, "rb") as f:
                        entry["sha256"] = hashlib.sha256(f.read()).hexdigest()
                found[path] = entry
    return found


def read(path):
    try:
        with open(path, errors="surrogateescape") as f:
            return f.read()
    except FileNotFoundError:
        return None


def sshd():
    out = subprocess.run(["/usr/sbin/sshd", "-T"], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith("trustedusercakeys "):
            return line.split(" ", 1)[1]
    return "sshd -T failed: " + out.stderr.strip()


def status():
    out = subprocess.run(["cloud-init", "status", "--format", "json"], capture_output=True, text=True)
    data = json.loads(out.stdout)
    return {"errors": data.get("errors", []), "recoverable_errors": data.get("recoverable_errors", {})}


def warnings():
    log = read("/var/log/cloud-init.log") or ""
    return [line for line in log.splitlines() if re.search(r" - [^ ]+\[(WARNING|ERROR|CRITICAL)\]: ", line)]


json.dump({
    "files": files(),
    "markers": (read("/opt/marker/order") or "").split(),
    "boots": len((read("/opt/marker/boots") or "").split()),
    "shim": (read("/tmp/ci/shim.log") or "").splitlines(),
    "sshd": sshd(),
    "status": status(),
    "warnings": warnings(),
    "failedStages": (read("/tmp/ci/failed") or "").splitlines(),
}, os.sys.stdout)
