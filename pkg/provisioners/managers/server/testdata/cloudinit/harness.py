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

# Runs user-data through cloud-init's own Python, so tests check behaviour
# against cloud-init itself.
#
# prefixes: stdout is cloud-init's first-line prefix to content type table.
# detect:   stdin is a JSON list of payloads (base64), stdout the type
#           cloud-init detects for each (null for none), decoded as
#           fully_decoded_payload does for a user-data part.
# parts:    stdin is raw user-data, stdout every part cloud-init would hand
#           to a handler (type, filename, Merge-Type, payload base64) and
#           every WARNING+ it logged.

import base64
import json
import logging
import shutil
import sys
import tempfile

from cloudinit import handlers, helpers, user_data


class Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def prefixes():
    json.dump(handlers.INCLUSION_TYPES_MAP, sys.stdout)


def detect():
    payloads = [base64.b64decode(p) for p in json.load(sys.stdin)]
    json.dump([handlers.type_from_starts_with(p.decode("utf-8", "surrogateescape")) for p in payloads], sys.stdout)


def parts():
    collect = Collect()
    logging.getLogger().addHandler(collect)
    logging.getLogger().setLevel(logging.DEBUG)

    tmp = tempfile.mkdtemp()
    try:
        paths = helpers.Paths({"cloud_dir": tmp, "run_dir": tmp})
        message = user_data.UserDataProcessor(paths).process(sys.stdin.buffer.read())
    finally:
        shutil.rmtree(tmp)

    known = set(handlers.INCLUSION_TYPES_MAP.values())
    found = []

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        found.append({
            "type": ctype,
            "handled": ctype in known,
            "filename": part.get_filename(),
            "mergeType": part.get("Merge-Type") or part.get("X-Merge-Type"),
            "payload": base64.b64encode(part.get_payload(decode=True) or b"").decode(),
        })

    json.dump({"parts": found, "warnings": collect.records}, sys.stdout)


{"prefixes": prefixes, "detect": detect, "parts": parts}[sys.argv[1]]()
