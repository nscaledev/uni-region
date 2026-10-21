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

# Real cloud-init for the cloud-init tests. Base image and packages are pinned
# exactly. Packages come from a dated Ubuntu archive snapshot, so the pins stay
# installable after the live archive moves on; bumping them means moving the
# snapshot. The snapshot service has no arm64 archive, so the image is amd64
# only. The base image has no CA bundle, so TLS peer checks are off for the
# snapshot host; apt still verifies the signed Release files. See the server
# package README's "Cloud-init tests".
FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ARG SNAPSHOT=20261015T120000Z

RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}" \
      'Suites: noble noble-updates noble-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/ubuntu.sources && \
    echo 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";' \
      > /etc/apt/apt.conf.d/99snapshot && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      cloud-init=26.1-0ubuntu1~24.04.1 \
      openssh-server=1:9.6p1-3ubuntu13.20 \
      lsb-release=12.0-2 && \
    rm -rf /var/lib/apt/lists/*

COPY 99-test.cfg /etc/cloud/cloud.cfg.d/99-test.cfg
COPY shim /usr/local/sbin/systemctl
COPY shim /usr/local/sbin/service
COPY boot /usr/local/bin/ci-boot
COPY collect.py /usr/local/bin/ci-collect
COPY harness.py /usr/local/bin/ci-harness
