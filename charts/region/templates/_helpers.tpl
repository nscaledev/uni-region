{{/*
Create the container images
*/}}
{{- define "unikorn.defaultTag" -}}
v{{ .Chart.Version }}
{{- end }}

{{- define "unikorn.serverImage" -}}
{{- .Values.server.image | default (printf "%s/unikorn-region-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.projectConsumerImage" -}}
{{- .Values.projectConsumer.image | default (printf "%s/unikorn-region-project-consumer:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.regionMonitorImage" -}}
{{- .Values.monitor.image | default (printf "%s/unikorn-region-monitor:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.identityControllerImage" -}}
{{- .Values.identityController.image | default (printf "%s/unikorn-identity-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.networkControllerImage" -}}
{{- .Values.networkController.image | default (printf "%s/unikorn-network-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.securityGroupControllerImage" -}}
{{- .Values.securityGroupController.image | default (printf "%s/unikorn-security-group-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.loadBalancerControllerImage" -}}
{{- .Values.loadBalancerController.image | default (printf "%s/unikorn-load-balancer-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.securityGroupRuleControllerImage" -}}
{{- .Values.securityGroupRuleController.image | default (printf "%s/unikorn-security-group-rule-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{- define "unikorn.serverControllerImage" -}}
{{- .Values.serverController.image | default (printf "%s/unikorn-server-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}

{{/*
SPIFFE client credential flags.  unikorn.mtls.flags hardcodes a Secret name, which is
why these are separate rather than an option on it.
*/}}
{{- define "unikorn.spiffe.flags" -}}
{{- if .Values.spiffe.enabled }}
- --client-certificate-source=spiffe
- --spiffe-server-id={{ required "spiffe.serverID is required when spiffe.enabled is true: uni-core refuses to start without it, because the alternative authorizes any attested workload to pose as the identity service" .Values.spiffe.serverID }}
{{- end }}
{{- end }}

{{/*
The socket path is required in both of the templates below rather than defaulted,
because empty renders SPIFFE_ENDPOINT_SOCKET as unix://, which go-spiffe rejects, and a
mountPath of '.', which the kubelet refuses -- both of which fail at container creation
rather than at render.
*/}}
{{- define "unikorn.spiffe.env" -}}
{{- if .Values.spiffe.enabled }}
- name: SPIFFE_ENDPOINT_SOCKET
  value: unix://{{ required "spiffe.workloadAPISocketPath is required when spiffe.enabled is true" .Values.spiffe.workloadAPISocketPath }}
{{- end }}
{{- end }}

{{- define "unikorn.spiffe.volumeMounts" -}}
{{- if .Values.spiffe.enabled }}
- name: spiffe-workload-api
  mountPath: {{ dir (required "spiffe.workloadAPISocketPath is required when spiffe.enabled is true" .Values.spiffe.workloadAPISocketPath) }}
  readOnly: true
{{- end }}
{{- end }}

{{- define "unikorn.spiffe.volumes" -}}
{{- if .Values.spiffe.enabled }}
- name: spiffe-workload-api
  csi:
    driver: csi.spiffe.io
    readOnly: true
{{- end }}
{{- end }}
