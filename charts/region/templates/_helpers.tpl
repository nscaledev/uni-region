{{/*
Create the container images
*/}}
{{- define "unikorn.serverImage" -}}
{{- .Values.server.image | default (printf "%s/unikorn-region-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.regionMonitorImage" -}}
{{- .Values.monitor.image | default (printf "%s/unikorn-region-monitor:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.identityControllerImage" -}}
{{- .Values.identityController.image | default (printf "%s/unikorn-identity-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.networkControllerImage" -}}
{{- .Values.networkController.image | default (printf "%s/unikorn-network-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.securityGroupControllerImage" -}}
{{- .Values.securityGroupController.image | default (printf "%s/unikorn-security-group-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.securityGroupRuleControllerImage" -}}
{{- .Values.securityGroupRuleController.image | default (printf "%s/unikorn-security-group-rule-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.serverControllerImage" -}}
{{- .Values.serverController.image | default (printf "%s/unikorn-server-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}
