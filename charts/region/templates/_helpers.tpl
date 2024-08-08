{{/*
Create the container images
*/}}
{{- define "unikorn.regionImage" -}}
{{- .Values.image | default (printf "%s/unikorn-region-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.identityControllerImage" -}}
{{- .Values.identityController.image | default (printf "%s/unikorn-identity-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "unikorn.imagePullSecrets" -}}
{{- if .Values.imagePullSecret -}}
- name: {{ .Values.imagePullSecret }}
{{ end }}
{{- if .Values.dockerConfig -}}
- name: docker-config
{{- end }}
{{- end }}
