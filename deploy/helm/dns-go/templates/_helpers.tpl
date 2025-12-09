{{/*
Expand the name of the chart.
*/}}
{{- define "dns-go.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "dns-go.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "dns-go.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "dns-go.labels" -}}
helm.sh/chart: {{ include "dns-go.chart" . }}
{{ include "dns-go.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "dns-go.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dns-go.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Control plane labels
*/}}
{{- define "dns-go.control.labels" -}}
{{ include "dns-go.labels" . }}
app.kubernetes.io/component: control
{{- end }}

{{/*
Control plane selector labels
*/}}
{{- define "dns-go.control.selectorLabels" -}}
{{ include "dns-go.selectorLabels" . }}
app.kubernetes.io/component: control
{{- end }}

{{/*
Worker labels
*/}}
{{- define "dns-go.worker.labels" -}}
{{ include "dns-go.labels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Worker selector labels
*/}}
{{- define "dns-go.worker.selectorLabels" -}}
{{ include "dns-go.selectorLabels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Create the name of the service account to use for control
*/}}
{{- define "dns-go.control.serviceAccountName" -}}
{{- default (printf "%s-control" (include "dns-go.fullname" .)) .Values.control.serviceAccount.name }}
{{- end }}

{{/*
Create the name of the service account to use for worker
*/}}
{{- define "dns-go.worker.serviceAccountName" -}}
{{- default (printf "%s-worker" (include "dns-go.fullname" .)) .Values.worker.serviceAccount.name }}
{{- end }}

{{/*
Return the proper image name for control
*/}}
{{- define "dns-go.control.image" -}}
{{- $registryName := .Values.global.imageRegistry | default "" -}}
{{- $repositoryName := .Values.control.image.repository -}}
{{- $tag := .Values.control.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper image name for worker
*/}}
{{- define "dns-go.worker.image" -}}
{{- $registryName := .Values.global.imageRegistry | default "" -}}
{{- $repositoryName := .Values.worker.image.repository -}}
{{- $tag := .Values.worker.image.tag | default .Chart.AppVersion -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Control plane service name
*/}}
{{- define "dns-go.control.serviceName" -}}
{{- printf "%s-control" (include "dns-go.fullname" .) }}
{{- end }}

{{/*
Worker service name
*/}}
{{- define "dns-go.worker.serviceName" -}}
{{- printf "%s-worker" (include "dns-go.fullname" .) }}
{{- end }}
