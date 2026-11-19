{{/*
Expand the name of the chart.
*/}}
{{- define "kxn-logs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kxn-logs.fullname" -}}
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
Chart label.
*/}}
{{- define "kxn-logs.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kxn-logs.labels" -}}
helm.sh/chart: {{ include "kxn-logs.chart" . }}
{{ include "kxn-logs.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "kxn-logs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kxn-logs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "kxn-logs.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kxn-logs.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference (repo:tag).
*/}}
{{- define "kxn-logs.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Loki URL written to the `[[save]]` block. Credentials are not inlined: kxn
reads LOKI_USER / LOKI_PASSWORD from the environment.
*/}}
{{- define "kxn-logs.lokiUrl" -}}
{{- if or (hasPrefix "loki://" .Values.loki.url) (hasPrefix "loki+https://" .Values.loki.url) (hasPrefix "http://" .Values.loki.url) (hasPrefix "https://" .Values.loki.url) }}
{{- .Values.loki.url }}
{{- else }}
{{- printf "loki://%s" .Values.loki.url }}
{{- end }}
{{- end }}
