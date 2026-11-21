{{- /*
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
*/ -}}

{{/* Chart name. */}}
{{- define "bomcensus-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Full name of the release's objects. */}}
{{- define "bomcensus-scanner.fullname" -}}
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

{{- define "bomcensus-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "bomcensus-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bomcensus-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "bomcensus-scanner.labels" -}}
helm.sh/chart: {{ include "bomcensus-scanner.chart" . }}
{{ include "bomcensus-scanner.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: scanner
app.kubernetes.io/part-of: bomcensus
{{- end }}

{{- define "bomcensus-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bomcensus-scanner.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "bomcensus-scanner.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Server URL. In a bundled install it defaults to the agent Service of the
bomcensus-manager release, whose objects are named after the release.
*/}}
{{- define "bomcensus-scanner.serverURL" -}}
{{- if .Values.server.url }}
{{- .Values.server.url }}
{{- else if .Values.bundled }}
{{- printf "https://%s-agent.%s.svc:8443" .Release.Name .Release.Namespace }}
{{- else }}
{{- fail "server.url is required: the agent listener of the bomcensus server, https://HOST:8443" }}
{{- end }}
{{- end }}

{{/*
Secret name and key of the enrollment string. In a bundled install without
a token or Secret of its own, the Secret written by the manager's
bootstrap Job is used.
*/}}
{{- define "bomcensus-scanner.tokenSecretName" -}}
{{- $e := .Values.enrollment }}
{{- if and $e.token $e.existingSecret.name }}
{{- fail "set either enrollment.token or enrollment.existingSecret.name, not both" }}
{{- else if $e.token }}
{{- printf "%s-enrollment" (include "bomcensus-scanner.fullname" .) }}
{{- else if $e.existingSecret.name }}
{{- $e.existingSecret.name }}
{{- else if .Values.bundled }}
{{- printf "%s-scanner-enrollment" .Release.Name }}
{{- else }}
{{- fail "an enrollment string is required: set enrollment.existingSecret.name (recommended) or enrollment.token" }}
{{- end }}
{{- end }}

{{- define "bomcensus-scanner.tokenSecretKey" -}}
{{- if .Values.enrollment.token }}token{{ else }}{{ default "token" .Values.enrollment.existingSecret.key }}{{ end }}
{{- end }}

{{/*
The volume holding the state directory is mounted here. The path does not
exist in the image: a runtime may copy image content found under a mount
point into a fresh volume, with an owner the scanner cannot change.
*/}}
{{- define "bomcensus-scanner.dataDir" -}}/var/lib/bomcensus-scanner{{- end }}

{{/*
State directory: a subdirectory of the volume, so that the scanner creates
it itself with mode 0700 whatever the volume root looks like.
*/}}
{{- define "bomcensus-scanner.stateDir" -}}/var/lib/bomcensus-scanner/state{{- end }}
