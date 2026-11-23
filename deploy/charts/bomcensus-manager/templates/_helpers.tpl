{{- /*
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
*/ -}}

{{- define "bomcensus-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full name. Objects are named after the release so that the scanner chart,
installed as a dependency, can find the agent Service and the enrollment
Secret from the release name alone. Suffixes add at most 20 characters.
*/}}
{{- define "bomcensus-manager.fullname" -}}
{{- default .Release.Name .Values.fullnameOverride | trunc 42 | trimSuffix "-" }}
{{- end }}

{{- define "bomcensus-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "bomcensus-manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bomcensus-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "bomcensus-manager.labels" -}}
helm.sh/chart: {{ include "bomcensus-manager.chart" . }}
{{ include "bomcensus-manager.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: bomcensus
{{- end }}

{{- define "bomcensus-manager.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bomcensus-manager.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "bomcensus-manager.image" -}}
{{- $default := ternary "latest" .Chart.AppVersion (eq .Chart.AppVersion "0.0.0-dev") }}
{{- printf "%s:%s" .Values.image.repository (default $default .Values.image.tag) }}
{{- end }}

{{- define "bomcensus-manager.webService" -}}{{ include "bomcensus-manager.fullname" . }}-web{{- end }}
{{- define "bomcensus-manager.agentService" -}}{{ include "bomcensus-manager.fullname" . }}-agent{{- end }}

{{/* off with an ingress in front, otherwise web.tls. */}}
{{- define "bomcensus-manager.webTLS" -}}
{{- if .Values.ingress.enabled }}off{{ else }}{{ .Values.web.tls }}{{ end }}
{{- end }}

{{/* The DNS names of a Service, shortest first. */}}
{{- define "bomcensus-manager.serviceNames" -}}
{{- $svc := .svc }}
{{- $ns := .ctx.Release.Namespace }}
{{- list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.%s" $svc $ns .ctx.Values.clusterDomain) | join "," }}
{{- end }}

{{/*
BOMCENSUS_AGENT_SERVER_NAMES. Computed here and not from the pod host name,
so that every replica asks for the same certificate.
*/}}
{{- define "bomcensus-manager.agentServerNames" -}}
{{- $names := splitList "," (include "bomcensus-manager.serviceNames" (dict "svc" (include "bomcensus-manager.agentService" .) "ctx" .)) }}
{{- range .Values.agent.extraServerNames }}
{{- $names = append $names (lower .) }}
{{- end }}
{{- $names | uniq | join "," }}
{{- end }}

{{- define "bomcensus-manager.webServerNames" -}}
{{- $names := splitList "," (include "bomcensus-manager.serviceNames" (dict "svc" (include "bomcensus-manager.webService" .) "ctx" .)) }}
{{- range .Values.web.extraServerNames }}
{{- $names = append $names (lower .) }}
{{- end }}
{{- $names | uniq | join "," }}
{{- end }}

{{/* Master key Secret name and key. */}}
{{- define "bomcensus-manager.masterKeySecret" -}}
{{- default (printf "%s-master-key" (include "bomcensus-manager.fullname" .)) .Values.masterKey.existingSecret.name }}
{{- end }}
{{- define "bomcensus-manager.masterKeyKey" -}}
{{- if .Values.masterKey.existingSecret.name }}{{ default "master-key" .Values.masterKey.existingSecret.key }}{{ else }}master-key{{ end }}
{{- end }}

{{/* Admin Secret name. */}}
{{- define "bomcensus-manager.adminSecret" -}}
{{- default (printf "%s-admin" (include "bomcensus-manager.fullname" .)) .Values.admin.existingSecret.name }}
{{- end }}

{{/*
Database mode: url, existingSecret, cnpgCluster or cnpgDatabase. Fails
unless exactly one is configured.
*/}}
{{- define "bomcensus-manager.databaseMode" -}}
{{- $modes := list }}
{{- if .Values.database.url }}{{ $modes = append $modes "url" }}{{ end }}
{{- if .Values.database.existingSecret.name }}{{ $modes = append $modes "existingSecret" }}{{ end }}
{{- if .Values.cnpg.cluster.create }}{{ $modes = append $modes "cnpgCluster" }}{{ end }}
{{- if .Values.cnpg.database.create }}{{ $modes = append $modes "cnpgDatabase" }}{{ end }}
{{- if ne (len $modes) 1 }}
{{- fail (printf "configure exactly one database: database.url, database.existingSecret.name, cnpg.cluster.create=true or cnpg.database.create=true (got %d)" (len $modes)) }}
{{- end }}
{{- first $modes }}
{{- end }}

{{- define "bomcensus-manager.cnpgClusterName" -}}
{{- default (printf "%s-pg" (include "bomcensus-manager.fullname" .)) .Values.cnpg.cluster.name }}
{{- end }}

{{/* Mode cnpgDatabase: namespace of the existing Cluster. */}}
{{- define "bomcensus-manager.cnpgDatabaseNamespace" -}}
{{- default .Release.Namespace .Values.cnpg.database.namespace }}
{{- end }}

{{- define "bomcensus-manager.cnpgDatabaseName" -}}
{{- default (printf "bomcensus_%s" (.Release.Name | replace "-" "_" | replace "." "_")) .Values.cnpg.database.name | trunc 63 }}
{{- end }}

{{- define "bomcensus-manager.cnpgDatabaseOwner" -}}
{{- default (include "bomcensus-manager.cnpgDatabaseName" .) .Values.cnpg.database.owner }}
{{- end }}

{{/*
Name of the CloudNativePG objects of mode cnpgDatabase. They live in the
Cluster's namespace, which several releases may share.
*/}}
{{- define "bomcensus-manager.cnpgDatabaseObject" -}}
{{- printf "%s-%s" .Release.Namespace (include "bomcensus-manager.fullname" .) | trunc 52 | trimSuffix "-" }}
{{- end }}

{{/* Secret and key the server reads BOMCENSUS_DATABASE_URL from. */}}
{{- define "bomcensus-manager.databaseSecret" -}}
{{- $mode := include "bomcensus-manager.databaseMode" . }}
{{- if eq $mode "existingSecret" }}{{ .Values.database.existingSecret.name }}
{{- else if eq $mode "cnpgCluster" }}{{ include "bomcensus-manager.cnpgClusterName" . }}-app
{{- else }}{{ include "bomcensus-manager.fullname" . }}-database
{{- end }}
{{- end }}
{{- define "bomcensus-manager.databaseKey" -}}
{{- $mode := include "bomcensus-manager.databaseMode" . }}
{{- if eq $mode "existingSecret" }}{{ default "url" .Values.database.existingSecret.key }}
{{- else if eq $mode "cnpgCluster" }}uri
{{- else }}url
{{- end }}
{{- end }}

{{/* Whether the scanner bootstrap Job runs. */}}
{{- define "bomcensus-manager.scannerBootstrap" -}}
{{- $e := (.Values.scanner.enrollment | default dict) }}
{{- $secret := (get $e "existingSecret") | default dict }}
{{- if and .Values.scanner.enabled (not (get $e "token")) (not (get $secret "name")) }}true{{ end }}
{{- end }}

{{- define "bomcensus-manager.scannerSecret" -}}
{{- printf "%s-scanner-enrollment" .Release.Name }}
{{- end }}

{{/* Environment of the server and of the bootstrap Job. */}}
{{- define "bomcensus-manager.commonEnv" -}}
- name: BOMCENSUS_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "bomcensus-manager.databaseSecret" . }}
      key: {{ include "bomcensus-manager.databaseKey" . }}
- name: BOMCENSUS_MASTER_KEY_FILE
  value: /etc/bomcensus/master-key/{{ include "bomcensus-manager.masterKeyKey" . }}
- name: BOMCENSUS_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
- name: BOMCENSUS_LOG_FORMAT
  value: {{ .Values.logFormat | quote }}
{{- end }}

{{- define "bomcensus-manager.masterKeyVolume" -}}
- name: master-key
  secret:
    secretName: {{ include "bomcensus-manager.masterKeySecret" . }}
    defaultMode: 0440
    items:
      - key: {{ include "bomcensus-manager.masterKeyKey" . }}
        path: {{ include "bomcensus-manager.masterKeyKey" . }}
{{- end }}
