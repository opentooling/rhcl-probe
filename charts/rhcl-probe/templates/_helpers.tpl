{{- define "rhcl-probe.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified name, short enough to take the longest suffix (-pricing-faulty) and stay a
valid Service name.
*/}}
{{- define "rhcl-probe.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "rhcl-probe.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "rhcl-probe.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rhcl-probe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "rhcl-probe.labels" -}}
helm.sh/chart: {{ include "rhcl-probe.chart" . }}
{{ include "rhcl-probe.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector for one component's pods. Pass a dict: ctx, component. */}}
{{- define "rhcl-probe.componentSelector" -}}
{{ include "rhcl-probe.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/* Selector for every pod of a role (catalog = v1 and v2). Pass a dict: ctx, role. */}}
{{- define "rhcl-probe.roleSelector" -}}
{{ include "rhcl-probe.selectorLabels" .ctx }}
rhcl-probe/role: {{ .role }}
{{- end }}

{{- define "rhcl-probe.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* A ServiceAccount name for a role. Pass a dict: ctx, role. */}}
{{- define "rhcl-probe.sa" -}}
{{- printf "%s-%s" (include "rhcl-probe.fullname" .ctx) .role }}
{{- end }}

{{- define "rhcl-probe.gatewaySA" -}}
{{- default (printf "%s-istio" .Values.gateway.name) .Values.gateway.serviceAccount }}
{{- end }}

{{/* An AuthorizationPolicy principal. Pass a dict: ctx, namespace, sa. */}}
{{- define "rhcl-probe.principal" -}}
{{- printf "%s/ns/%s/sa/%s" .ctx.Values.trustDomain .namespace .sa }}
{{- end }}

{{/* Base URL of one of the probe's Services. Pass a dict: ctx, svc. */}}
{{- define "rhcl-probe.url" -}}
{{- printf "http://%s-%s:8080" (include "rhcl-probe.fullname" .ctx) .svc }}
{{- end }}

{{/* The CA bundle ConfigMap the console mounts, or empty for none. */}}
{{- define "rhcl-probe.caConfigMap" -}}
{{- if .Values.trustedCA.configMap }}
{{- .Values.trustedCA.configMap }}
{{- else if .Values.trustedCA.openshiftInjected }}
{{- printf "%s-ca-bundle" (include "rhcl-probe.fullname" .) }}
{{- end }}
{{- end }}

{{/* Labels for sidecar injection. Pass a dict: ctx, mesh (bool). */}}
{{- define "rhcl-probe.meshLabels" -}}
{{- if not .mesh }}
sidecar.istio.io/inject: "false"
rhcl-probe/mesh: "false"
{{- else if .ctx.Values.mesh.revision }}
istio.io/rev: {{ .ctx.Values.mesh.revision }}
rhcl-probe/mesh: "true"
{{- else }}
sidecar.istio.io/inject: "true"
rhcl-probe/mesh: "true"
{{- end }}
{{- end }}

{{/* restricted-v2 friendly: no fixed UID, so OpenShift can assign one. */}}
{{- define "rhcl-probe.podSecurityContext" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "rhcl-probe.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}

{{- define "rhcl-probe.validate" -}}
{{- if not .Values.gateway.hostname }}
{{- fail "gateway.hostname is required: a hostname under the gateway listener's hostname" }}
{{- end }}
{{- if and .Values.auth.oidc.enabled (or (not .Values.auth.oidc.issuerUrl) (not .Values.auth.oidc.clientId) (not .Values.auth.oidc.clientSecret.existingSecret)) }}
{{- fail "auth.oidc.enabled needs auth.oidc.issuerUrl, auth.oidc.clientId and auth.oidc.clientSecret.existingSecret" }}
{{- end }}
{{- $pct := list (int .Values.routes.splitV2Percent) (int .Values.mesh.splitV2Percent) }}
{{- range $pct }}
{{- if or (lt . 0) (gt . 100) }}
{{- fail "routes.splitV2Percent and mesh.splitV2Percent must be between 0 and 100" }}
{{- end }}
{{- end }}
{{- end }}
