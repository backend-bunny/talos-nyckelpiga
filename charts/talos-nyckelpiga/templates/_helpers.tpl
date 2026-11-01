{{- define "nyckelpiga.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nyckelpiga.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "nyckelpiga.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nyckelpiga.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "nyckelpiga.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "nyckelpiga.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "nyckelpiga.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nyckelpiga.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "nyckelpiga.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "nyckelpiga.allowlistConfigMap" -}}
{{- default (printf "%s-allowlist" (include "nyckelpiga.fullname" .)) .Values.allowlist.existingConfigMap }}
{{- end }}

{{- /* Paths inside the pod. */ -}}
{{- define "nyckelpiga.tokenPath" -}}/var/run/secrets/talos-nyckelpiga/serviceaccount/token{{- end }}

{{- /* Server config (TOML). Strings go through toJson: JSON string escaping is valid TOML. */ -}}
{{- define "nyckelpiga.config" -}}
[server]
listen = {{ printf "[::]:%d" (int .Values.grpc.port) | toJson }}
tls_cert = "/etc/talos-nyckelpiga/tls/tls.crt"
tls_key = "/etc/talos-nyckelpiga/tls/tls.key"
reload_interval_secs = {{ int .Values.reloadIntervalSecs }}

[health]
listen = {{ printf "[::]:%d" (int .Values.health.port) | toJson }}

[openbao]
address = {{ required "openbao.address is required" .Values.openbao.address | toJson }}
{{- if or .Values.openbao.caCert.configMap .Values.openbao.caCert.secret }}
ca_cert = {{ printf "/etc/talos-nyckelpiga/openbao-ca/%s" .Values.openbao.caCert.key | toJson }}
{{- end }}
transit_mount = {{ .Values.openbao.transitMount | toJson }}
key_template = {{ .Values.openbao.keyTemplate | toJson }}
associated_data = {{ .Values.openbao.associatedData }}
request_timeout_secs = {{ int .Values.openbao.requestTimeoutSecs }}

[openbao.auth]
method = "kubernetes"
mount = {{ .Values.openbao.auth.mount | toJson }}
role = {{ required "openbao.auth.role is required" .Values.openbao.auth.role | toJson }}
token_path = {{ include "nyckelpiga.tokenPath" . | toJson }}

[allowlist]
path = "/etc/talos-nyckelpiga/allowlist/allowlist.toml"
{{- end }}
