# Shared helpers for the Vault bootstrap scripts (POSIX sh, busybox). Never echo secret values.
log() { printf '[bootstrap] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# http_status <url>: prints the HTTP status of an unauthenticated GET (busybox wget).
http_status() {
  _c=$(wget -S -q -O /dev/null "$1" 2>&1 | sed -n 's/.*HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' | head -n1)
  echo "${_c:-0}"
}

# wait_status <base-url> <wanted...>: poll sys/health until one of the wanted codes appears.
wait_health() {
  base=$1; shift
  i=0
  while [ $i -lt 120 ]; do
    code=$(http_status "$base/v1/sys/health")
    for w in "$@"; do [ "$code" = "$w" ] && { echo "$code"; return 0; }; done
    i=$((i + 1)); sleep 0.5
  done
  die "timeout waiting for $base health in [$*], last=$code"
}

# json_str <key>: first "key":"value" string from stdin JSON (flat values only).
json_str() { sed -n "s/.*\"$1\":[ ]*\"\([^\"]*\)\".*/\1/p" | head -n1; }

# rand_secret: 32 url-safe random chars.
rand_secret() { head -c 48 /dev/urandom | base64 | tr -d '\n/+=' | cut -c1-32; }

mount_exists() { vault secrets list -format=json 2>/dev/null | grep -q "\"$1/\""; }
auth_exists() { vault auth list -format=json 2>/dev/null | grep -q "\"$1/\""; }
