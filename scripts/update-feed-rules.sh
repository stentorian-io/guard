#!/usr/bin/env zsh
#
# Extract host IOCs from OSV.dev malicious-package advisories (MAL-*) and
# write them to crates/sentinel-core/data/deny/ossf-malicious-packages.yaml.
#
# Downloads the combined all-ecosystem bulk ZIP from the public OSV.dev GCS
# bucket — every advisory across every ecosystem in a single archive.
# No git, no auth, no rate limits.
#
# Requires: curl, jq, unzip, shasum

set -euo pipefail

OSV_ALL_ZIP="https://osv-vulnerabilities.storage.googleapis.com/all.zip"
OUTPUT_FILE="crates/sentinel-core/data/deny/ossf-malicious-packages.yaml"

cleanup() {
  if [[ -n "${tmpdir:-}" ]]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

tmpdir=$(mktemp -d)

echo "Downloading OSV.dev combined bulk archive …"
curl -fsSL --retry 3 --retry-delay 5 -o "${tmpdir}/all.zip" "$OSV_ALL_ZIP"
echo "Extracting MAL-* advisories …"
unzip -q -o "${tmpdir}/all.zip" 'MAL-*.json' -d "${tmpdir}/advisories" 2>/dev/null || true
rm "${tmpdir}/all.zip"

mal_count=$(find "${tmpdir}/advisories" -name 'MAL-*.json' 2>/dev/null | wc -l | tr -d ' ')
echo "Found ${mal_count} MAL-* advisories across all ecosystems."

echo "Filtering MAL-* advisories and extracting host IOCs …"

# Collect only MAL-* (confirmed malware) advisories across all downloaded
# ecosystems. Extract structured IOCs from database_specific.iocs first
# (highest signal), then supplement with EVIDENCE/REPORT reference URL hosts.
#
# We skip reference hosts that are known-benign analysis platforms to avoid
# false-positive denies (e.g. github.com, virustotal.com).

raw_iocs=$(find "${tmpdir}/advisories" -name 'MAL-*.json' -print0 \
  | xargs -0 jq -r '
    def safe_str_array: if type == "array" then .[] | select(type == "string") else empty end;

    # Known-benign hosts that appear in reference URLs but are not C2/exfil
    def benign_ref_host:
      . as $h |
      ($h == "github.com" or $h == "www.github.com" or
       $h == "gitlab.com" or
       $h == "www.virustotal.com" or $h == "virustotal.com" or
       $h == "www.zscaler.com" or $h == "zscaler.com" or
       $h == "blog.phylum.io" or $h == "phylum.io" or
       $h == "research.jfrog.com" or
       $h == "snyk.io" or
       $h == "socket.dev" or
       $h == "www.npmjs.com" or $h == "npmjs.com" or
       $h == "pypi.org" or $h == "www.pypi.org" or
       $h == "rubygems.org" or
       $h == "crates.io" or
       $h == "pkg.go.dev" or
       $h == "hex.pm" or
       $h == "nuget.org" or $h == "www.nuget.org" or
       $h == "packagist.org" or
       $h == "osv.dev" or $h == "api.osv.dev" or
       $h == "nvd.nist.gov" or
       $h == "security.snyk.io" or
       $h == "deps.dev");

    (.id // "unknown") as $id |

    # Primary: structured domains (confirmed)
    ((.database_specific.iocs.domains // []) | safe_str_array
      | select(length > 0 and length <= 256)
      | "exact\t" + . + "\t" + $id + "\tconfirmed"),

    # Primary: structured IPs (confirmed)
    ((.database_specific.iocs.ips // []) | safe_str_array
      | select(length > 0 and length <= 256)
      | "ip\t" + . + "\t" + $id + "\tconfirmed"),

    # Secondary: EVIDENCE/REPORT reference URL hosts (suspect)
    ((.references // [])[]
      | select(.type == "EVIDENCE" or .type == "REPORT")
      | .url // empty
      | capture("^https?://(?<host>[^/:]+)") | .host
      | select(length > 0 and length <= 256)
      | select(benign_ref_host | not)
      | "exact\t" + . + "\t" + $id + "\tsuspect")
  ' 2>/dev/null || true)

# Deduplicate by (match_type, pattern), keeping the first advisory ID seen.
# If a host appears as both confirmed and suspect, promote to confirmed.
declare -A seen
declare -A confidence_map
declare -a entries
while IFS=$'\t' read -r match_type pattern advisory_id confidence; do
  [[ -z "$pattern" ]] && continue
  key="${match_type}:${pattern}"
  if [[ -z "${seen[$key]:-}" ]]; then
    seen[$key]=1
    confidence_map[$key]="${confidence:-suspect}"
    entries+=("${match_type}"$'\t'"${pattern}"$'\t'"${advisory_id}"$'\t'"${confidence:-suspect}")
  elif [[ "$confidence" == "confirmed" && "${confidence_map[$key]:-}" != "confirmed" ]]; then
    # Promote to confirmed: rebuild entry with confirmed confidence
    confidence_map[$key]="confirmed"
    local_entries=()
    for e in "${entries[@]}"; do
      IFS=$'\t' read -r mt pt ai cf <<< "$e"
      if [[ "${mt}:${pt}" == "$key" ]]; then
        local_entries+=("${mt}"$'\t'"${pt}"$'\t'"${ai}"$'\t'"confirmed")
      else
        local_entries+=("$e")
      fi
    done
    entries=("${local_entries[@]}")
  fi
done <<< "$raw_iocs"

# Sort entries by pattern for stable output.
sorted_entries=("${(@f)$(printf '%s\n' "${entries[@]}" | sort -t$'\t' -k2,2)}")
[[ ${#sorted_entries[@]} -eq 1 && -z "${sorted_entries[1]}" ]] && sorted_entries=()

ioc_count=${#sorted_entries[@]}
echo "Found $ioc_count unique host IOCs."

# Write the output file (full replace).
{
  echo "# Auto-generated from OSV.dev malicious-package advisories (MAL-*)."
  echo "# Source: ${OSV_ALL_ZIP}"
  echo "# Managed by scripts/update-feed-rules.sh — do not edit manually."
  for entry in "${sorted_entries[@]}"; do
    IFS=$'\t' read -r match_type pattern advisory_id confidence <<< "$entry"
    [[ -z "$pattern" ]] && continue
    cat <<YAML
- match: $match_type
  pattern: $pattern
  reason: "$advisory_id supply-chain IOC (FEED)"
  confidence: ${confidence:-suspect}
YAML
  done
} > "$OUTPUT_FILE"

confirmed_count=$(printf '%s\n' "${sorted_entries[@]}" | grep -c $'\tconfirmed$' || true)
suspect_count=$(printf '%s\n' "${sorted_entries[@]}" | grep -c $'\tsuspect$' || true)
echo "Wrote $ioc_count feed IOC entries to $OUTPUT_FILE ($confirmed_count confirmed, $suspect_count suspect)."
shasum -a 256 "$OUTPUT_FILE"
