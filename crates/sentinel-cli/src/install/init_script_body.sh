# managed by `sentinel setup` — sourced by shell rc-file marker block
# Ambient shell wrapping: transparently runs package-install commands under
# Sentinel so network egress is monitored without needing `sentinel run`.

# Resolve sentinel binary path once at shell startup.
_sentinel_bin="$(command -v sentinel 2>/dev/null)"

if [ -n "$_sentinel_bin" ]; then
  export SENTINEL_AMBIENT=1

  _sentinel_wrap() {
    local pm="$1"; shift
    local subcmd="${1:-}"
    case "$subcmd" in
      install|add|remove|uninstall|update|upgrade|ci|create|init|publish|exec|run)
        "$_sentinel_bin" run "$pm" "$@"
        ;;
      *)
        command "$pm" "$@"
        ;;
    esac
  }

  npm()   { _sentinel_wrap npm   "$@"; }
  npx()   { _sentinel_wrap npx   "$@"; }
  yarn()  { _sentinel_wrap yarn  "$@"; }
  pnpm()  { _sentinel_wrap pnpm  "$@"; }
  bun()   { _sentinel_wrap bun   "$@"; }
  pip()   { _sentinel_wrap pip   "$@"; }
  pip3()  { _sentinel_wrap pip3  "$@"; }
  cargo() { _sentinel_wrap cargo "$@"; }
  gem()   { _sentinel_wrap gem   "$@"; }
  go()    { _sentinel_wrap go    "$@"; }
  composer() { _sentinel_wrap composer "$@"; }
fi
