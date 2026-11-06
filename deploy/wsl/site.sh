# Site settings for the WSL installers. Sourced, not run: `. deploy/wsl/site.sh` from the repository root.
# Reads config/wsl/site.env, then config/wsl/site.local.env, and refuses a value that was not set for this machine.
# render installs a file with each @NAME@ placeholder replaced by its site value.

. config/wsl/site.env
if [ -f config/wsl/site.local.env ]; then
  . config/wsl/site.local.env
fi
for _name in SIEM_WINDOWS_MONITOR SIEM_WINDOWS_INVENTORY; do
  case ${!_name:-} in
    /*) case ${!_name} in *'<'*|*'>'*|*'#'*|*' '*) echo "site.sh: set $_name in config/wsl/site.local.env" >&2; exit 1 ;; esac ;;
    *) echo "site.sh: set $_name in config/wsl/site.local.env, as an absolute path" >&2; exit 1 ;;
  esac
done
unset _name

# render <mode> <owner> <group> <destination file or folder> <source>...
render() {
  local mode=$1 owner=$2 group=$3 destination=$4 source target
  shift 4
  for source in "$@"; do
    target=$destination
    [ -d "$destination" ] && target="$destination/$(basename "$source")"
    sed -e "s#@SIEM_WINDOWS_MONITOR@#$SIEM_WINDOWS_MONITOR#g" -e "s#@SIEM_WINDOWS_INVENTORY@#$SIEM_WINDOWS_INVENTORY#g" "$source" > "$target.new"
    if grep -q '@SIEM_[A-Z_]*@' "$target.new"; then
      rm -f "$target.new"
      echo "render: $source has a placeholder with no site value" >&2
      return 1
    fi
    chown "$owner:$group" "$target.new"
    chmod "$mode" "$target.new"
    mv "$target.new" "$target"
  done
}
