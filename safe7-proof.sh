#!/usr/bin/env bash
# safe7-proof.sh — one-shot bootstrap + end-to-end Vaulta/EOS proof on Safe 7 (Pop!OS).
#
# Installs Nix (official nixos.org installer), clones beehive-nature/Trezor-firmware-dApp
# branch `beehive`, builds the T3W1 DEBUG emulator, launches it headless in a dedicated
# profile (~/.trezoremu/safe7), then safe7/proof.py seeds it with the repo test-vector
# mnemonic over the debug link and asserts the EOS public key against the repo's own
# device-test vector. Prints "PROOF OK" on success.
#
# Idempotent: safe to re-run at any point. An existing ~/trezor-firmware checkout is left
# untouched (the proof then covers whatever is checked out — intended for dev iterations;
# provenance is recorded in ~/safe7/proof.out). Kills any previous emulator started from a
# build-xtask artifact for a deterministic run.
# Needs sudo once (Nix install only). Working files/logs: ~/safe7/
#
# NOTE: install.determinate.systems is unreachable on some networks (connection reset) —
# this script deliberately uses the official nixos.org installer instead.
set -euo pipefail

REPO="$HOME/trezor-firmware"
URL="https://github.com/beehive-nature/Trezor-firmware-dApp.git"
WORKDIR="$HOME/safe7"
NIX_PROFILE_D=/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
mkdir -p "$WORKDIR"
export EMU_LOG="$WORKDIR/emu.log"
export EMU_PIDFILE="$WORKDIR/emu.pid"
export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true

exec 9>"$WORKDIR/.lock"
flock -n 9 || { echo "FATAL: another safe7-proof.sh run is already in progress." >&2; exit 1; }

stage(){ printf '\n=== %s ===\n' "$*"; }
# Reachability probe: ANY http response code proves the TCP+TLS path is open;
# only no-response-at-all (curl 000) counts as blocked. Tries IPv4 first, then default.
probe(){
  local u="$1" code
  code=$(curl -4 -sS --max-time 20 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || true)
  { [ -n "$code" ] && [ "$code" != "000" ]; } && return 0
  code=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || true)
  { [ -n "$code" ] && [ "$code" != "000" ]; } && return 0
  echo "FATAL: cannot reach $u — this network appears to block it (like install.determinate.systems). Unblock it and re-run." >&2
  exit 1
}

stage "1/5 nix"
if ! command -v nix-shell >/dev/null 2>&1; then
  for p in "$NIX_PROFILE_D" /etc/profile.d/nix.sh \
           "$HOME/.nix-profile/etc/profile.d/nix.sh" \
           "$HOME/.local/state/nix/profile/etc/profile.d/nix.sh"; do
    if [ -e "$p" ]; then set +eu; . "$p"; set -eu; fi
  done
fi
if ! command -v nix-shell >/dev/null 2>&1; then
  if [ -d /nix ]; then
    echo "FATAL: /nix exists but nix-shell is not usable — a previous install is broken or single-user." >&2
    echo "Recover manually (restore /etc/*.backup-before-nix files, sudo rm -rf /nix) and re-run." >&2
    exit 1
  fi
  for f in /etc/bashrc /etc/bash.bashrc /etc/profile.d/nix.sh /etc/zshrc; do
    if [ -e "$f.backup-before-nix" ]; then
      echo "FATAL: leftover $f.backup-before-nix from an aborted Nix install." >&2
      echo "Restore it first:  sudo mv '$f.backup-before-nix' '$f'  — then re-run." >&2
      exit 1
    fi
  done
  probe https://nixos.org/nix/install
  probe https://cache.nixos.org/nix-cache-info
  if ! sudo -n true 2>/dev/null; then
    if [ -t 0 ]; then
      sudo -v || { echo "FATAL: sudo authentication failed." >&2; exit 1; }
    else
      echo "FATAL: the Nix install needs sudo but there is no TTY here." >&2
      echo "Run 'sudo -v' in a real terminal on this machine first, then re-run this script." >&2
      exit 1
    fi
  fi
  echo "Installing Nix via the official nixos.org installer (sudo may prompt once)..."
  inst="$(mktemp)"
  trap 'rm -f "${inst:-}"' EXIT
  curl -4 -fsSL --retry 3 --max-time 300 https://nixos.org/nix/install -o "$inst"
  sh "$inst" --daemon --yes --no-channel-add || {
    rc=$?
    echo "FATAL: nix installer exited $rc — see its output above. (If it rejected '--yes', the installer version is very old.)" >&2
    exit 1
  }
  [ -e "$NIX_PROFILE_D" ] || { echo "FATAL: installer exited 0 but $NIX_PROFILE_D is missing (partial install?)." >&2; exit 1; }
  set +eu; . "$NIX_PROFILE_D"; set -eu
fi
command -v nix-shell >/dev/null 2>&1 || { echo "FATAL: nix-shell still not on PATH — open a NEW terminal and re-run." >&2; exit 1; }
nix-shell --version

stage "2/5 repo"
if [ -e "$REPO" ]; then
  git -C "$REPO" rev-parse --verify HEAD >/dev/null 2>&1 || {
    echo "FATAL: $REPO exists but is not a usable git checkout (interrupted clone?)." >&2
    echo "Remove it (rm -rf '$REPO') and re-run." >&2; exit 1; }
  actual_url="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
  [ "$actual_url" = "$URL" ] || {
    echo "FATAL: $REPO exists but its origin is '$actual_url', not this fork." >&2
    echo "Move it aside and re-run." >&2; exit 1; }
  if git -C "$REPO" submodule status --recursive 2>/dev/null | grep -q '^-'; then
    echo "FATAL: $REPO has uninitialized submodules (interrupted clone?)." >&2
    echo "Fix:  git -C '$REPO' submodule update --init --recursive  — then re-run." >&2
    exit 1
  fi
  echo "existing checkout left untouched"
else
  [ -n "$(git ls-remote "$URL" beehive)" ] || { echo "FATAL: cannot see branch 'beehive' at $URL." >&2; exit 1; }
  git clone --recursive -b beehive "$URL" "$REPO"
fi
[ -f "$REPO/safe7/proof.py" ] || {
  echo "FATAL: $REPO/safe7/proof.py is missing — this checkout does not contain the proof harness." >&2; exit 1; }
TREE_HEAD="$(git -C "$REPO" rev-parse --short HEAD)"
TREE_BRANCH="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
TREE_DIRTY=""
[ -z "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] || TREE_DIRTY=" (DIRTY: proof covers uncommitted local changes)"
echo "tree: $TREE_HEAD on $TREE_BRANCH$TREE_DIRTY"

stage "3/5 deps + DEBUG emulator build (first run is LONG: ~2-4 GB nix download, then the build)"
probe https://cache.nixos.org/nix-cache-info
probe https://pypi.org/pypi/pip/json
probe https://index.crates.io/config.json
cd "$REPO"
nix-shell --run '
  set -euo pipefail
  uv sync
  source .venv/bin/activate
  cd core/embed
  cargo run -p xtask -- build firmware -m t3w1 -e --pyopt=false --disable-tropic
'
test -x "$REPO/core/build-xtask/artifacts/latest/firmware-emu" || {
  echo "FATAL: build finished but core/build-xtask/artifacts/latest/firmware-emu is missing." >&2; exit 1; }

stage "4/5 emulator (headless debug build, erased 'safe7' profile)"
oldpid="$(cat "$EMU_PIDFILE" 2>/dev/null || true)"
if [ -n "$oldpid" ] && tr '\0' ' ' <"/proc/$oldpid/cmdline" 2>/dev/null | grep -q 'emu\.py'; then
  kill "$oldpid" 2>/dev/null || true
fi
rm -f "$EMU_PIDFILE"
pkill -u "$(id -u)" -f 'build-xtask/artifacts/latest/firmware-emu' 2>/dev/null || true
for _ in $(seq 1 20); do
  pgrep -u "$(id -u)" -f 'build-xtask/artifacts/latest/firmware-emu' >/dev/null || break
  sleep 0.5
done
: > "$EMU_LOG"
nix-shell --run '
  set -euo pipefail
  : "${EMU_LOG:?}" "${EMU_PIDFILE:?}"
  cd core
  nohup env TMPDIR=/tmp TMP=/tmp uv run python emu.py -e --headless -p safe7 > "$EMU_LOG" 2>&1 &
  echo "$!" > "$EMU_PIDFILE"
'
sleep 3
kill -0 "$(cat "$EMU_PIDFILE")" 2>/dev/null || {
  echo "FATAL: emulator died immediately; log tail:" >&2; tail -n 40 "$EMU_LOG" >&2 || true; exit 1; }
echo "emulator running (pid $(cat "$EMU_PIDFILE")), log: $EMU_LOG"

stage "5/5 THE PROOF"
{ echo "provenance: tree $TREE_HEAD on $TREE_BRANCH$TREE_DIRTY"; } | tee "$WORKDIR/proof.out"
set +e
nix-shell --run 'timeout 300 uv run python safe7/proof.py' 2>&1 | tee -a "$WORKDIR/proof.out"
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ] || ! grep -q 'PROOF OK' "$WORKDIR/proof.out"; then
  [ "$rc" = 124 ] && echo "FATAL: proof timed out after 300s (hung inside trezorlib — emulator wedged?)." >&2
  echo "FATAL: proof did not verify (rc=$rc); emulator log tail:" >&2
  tail -n 40 "$EMU_LOG" >&2 || true
  exit 1
fi
stage "DONE — Vaulta/EOS proven end-to-end on Safe 7 (exact repo test-vector match, tree $TREE_HEAD). Emulator left running for dev."
