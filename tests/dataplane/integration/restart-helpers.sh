# One-sided restart helpers for the chaos-E2E chains. Sourced by run.sh
# (and exercised by self-test.sh). Kept deliberately small and aligned
# with cleanup.sh's stop_owned_process ownership convention.

# sigkill_owned_process is the abrupt-crash sibling of cleanup.sh's
# graceful stop_owned_process: it verifies the PID's command line still
# names the expected component (so a reused PID is never signalled),
# then SIGKILLs it and waits for it to actually exit. It sends KILL
# directly — no INT/TERM first — because a chaos restart models an
# unclean crash, not a coordinated shutdown; only the named side is
# touched, so the other process keeps running.
sigkill_owned_process() {
	local pid=$1 expected=$2 command_line process_state
	[[ $pid =~ ^[0-9]+$ ]] || {
		echo "sigkill: invalid pid '$pid'" >&2
		return 1
	}
	command_line=$(ps -p "$pid" -o command= 2>/dev/null || true)
	[[ -n $command_line ]] || {
		echo "sigkill: PID $pid is already gone" >&2
		return 1
	}
	if [[ $command_line != *"$expected"* ]]; then
		echo "refusing to SIGKILL PID $pid: command does not contain '$expected'" >&2
		return 1
	fi
	kill -s KILL "$pid" 2>/dev/null || true
	for _ in {1..100}; do
		process_state=$(ps -p "$pid" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && return 0
		sleep 0.1
	done
	echo "SIGKILLed process $pid ($expected) did not exit" >&2
	return 1
}

# remove_dead_backend_socket removes a control UDS inode left behind by
# a SIGKILLed owner, under three conditions that TOGETHER guarantee a
# live socket (or the wrong path) is never deleted: (1) the owner PID is
# dead, (2) the path is verified to be a socket, (3) no process still
# holds it open (lsof). The dropper's own front socket is never passed
# here — only the backend Go control socket a killed Go left behind.
remove_dead_backend_socket() {
	local path=$1 dead_pid=$2
	if [[ $dead_pid =~ ^[0-9]+$ ]] && kill -0 "$dead_pid" 2>/dev/null; then
		echo "refusing to remove $path: owner PID $dead_pid is still alive" >&2
		return 1
	fi
	[[ -e $path ]] || return 0
	if [[ ! -S $path ]]; then
		echo "refusing to remove $path: it is not a socket" >&2
		return 1
	fi
	if lsof -- "$path" >/dev/null 2>&1; then
		echo "refusing to remove $path: it is still held open" >&2
		return 1
	fi
	rm -f -- "$path"
}
