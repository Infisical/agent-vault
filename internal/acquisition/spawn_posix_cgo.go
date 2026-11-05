//go:build (darwin || linux) && cgo

package acquisition

/*
#cgo CFLAGS: -D_GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

static int av_spawn_provider(const char *path, char *const envp[], int provider_fd, int stderr_fd, pid_t *pid_out) {
	posix_spawn_file_actions_t actions;
	posix_spawnattr_t attributes;
	int actions_ready = 0;
	int attributes_ready = 0;
	int rc = posix_spawn_file_actions_init(&actions);
	if (rc != 0) goto cleanup;
	actions_ready = 1;
	rc = posix_spawnattr_init(&attributes);
	if (rc != 0) goto cleanup;
	attributes_ready = 1;

	rc = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
	if (rc != 0) goto cleanup;
	rc = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
	if (rc != 0) goto cleanup;
	rc = posix_spawn_file_actions_adddup2(&actions, stderr_fd, STDERR_FILENO);
	if (rc != 0) goto cleanup;
	rc = posix_spawn_file_actions_adddup2(&actions, provider_fd, 3);
	if (rc != 0) goto cleanup;
#if defined(__APPLE__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
	rc = posix_spawn_file_actions_addchdir_np(&actions, "/");
#if defined(__APPLE__)
#pragma clang diagnostic pop
#endif
	if (rc != 0) goto cleanup;

#if defined(__APPLE__)
#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#error "Agent Vault provider runner requires POSIX_SPAWN_CLOEXEC_DEFAULT on macOS"
#endif
#else
	rc = posix_spawn_file_actions_addclosefrom_np(&actions, 4);
	if (rc != 0) goto cleanup;
#endif

	sigset_t empty_mask;
	sigset_t default_signals;
	sigemptyset(&empty_mask);
	sigemptyset(&default_signals);
	sigaddset(&default_signals, SIGPIPE);
	sigaddset(&default_signals, SIGTERM);
	sigaddset(&default_signals, SIGINT);
	sigaddset(&default_signals, SIGHUP);
	sigaddset(&default_signals, SIGQUIT);
	rc = posix_spawnattr_setsigmask(&attributes, &empty_mask);
	if (rc != 0) goto cleanup;
	rc = posix_spawnattr_setsigdefault(&attributes, &default_signals);
	if (rc != 0) goto cleanup;
	rc = posix_spawnattr_setpgroup(&attributes, 0);
	if (rc != 0) goto cleanup;

	short flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
#if defined(__APPLE__)
	flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
	rc = posix_spawnattr_setflags(&attributes, flags);
	if (rc != 0) goto cleanup;

	char *const argv[] = {(char *)path, NULL};
	rc = posix_spawn(pid_out, path, &actions, &attributes, argv, envp);

cleanup:
	if (attributes_ready) posix_spawnattr_destroy(&attributes);
	if (actions_ready) posix_spawn_file_actions_destroy(&actions);
	return rc;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func spawnProvider(path string, environment []string, providerFD, stderrFD int) (int, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	pointers := make([]*C.char, len(environment)+1)
	for index, value := range environment {
		pointers[index] = C.CString(value)
	}
	defer func() {
		for _, pointer := range pointers[:len(environment)] {
			C.free(unsafe.Pointer(pointer))
		}
	}()

	var pid C.pid_t
	rc := C.av_spawn_provider(
		cPath,
		(**C.char)(unsafe.Pointer(&pointers[0])),
		C.int(providerFD),
		C.int(stderrFD),
		&pid,
	)
	if rc != 0 {
		return 0, fmt.Errorf("posix_spawn failed with code %d", int(rc))
	}
	return int(pid), nil
}
