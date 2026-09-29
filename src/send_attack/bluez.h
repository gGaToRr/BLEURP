#ifndef BLUEZ_H
#define BLUEZ_H

#include <stdbool.h>
#include <sys/types.h>

/* Agent NoInputNoOutput auto-acceptant (le cœur de la CVE-2023-45866).
   forke un processus qui sert D-Bus ; le parent continue. */
int  bluez_agent_start(const char *adapter, pid_t *out_pid);
void bluez_agent_stop(pid_t pid);

int bluez_device_remove(const char *adapter, const char *mac);
int bluez_device_pair(const char *adapter, const char *mac);   /* bloquant ~30s */
int bluez_device_discover(const char *adapter, const char *mac);
int bluez_device_trust(const char *adapter, const char *mac);

#endif
