# ns

Linux user namespace utility to drop as many privileges as we can while still producing a *functioning* shell.

Provides isolated:

* user namespace
* hostname / domain
* pid tree
* ipc queue
* mounts (remounted as read-only additionally)
* cgroups

⚠ Most applications are a bit grumpy that everything other than the executing user is shown as `nobody` - notably ssh has issues with this.

There might be a winner in `uid_map` that I can't figure out, from what I can gather it seems like user_namespaces are a bit too new for a lot of filesystems to handle well.
