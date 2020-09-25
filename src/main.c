#define _GNU_SOURCE

#include <mntent.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

struct user_info {
    uid_t uid;
    gid_t gid;
};


// List of filesystems we can't bind remount.
// Taken from my /proc/filesystems - probs needs more
// Be sure to have NULL at the end.
static const char *ignoredfs[] = {
    "autofs",
    "bdev",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "cpuset",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fuse",
    "fuse.gvfsd-fuse",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "pipefs",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "sockfs",
    "sysfs",
    "tmpfs",
    "tracefs",
    "vfat",
    NULL,
};

/*
 * Figure out if the target filesystem is a pseudo-fs and should be ignored
 * when we bind-ro remount things.
 */
bool is_ignored_fs(const char *fs_type) {
    int i = 0;
    while (ignoredfs[i] != NULL) {
        if (strcmp(ignoredfs[i], fs_type) == 0) {
            return true;
        }
        i++;
    }
    return false;
}

/*
 * Fake ID mappings inside an user_namespace back to the parent as we're not
 * pretending to be root or anything fun.
 */
void write_maps(struct user_info user) {
    FILE *f;
    f = fopen("/proc/self/uid_map", "w");
    // fprintf(f, "0 %ld 1\n", (long int)user.uid);
    fprintf(f, "%ld %ld 1\n", (long int)user.uid, (long int)user.uid);
    fflush(f);
    fclose(f);

    f = fopen("/proc/self/setgroups", "w");
    fprintf(f, "deny");
    fflush(f);
    fclose(f);

    f = fopen("/proc/self/gid_map", "w");
    // fprintf(f, "0 %ld 1\n", (long int)user.gid);
    fprintf(f, "%ld %ld 1\n", (long int)user.gid, (long int)user.gid);
    fflush(f);
    fclose(f);
}

/*
 * Try and remount all the filesystems we can as read-only. This *could* be
 * undone if we're root inside the user namespace (depends on uid_map)
 */
void remount_all_ro() {
    struct mntent *ent;
    FILE *f = setmntent("/proc/self/mounts", "r");
    if (f == NULL) {
        perror("Failed to read mounts");
        exit(EXIT_FAILURE);
    }
    while (NULL != (ent = getmntent(f))) {
        if (is_ignored_fs(ent->mnt_type))
            continue;
        printf("Remounting ro: %s %s\n", ent->mnt_fsname, ent->mnt_dir);
        if (mount("none", ent->mnt_dir, ent->mnt_type, MS_RDONLY|MS_REMOUNT|MS_NOATIME|MS_BIND|MS_REC, NULL) != 0) {
            perror("Recursive readonly-remount");
            exit(EXIT_FAILURE);
        }
    }
    endmntent(f);
}

/*
 * Replace ourselves with an interactive bash prompt.
 */
int spawn_bash(void) {
    char *newargv[] = { "/bin/bash", "-l", NULL };

    execvp("/bin/bash", newargv);
    perror("exec");
    exit(EXIT_FAILURE);
}

/*
 * Inside our fork()
 * Remount everything as private so we don't modify FS outside our namespace
 * Remount proc so `ps` looks right, remount everything else we can
 */
int child(void *arg) {
    // Mark all mounts as private (once we're in child CLONENEWNS)
    if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) != 0) {
        perror("Recursive remount");
        exit(EXIT_FAILURE);
    }

    // Remount proc so we only see new PID tree (with CLONE_NEWNS or break the parent)
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("Proc namespace shadow");
        exit(EXIT_FAILURE);
    }

    // Remount everything we can as readonly
    remount_all_ro();

    // Dump user in a shell
    spawn_bash();
    return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
    struct user_info user;
    user.uid = getuid();
    user.gid = getgid();

    // Drop into a user_namespace with CAP_SYS_ADMIN so we can clone with namespaces without being root
    unshare(CLONE_NEWUSER);
    write_maps(user);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, NULL, NULL, NULL) == -1)
        perror("PR_SET_NO_NEW_PRIVS");


    int namespaces = CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWCGROUP;
    pid_t p = clone(child, child_stack + STACK_SIZE, namespaces|SIGCHLD, NULL);
    if (p == -1) {
        perror("clone");
        exit(EXIT_FAILURE);
    }
    waitpid(p, NULL, 0);
    return 0;
}
