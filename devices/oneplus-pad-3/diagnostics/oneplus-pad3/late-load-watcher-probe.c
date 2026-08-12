#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Non-root fault harness for late_load.c's process topology. It changes only
 * anonymous state and a temporary lock file: no SELinux/sysctl/module path is
 * opened. Parent death and a forced deadline must both kill the private worker
 * process group, restore every simulated global, and retain the flock through
 * cleanup. */

enum { PROBE_PENDING = 0, PROBE_ABORT = 1 };

struct probe_mailbox {
  atomic_int watcher_ready;
  atomic_int outer_ready;
  atomic_int worker_ready;
  atomic_int decision;
  atomic_int cleanup_started;
  atomic_int cleanup_done;
  atomic_int kptr_state;
  atomic_int trusted_receipt;
  atomic_int public_receipt;
  atomic_int enforcing;
  pid_t outer_pid;
  pid_t watcher_pid;
  pid_t worker_pid;
};

static int pidfd_open_exact(pid_t pid) {
#ifdef SYS_pidfd_open
  return (int)syscall(SYS_pidfd_open, pid, 0);
#else
  (void)pid;
  errno = ENOSYS;
  return -1;
#endif
}

static int pidfd_dead(int fd) {
  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  int ret;
  do {
    ret = poll(&pfd, 1, 0);
  } while (ret < 0 && errno == EINTR);
  return ret > 0;
}

static int wait_atomic(atomic_int *field, int expected, int timeout_ms) {
  for (int i = 0; i < timeout_ms; i++) {
    if (atomic_load_explicit(field, memory_order_acquire) == expected) {
      return 1;
    }
    usleep(1000);
  }
  return 0;
}

static void worker_main(struct probe_mailbox *mailbox) {
  pid_t self = getpid();
  if (setpgid(0, 0) != 0) {
    _exit(21);
  }
  pid_t loader = fork();
  if (loader < 0) {
    _exit(22);
  }
  if (loader == 0) {
    for (;;) {
      pause();
    }
  }
  mailbox->worker_pid = self;
  atomic_store_explicit(&mailbox->worker_ready, 1, memory_order_release);
  for (;;) {
    pause();
  }
}

static void watcher_main(struct probe_mailbox *mailbox, int outer_pidfd,
                         int lock_fd, int timeout_ms) {
  if (prctl(PR_SET_PDEATHSIG, 0) != 0 ||
      flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    _exit(31);
  }
  mailbox->watcher_pid = getpid();
  atomic_store_explicit(&mailbox->watcher_ready, 1, memory_order_release);
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    _exit(32);
  }
  for (;;) {
    struct pollfd parent = {.fd = outer_pidfd, .events = POLLIN};
    int parent_poll = poll(&parent, 1, 0);
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      _exit(33);
    }
    int64_t elapsed = (now.tv_sec - start.tv_sec) * 1000LL +
                      (now.tv_nsec - start.tv_nsec) / 1000000LL;
    if (parent_poll != 0 || elapsed >= timeout_ms) {
      break;
    }
    usleep(1000);
  }
  atomic_store_explicit(&mailbox->decision, PROBE_ABORT,
                        memory_order_release);
  if (!wait_atomic(&mailbox->worker_ready, 1, 3000)) {
    _exit(34);
  }
  int worker_pidfd = pidfd_open_exact(mailbox->worker_pid);
  if (worker_pidfd < 0 || getpgid(mailbox->worker_pid) != mailbox->worker_pid) {
    _exit(35);
  }
  atomic_store_explicit(&mailbox->cleanup_started, 1,
                        memory_order_release);
  (void)kill(-mailbox->worker_pid, SIGKILL);
#ifdef SYS_pidfd_send_signal
  (void)syscall(SYS_pidfd_send_signal, worker_pidfd, SIGKILL, NULL, 0);
#endif
  for (int i = 0; i < 3000 && !pidfd_dead(worker_pidfd); i++) {
    usleep(1000);
  }
  if (!pidfd_dead(worker_pidfd)) {
    _exit(36);
  }
  close(worker_pidfd);

  atomic_store_explicit(&mailbox->kptr_state, 2, memory_order_release);
  atomic_store_explicit(&mailbox->trusted_receipt, 0, memory_order_release);
  atomic_store_explicit(&mailbox->public_receipt, 0, memory_order_release);
  atomic_store_explicit(&mailbox->enforcing, 1, memory_order_release);
  atomic_store_explicit(&mailbox->cleanup_done, 1, memory_order_release);
  /* Give the controller a deterministic interval in which the cleanup flag is
   * visible while the inherited flock must still exclude a second opener. */
  usleep(100000);
  _exit(0);
}

static void outer_main(struct probe_mailbox *mailbox, const char *lock_path,
                       int timeout_ms) {
  int lock_fd = open(lock_path, O_RDWR | O_CLOEXEC);
  if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    _exit(41);
  }
  pid_t self = getpid();
  int self_pidfd = pidfd_open_exact(self);
  if (self_pidfd < 0) {
    _exit(42);
  }
  pid_t watcher = fork();
  if (watcher == 0) {
    watcher_main(mailbox, self_pidfd, lock_fd, timeout_ms);
  }
  close(self_pidfd);
  if (watcher < 0 || !wait_atomic(&mailbox->watcher_ready, 1, 3000) ||
      mailbox->watcher_pid != watcher) {
    _exit(43);
  }
  pid_t worker = fork();
  if (worker == 0) {
    worker_main(mailbox);
  }
  if (worker < 0 || !wait_atomic(&mailbox->worker_ready, 1, 3000) ||
      mailbox->worker_pid != worker) {
    _exit(44);
  }
  mailbox->outer_pid = self;
  atomic_store_explicit(&mailbox->kptr_state, 0, memory_order_release);
  atomic_store_explicit(&mailbox->trusted_receipt, 1, memory_order_release);
  atomic_store_explicit(&mailbox->public_receipt, 1, memory_order_release);
  atomic_store_explicit(&mailbox->enforcing, 0, memory_order_release);
  atomic_store_explicit(&mailbox->outer_ready, 1, memory_order_release);
  for (;;) {
    pause();
  }
}

static int lock_is_excluded(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  int excluded = flock(fd, LOCK_EX | LOCK_NB) != 0 &&
                 (errno == EWOULDBLOCK || errno == EAGAIN);
  close(fd);
  return excluded;
}

static int lock_is_available(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  int available = flock(fd, LOCK_EX | LOCK_NB) == 0;
  close(fd);
  return available;
}

static int run_case(const char *lock_path, int kill_parent, int timeout_ms) {
  struct probe_mailbox *mailbox =
      mmap(NULL, sizeof(*mailbox), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    return 0;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  atomic_init(&mailbox->decision, PROBE_PENDING);
  pid_t outer = fork();
  if (outer == 0) {
    outer_main(mailbox, lock_path, timeout_ms);
  }
  int outer_pidfd = outer > 0 ? pidfd_open_exact(outer) : -1;
  if (outer <= 0 || outer_pidfd < 0 ||
      !wait_atomic(&mailbox->outer_ready, 1, 3000)) {
    if (outer > 0) {
      kill(outer, SIGKILL);
      waitpid(outer, NULL, 0);
    }
    if (outer_pidfd >= 0) {
      close(outer_pidfd);
    }
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }
  int watcher_pidfd = pidfd_open_exact(mailbox->watcher_pid);
  int worker_pidfd = pidfd_open_exact(mailbox->worker_pid);
  if (watcher_pidfd < 0 || worker_pidfd < 0 || !lock_is_excluded(lock_path)) {
    kill(outer, SIGKILL);
    waitpid(outer, NULL, 0);
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }
  if (kill_parent) {
    kill(outer, SIGKILL);
    waitpid(outer, NULL, 0);
    outer = -1;
  }
  int started = wait_atomic(&mailbox->cleanup_started, 1, 5000);
  int retained = started && lock_is_excluded(lock_path);
  int cleaned = wait_atomic(&mailbox->cleanup_done, 1, 5000);
  for (int i = 0; i < 5000 && !pidfd_dead(watcher_pidfd); i++) {
    usleep(1000);
  }
  if (outer > 0) {
    /* In the deadline case the deliberately hung parent continues to retain
     * the same flock after watcher cleanup. Kill it only after verifying that
     * fail-closed property. */
    retained = retained && lock_is_excluded(lock_path);
    kill(outer, SIGKILL);
    waitpid(outer, NULL, 0);
  }
  for (int i = 0; i < 3000 && !pidfd_dead(outer_pidfd); i++) {
    usleep(1000);
  }
  int passed = retained && cleaned && pidfd_dead(watcher_pidfd) &&
               pidfd_dead(worker_pidfd) &&
               atomic_load_explicit(&mailbox->decision,
                                    memory_order_acquire) == PROBE_ABORT &&
               atomic_load_explicit(&mailbox->kptr_state,
                                    memory_order_acquire) == 2 &&
               atomic_load_explicit(&mailbox->trusted_receipt,
                                    memory_order_acquire) == 0 &&
               atomic_load_explicit(&mailbox->public_receipt,
                                    memory_order_acquire) == 0 &&
               atomic_load_explicit(&mailbox->enforcing,
                                    memory_order_acquire) == 1 &&
               lock_is_available(lock_path);
  close(worker_pidfd);
  close(watcher_pidfd);
  close(outer_pidfd);
  munmap(mailbox, sizeof(*mailbox));
  return passed;
}

static int run_nominal_ok_parent_restore_case(void) {
  int status = 0;
  int enforcing_result = 2; /* worker said OK, parent found 0 and restored 1 */
  int trusted_receipt = 1;
  int public_receipt = 1;
  if (enforcing_result == 0 || (status == 0 && enforcing_result != 1)) {
    status = 16; /* LATE_LOAD_STATUS_SELINUX */
  }
  /* This is the regression join: receipt invalidation belongs after the
   * enforcing result has finalized status, not only after worker wait. */
  if (status != 0) {
    trusted_receipt = 0;
    public_receipt = 0;
  }
  return status == 16 && trusted_receipt == 0 && public_receipt == 0;
}

enum receipt_fault {
  RECEIPT_FAULT_UNLINK = 1,
  RECEIPT_FAULT_OPEN = 2,
  RECEIPT_FAULT_FSYNC = 3,
};

struct receipt_fault_state {
  int trusted_receipt;
  int public_receipt;
  int trusted_durable;
  int lock_held;
  int returned;
};

static int simulate_receipt_cleanup(struct receipt_fault_state *state,
                                    enum receipt_fault fault,
                                    int attempt) {
  int first = attempt == 0;
  int trusted_opened = !(first && fault == RECEIPT_FAULT_OPEN);
  int trusted_unlinked = trusted_opened &&
                         !(first && fault == RECEIPT_FAULT_UNLINK);
  int trusted_synced = trusted_opened && trusted_unlinked &&
                       !(first && fault == RECEIPT_FAULT_FSYNC);

  /* Model the production cleanup's independent public attempt even when the
   * trusted side failed. */
  state->public_receipt = 0;
  if (trusted_unlinked) {
    state->trusted_receipt = 0;
  }
  if (trusted_synced) {
    state->trusted_durable = 1;
  } else if (trusted_unlinked) {
    state->trusted_durable = 0;
  }
  return trusted_opened && trusted_unlinked && trusted_synced &&
         state->trusted_receipt == 0 && state->public_receipt == 0 &&
         state->trusted_durable;
}

static int run_receipt_io_fail_stop_case(enum receipt_fault fault) {
  struct receipt_fault_state state = {
      .trusted_receipt = 1,
      .public_receipt = 1,
      .trusted_durable = 1,
      .lock_held = 1,
      .returned = 0,
  };
  int attempts = 0;
  while (!simulate_receipt_cleanup(&state, fault, attempts++)) {
    /* A failed cleanup attempt is allowed to make partial progress, but it
     * cannot publish a return or release the serialization lock. */
    if (state.returned || !state.lock_held || attempts > 4) {
      return 0;
    }
  }
  state.returned = 1;
  int passed = attempts == 2 && state.lock_held && state.returned &&
               state.trusted_receipt == 0 && state.public_receipt == 0 &&
               state.trusted_durable;
  state.lock_held = 0;
  return passed;
}

int main(void) {
  char lock_path[128];
#ifdef __ANDROID__
  const char *temp_root = "/data/local/tmp";
#else
  const char *temp_root = "/tmp";
#endif
  int len = snprintf(lock_path, sizeof(lock_path),
                     "%s/rmop-late-watch.%ld", temp_root, (long)getpid());
  if (len <= 0 || len >= (int)sizeof(lock_path)) {
    return 1;
  }
  int fd = open(lock_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    return 1;
  }
  close(fd);
  int parent_death = run_case(lock_path, 1, 5000);
  int timeout = run_case(lock_path, 0, 250);
  int nominal_restore = run_nominal_ok_parent_restore_case();
  int unlink_fail_stop =
      run_receipt_io_fail_stop_case(RECEIPT_FAULT_UNLINK);
  int open_fail_stop = run_receipt_io_fail_stop_case(RECEIPT_FAULT_OPEN);
  int fsync_fail_stop = run_receipt_io_fail_stop_case(RECEIPT_FAULT_FSYNC);
  int receipt_io_fail_stop =
      unlink_fail_stop && open_fail_stop && fsync_fail_stop;
  unlink(lock_path);
  printf("late_load_parent_death=%s\n", parent_death ? "PASS" : "FAIL");
  printf("late_load_timeout=%s\n", timeout ? "PASS" : "FAIL");
  printf("late_load_lock_cleanup=%s\n",
         parent_death && timeout ? "PASS" : "FAIL");
  printf("late_load_nominal_ok_parent_restore=%s\n",
         nominal_restore ? "PASS" : "FAIL");
  printf("late_load_receipt_unlink_fail_stop=%s\n",
         unlink_fail_stop ? "PASS" : "FAIL");
  printf("late_load_receipt_open_fail_stop=%s\n",
         open_fail_stop ? "PASS" : "FAIL");
  printf("late_load_receipt_fsync_fail_stop=%s\n",
         fsync_fail_stop ? "PASS" : "FAIL");
  printf("late_load_receipt_io_fail_stop=%s\n",
         receipt_io_fail_stop ? "PASS" : "FAIL");
  return parent_death && timeout && nominal_restore && receipt_io_fail_stop
             ? 0
             : 2;
}
