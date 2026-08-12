#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Android 16's bionic exports _Fork().  Unlike fork(), it does not run
 * pthread_atfork handlers; unlike a direct SYS_clone call, it also keeps
 * bionic's cached process identity coherent. */
extern pid_t _Fork(void);

enum {
  COMMAND_IDLE = 0,
  COMMAND_SPAWN_WATCHDOG = 1,
  COMMAND_EXIT = 2,
};

struct mailbox {
  _Atomic uint32_t command;
  _Atomic uint32_t bootstrap_ready;
  _Atomic uint32_t watchdog_ready;
  _Atomic uint32_t bootstrap_done;
  pid_t expected_parent;
  pid_t bootstrap_pid;
  pid_t bootstrap_libc_pid;
  pid_t bootstrap_raw_pid;
  pid_t bootstrap_parent;
  pid_t watchdog_pid;
  pid_t watchdog_parent;
  int watchdog_pdeathsig;
};

struct death_mailbox {
  _Atomic uint32_t victim_ready;
  pid_t outer_pid;
  pid_t victim_pid;
  pid_t victim_parent;
  int victim_pdeathsig;
};

struct stop_mailbox {
  _Atomic uint32_t ready;
  _Atomic uint32_t resumed;
  pid_t child_pid;
  pid_t child_tid;
};

struct pidfd_guard_mailbox {
  _Atomic uint32_t guardian_ready;
  _Atomic uint32_t guardian_observed_death;
  _Atomic uint32_t bootstrap_done;
  pid_t outer_pid;
  pid_t bootstrap_pid;
  pid_t guardian_pid;
  pid_t guardian_parent;
};

static int send_fd(int socket_fd, int passed_fd) {
  char marker = 'P';
  struct iovec iov = {.iov_base = &marker, .iov_len = sizeof(marker)};
  char control[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
  return sendmsg(socket_fd, &msg, 0) == (ssize_t)sizeof(marker);
}

static int recv_fd(int socket_fd) {
  struct pollfd pfd = {.fd = socket_fd, .events = POLLIN};
  if (poll(&pfd, 1, 3000) != 1 || !(pfd.revents & POLLIN)) {
    return -1;
  }
  char marker = 0;
  struct iovec iov = {.iov_base = &marker, .iov_len = sizeof(marker)};
  char control[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) !=
          (ssize_t)sizeof(marker) ||
      marker != 'P' || (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) {
    return -1;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
    return -1;
  }
  int received = -1;
  memcpy(&received, CMSG_DATA(cmsg), sizeof(received));
  return received;
}

static int wait_atomic(_Atomic uint32_t *value, uint32_t expected,
                       int timeout_ms) {
  struct timespec start;
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    return 0;
  }
  for (;;) {
    if (atomic_load_explicit(value, memory_order_acquire) == expected) {
      return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      return 0;
    }
    int64_t elapsed_ms = (now.tv_sec - start.tv_sec) * 1000LL +
                         (now.tv_nsec - start.tv_nsec) / 1000000LL;
    if (elapsed_ms >= timeout_ms) {
      return 0;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&pause, NULL);
  }
}

static void wait_command(struct mailbox *mailbox, uint32_t command) {
  while (atomic_load_explicit(&mailbox->command, memory_order_acquire) !=
         command) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&pause, NULL);
  }
}

static void watchdog_main(struct mailbox *mailbox) {
  int inherited = -1;
  if (prctl(PR_GET_PDEATHSIG, &inherited) != 0) {
    _exit(31);
  }
  mailbox->watchdog_pid = (pid_t)syscall(SYS_getpid);
  mailbox->watchdog_parent = (pid_t)syscall(SYS_getppid);
  mailbox->watchdog_pdeathsig = inherited;
  atomic_store_explicit(&mailbox->watchdog_ready, 1,
                        memory_order_release);
  wait_command(mailbox, COMMAND_EXIT);
  _exit(0);
}

static void bootstrap_main(struct mailbox *mailbox, int socket_fd) {
  pid_t raw_pid = (pid_t)syscall(SYS_getpid);
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      (pid_t)syscall(SYS_getppid) != mailbox->expected_parent ||
      prctl(PR_SET_NAME, "rmop-a3-probe", 0, 0, 0) != 0) {
    _exit(21);
  }
  int pin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (pin_fd < 0 || !send_fd(socket_fd, pin_fd) || close(pin_fd) != 0) {
    _exit(22);
  }
  close(socket_fd);

  mailbox->bootstrap_pid = raw_pid;
  mailbox->bootstrap_libc_pid = getpid();
  mailbox->bootstrap_raw_pid = (pid_t)syscall(SYS_getpid);
  mailbox->bootstrap_parent = (pid_t)syscall(SYS_getppid);
  atomic_store_explicit(&mailbox->bootstrap_ready, 1,
                        memory_order_release);

  wait_command(mailbox, COMMAND_SPAWN_WATCHDOG);
  pid_t watchdog = _Fork();
  if (watchdog < 0) {
    _exit(23);
  }
  if (watchdog == 0) {
    watchdog_main(mailbox);
  }
  if (!wait_atomic(&mailbox->watchdog_ready, 1, 3000) ||
      mailbox->watchdog_pid != watchdog) {
    kill(watchdog, SIGKILL);
    waitpid(watchdog, NULL, 0);
    _exit(24);
  }

  wait_command(mailbox, COMMAND_EXIT);
  int status = 0;
  if (waitpid(watchdog, &status, 0) != watchdog ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    _exit(25);
  }
  atomic_store_explicit(&mailbox->bootstrap_done, 1,
                        memory_order_release);
  _exit(0);
}

static void pdeath_victim_main(struct death_mailbox *mailbox,
                               pid_t expected_parent) {
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      (pid_t)syscall(SYS_getppid) != expected_parent) {
    _exit(41);
  }
  int configured = -1;
  if (prctl(PR_GET_PDEATHSIG, &configured) != 0) {
    _exit(42);
  }
  mailbox->victim_pid = (pid_t)syscall(SYS_getpid);
  mailbox->victim_parent = (pid_t)syscall(SYS_getppid);
  mailbox->victim_pdeathsig = configured;
  atomic_store_explicit(&mailbox->victim_ready, 1, memory_order_release);
  for (;;) {
    pause();
  }
}

static void pdeath_outer_main(struct death_mailbox *mailbox) {
  pid_t self = (pid_t)syscall(SYS_getpid);
  mailbox->outer_pid = self;
  pid_t victim = _Fork();
  if (victim < 0) {
    _exit(43);
  }
  if (victim == 0) {
    pdeath_victim_main(mailbox, self);
  }
  for (;;) {
    pause();
  }
}

static int run_pdeathsig_probe(void) {
  struct death_mailbox *mailbox = mmap(NULL, sizeof(*mailbox),
                                       PROT_READ | PROT_WRITE,
                                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    return 0;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  pid_t outer = _Fork();
  if (outer == 0) {
    pdeath_outer_main(mailbox);
  }
  if (outer < 0 || !wait_atomic(&mailbox->victim_ready, 1, 3000) ||
      mailbox->outer_pid != outer || mailbox->victim_pid <= 1 ||
      mailbox->victim_parent != outer ||
      mailbox->victim_pdeathsig != SIGKILL) {
    if (outer > 0) {
      kill(outer, SIGKILL);
      while (waitpid(outer, NULL, 0) < 0 && errno == EINTR) {
      }
    }
    if (mailbox->victim_pid > 1) {
      kill(mailbox->victim_pid, SIGKILL);
    }
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }

#ifdef SYS_pidfd_open
  int pidfd = (int)syscall(SYS_pidfd_open, mailbox->victim_pid, 0);
#else
  int pidfd = -1;
  errno = ENOSYS;
#endif
  if (pidfd < 0) {
    kill(outer, SIGKILL);
    while (waitpid(outer, NULL, 0) < 0 && errno == EINTR) {
    }
    kill(mailbox->victim_pid, SIGKILL);
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }

  kill(outer, SIGKILL);
  while (waitpid(outer, NULL, 0) < 0 && errno == EINTR) {
  }
  struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
  int died;
  do {
    died = poll(&pfd, 1, 3000);
  } while (died < 0 && errno == EINTR);
  int passed = died == 1 && (pfd.revents & POLLIN);
  if (!passed) {
    kill(mailbox->victim_pid, SIGKILL);
  }
  close(pidfd);
  munmap(mailbox, sizeof(*mailbox));
  return passed;
}

static void stop_child_main(struct stop_mailbox *mailbox,
                            pid_t expected_parent) {
  pid_t pid = (pid_t)syscall(SYS_getpid);
  pid_t tid = (pid_t)syscall(SYS_gettid);
  if (pid <= 1 || pid != tid ||
      prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      (pid_t)syscall(SYS_getppid) != expected_parent) {
    _exit(51);
  }
  mailbox->child_pid = pid;
  mailbox->child_tid = tid;
  atomic_store_explicit(&mailbox->ready, 1, memory_order_release);
  if (syscall(SYS_tgkill, pid, tid, SIGSTOP) != 0) {
    _exit(52);
  }
  atomic_store_explicit(&mailbox->resumed, 1, memory_order_release);
  _exit(0);
}

static int run_stop_resume_probe(void) {
  struct stop_mailbox *mailbox = mmap(NULL, sizeof(*mailbox),
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    return 0;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  pid_t parent = (pid_t)syscall(SYS_getpid);
  pid_t child = _Fork();
  if (child == 0) {
    stop_child_main(mailbox, parent);
  }
  int passed = 0;
  if (child > 0 && wait_atomic(&mailbox->ready, 1, 3000) &&
      mailbox->child_pid == child && mailbox->child_tid == child) {
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(child, &status, WUNTRACED);
    } while (waited < 0 && errno == EINTR);
    if (waited == child && WIFSTOPPED(status) &&
        WSTOPSIG(status) == SIGSTOP && kill(child, SIGCONT) == 0 &&
        wait_atomic(&mailbox->resumed, 1, 3000)) {
      do {
        waited = waitpid(child, &status, 0);
      } while (waited < 0 && errno == EINTR);
      passed = waited == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0;
      child = -1;
    }
  }
  if (child > 0) {
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
  }
  munmap(mailbox, sizeof(*mailbox));
  return passed;
}

static void pidfd_guardian_main(struct pidfd_guard_mailbox *mailbox,
                                int outer_pidfd, pid_t expected_parent) {
  mailbox->guardian_pid = (pid_t)syscall(SYS_getpid);
  mailbox->guardian_parent = (pid_t)syscall(SYS_getppid);
  if (mailbox->guardian_pid <= 1 ||
      mailbox->guardian_parent != expected_parent) {
    _exit(61);
  }
  atomic_store_explicit(&mailbox->guardian_ready, 1,
                        memory_order_release);
  struct pollfd pfd = {.fd = outer_pidfd, .events = POLLIN};
  int observed;
  do {
    observed = poll(&pfd, 1, 5000);
  } while (observed < 0 && errno == EINTR);
  if (observed == 1 && (pfd.revents & POLLIN)) {
    atomic_store_explicit(&mailbox->guardian_observed_death, 1,
                          memory_order_release);
    _exit(0);
  }
  _exit(62);
}

static void pidfd_bootstrap_main(struct pidfd_guard_mailbox *mailbox,
                                 int outer_pidfd) {
  pid_t self = (pid_t)syscall(SYS_getpid);
  mailbox->bootstrap_pid = self;
  pid_t guardian = _Fork();
  if (guardian < 0) {
    _exit(63);
  }
  if (guardian == 0) {
    pidfd_guardian_main(mailbox, outer_pidfd, self);
  }
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(guardian, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != guardian || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    _exit(64);
  }
  close(outer_pidfd);
  atomic_store_explicit(&mailbox->bootstrap_done, 1,
                        memory_order_release);
  _exit(0);
}

static void pidfd_outer_main(struct pidfd_guard_mailbox *mailbox) {
  pid_t self = (pid_t)syscall(SYS_getpid);
  mailbox->outer_pid = self;
#ifdef SYS_pidfd_open
  int self_pidfd = (int)syscall(SYS_pidfd_open, self, 0);
#else
  int self_pidfd = -1;
  errno = ENOSYS;
#endif
  if (self_pidfd < 0) {
    _exit(65);
  }
  pid_t bootstrap = _Fork();
  if (bootstrap < 0) {
    _exit(66);
  }
  if (bootstrap == 0) {
    pidfd_bootstrap_main(mailbox, self_pidfd);
  }
  close(self_pidfd);
  for (;;) {
    pause();
  }
}

static int run_inherited_pidfd_guard_probe(void) {
  struct pidfd_guard_mailbox *mailbox =
      mmap(NULL, sizeof(*mailbox), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    return 0;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  pid_t outer = _Fork();
  if (outer == 0) {
    pidfd_outer_main(mailbox);
  }
  int bootstrap_pidfd = -1;
  int passed = 0;
  if (outer > 0 && wait_atomic(&mailbox->guardian_ready, 1, 3000) &&
      mailbox->outer_pid == outer && mailbox->bootstrap_pid > 1 &&
      mailbox->guardian_pid > 1 &&
      mailbox->guardian_parent == mailbox->bootstrap_pid) {
#ifdef SYS_pidfd_open
    bootstrap_pidfd =
        (int)syscall(SYS_pidfd_open, mailbox->bootstrap_pid, 0);
#endif
    if (bootstrap_pidfd >= 0 && kill(outer, SIGKILL) == 0) {
      while (waitpid(outer, NULL, 0) < 0 && errno == EINTR) {
      }
      outer = -1;
      struct pollfd pfd = {.fd = bootstrap_pidfd, .events = POLLIN};
      int exited;
      do {
        exited = poll(&pfd, 1, 5000);
      } while (exited < 0 && errno == EINTR);
      passed = exited == 1 && (pfd.revents & POLLIN) &&
               atomic_load_explicit(&mailbox->guardian_observed_death,
                                    memory_order_acquire) == 1 &&
               atomic_load_explicit(&mailbox->bootstrap_done,
                                    memory_order_acquire) == 1;
    }
  }
  if (outer > 0) {
    kill(outer, SIGKILL);
    while (waitpid(outer, NULL, 0) < 0 && errno == EINTR) {
    }
  }
  if (!passed) {
    if (mailbox->bootstrap_pid > 1) {
      kill(mailbox->bootstrap_pid, SIGKILL);
    }
    if (mailbox->guardian_pid > 1) {
      kill(mailbox->guardian_pid, SIGKILL);
    }
  }
  if (bootstrap_pidfd >= 0) {
    close(bootstrap_pidfd);
  }
  munmap(mailbox, sizeof(*mailbox));
  return passed;
}

int main(void) {
  int result = 1;
  int sockets[2] = {-1, -1};
  int received_fd = -1;
  pid_t bootstrap = -1;
  struct mailbox *mailbox = mmap(NULL, sizeof(*mailbox),
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  mailbox->expected_parent = (pid_t)syscall(SYS_getpid);

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
    perror("socketpair");
    goto out;
  }
  bootstrap = _Fork();
  if (bootstrap < 0) {
    perror("_Fork");
    goto out;
  }
  if (bootstrap == 0) {
    close(sockets[0]);
    bootstrap_main(mailbox, sockets[1]);
  }
  close(sockets[1]);
  sockets[1] = -1;

  received_fd = recv_fd(sockets[0]);
  struct stat st;
  if (received_fd < 0 || fstat(received_fd, &st) != 0 ||
      !S_ISCHR(st.st_mode) || (fcntl(received_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
      !wait_atomic(&mailbox->bootstrap_ready, 1, 3000)) {
    fprintf(stderr, "FAIL pin/mailbox bootstrap errno=%d\n", errno);
    goto out;
  }
  if (mailbox->bootstrap_pid != bootstrap ||
      mailbox->bootstrap_libc_pid != bootstrap ||
      mailbox->bootstrap_raw_pid != bootstrap ||
      mailbox->bootstrap_parent != mailbox->expected_parent) {
    fprintf(stderr,
            "FAIL identity expected=%d child=%d libc=%d raw=%d ppid=%d\n",
            mailbox->expected_parent, bootstrap,
            mailbox->bootstrap_libc_pid, mailbox->bootstrap_raw_pid,
            mailbox->bootstrap_parent);
    goto out;
  }

  atomic_store_explicit(&mailbox->command, COMMAND_SPAWN_WATCHDOG,
                        memory_order_release);
  if (!wait_atomic(&mailbox->watchdog_ready, 1, 3000) ||
      mailbox->watchdog_pid <= 1 ||
      mailbox->watchdog_parent != bootstrap ||
      mailbox->watchdog_pdeathsig != 0) {
    fprintf(stderr,
            "FAIL watchdog pid=%d ppid=%d pdeathsig=%d bootstrap=%d\n",
            mailbox->watchdog_pid, mailbox->watchdog_parent,
            mailbox->watchdog_pdeathsig, bootstrap);
    goto out;
  }

  atomic_store_explicit(&mailbox->command, COMMAND_EXIT,
                        memory_order_release);
  if (!wait_atomic(&mailbox->bootstrap_done, 1, 3000)) {
    fprintf(stderr, "FAIL watchdog/bootstrap exit handshake\n");
    goto out;
  }
  int status = 0;
  if (waitpid(bootstrap, &status, 0) != bootstrap ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "FAIL bootstrap status=0x%x\n", status);
    bootstrap = -1;
    goto out;
  }
  bootstrap = -1;
  if (!run_pdeathsig_probe()) {
    fprintf(stderr, "FAIL PDEATHSIG parent-death delivery\n");
    goto out;
  }
  if (!run_stop_resume_probe()) {
    fprintf(stderr, "FAIL SIGSTOP/WUNTRACED/SIGCONT mailbox handshake\n");
    goto out;
  }
  if (!run_inherited_pidfd_guard_probe()) {
    fprintf(stderr, "FAIL inherited outer-pidfd guardian observation\n");
    goto out;
  }
  printf("PASS _Fork mailbox pin_fd=%d bootstrap=%d watchdog=%d "
         "watchdog_pdeathsig=%d parent_death=SIGKILL stop_resume=PASS "
         "inherited_pidfd_guard=PASS\n",
         received_fd, mailbox->bootstrap_pid, mailbox->watchdog_pid,
         mailbox->watchdog_pdeathsig);
  result = 0;

out:
  if (bootstrap > 0) {
    atomic_store_explicit(&mailbox->command, COMMAND_EXIT,
                          memory_order_release);
    kill(bootstrap, SIGKILL);
    while (waitpid(bootstrap, NULL, 0) < 0 && errno == EINTR) {
    }
  }
  if (received_fd >= 0) {
    close(received_fd);
  }
  if (sockets[0] >= 0) {
    close(sockets[0]);
  }
  if (sockets[1] >= 0) {
    close(sockets[1]);
  }
  munmap(mailbox, sizeof(*mailbox));
  return result;
}
