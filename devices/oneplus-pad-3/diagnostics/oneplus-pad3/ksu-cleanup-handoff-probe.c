#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* Non-root model of the two authenticated post-load handoffs. The production
 * filesystem/sysctl/SELinux operations stay device-only; this probe exercises
 * the proof algebra, every finalizer predicate, and partial-cleanup reentry. */

enum {
  PROBE_STATUS_EXEC = 12,
  PROBE_STATUS_CLEAN_ABORT = 23,
  PROBE_STATUS_CLEAN_SUCCESS = 24,
  PROBE_RESERVED_CLEAN_EXIT = 200,
  PROBE_RESERVED_SUCCESS_EXIT = 201,
};

enum success_predicate {
  SUCCESS_KSU_DOMAIN,
  SUCCESS_ROOT_IDENTITY,
  SUCCESS_DIGEST_BOUND,
  SUCCESS_MODULE_FLAG,
  SUCCESS_RUN_BOUND,
  SUCCESS_AUTHORITIES_PINNED,
  SUCCESS_INSTALLED_METADATA,
  SUCCESS_INSTALLED_HASH,
  SUCCESS_INSTALLED_INODE,
  SUCCESS_CURRENT_PATHS,
  SUCCESS_PRIVATE_RUN_CLEAN,
  SUCCESS_PRIVATE_RUN_DURABLE,
  SUCCESS_KSU_INFO,
  SUCCESS_KSU_UAPI,
  SUCCESS_KSU_LKM,
  SUCCESS_KSU_LATE_LOAD,
  SUCCESS_TRUSTED_RECEIPT,
  SUCCESS_PUBLIC_RECEIPT,
  SUCCESS_KPTR_ORIGINAL,
  SUCCESS_ENFORCING_ONE,
  SUCCESS_PREDICATE_COUNT,
};

struct proof_mailbox {
  atomic_int cleanup_proven;
  atomic_int success_proven;
  atomic_int worker_dead;
};

static int simulated_cleanup_exit(int ksu_domain, int root_identity,
                                  int digest_pinned, int cleanup_modules,
                                  int module_flag_bound, int run_bound,
                                  int authorities_pinned,
                                  int original_kptr_bound, int kptr_exact,
                                  int trusted_absent, int public_absent,
                                  int private_run_clean, int enforcing_exact) {
  int receipt_contract =
      !cleanup_modules || (run_bound && trusted_absent && public_absent);
  return ksu_domain && root_identity && digest_pinned && module_flag_bound &&
                 authorities_pinned && receipt_contract &&
                 original_kptr_bound && kptr_exact && private_run_clean &&
                 enforcing_exact
             ? PROBE_RESERVED_CLEAN_EXIT
             : 1;
}

static int simulated_success_exit(const int predicates[SUCCESS_PREDICATE_COUNT],
                                  int modules) {
  for (int i = 0; i < SUCCESS_PREDICATE_COUNT; i++) {
    if (!modules && (i == SUCCESS_RUN_BOUND ||
                     i == SUCCESS_TRUSTED_RECEIPT ||
                     i == SUCCESS_PUBLIC_RECEIPT)) {
      continue;
    }
    if (!predicates[i]) {
      return 1;
    }
  }
  return PROBE_RESERVED_SUCCESS_EXIT;
}

static int reap_exact_loader(struct proof_mailbox *mailbox,
                             pid_t expected_loader, pid_t waited_loader,
                             int exec_error_bytes, int exited,
                             int exit_status, int cleanup_handoff_expected) {
  if (waited_loader != expected_loader || exec_error_bytes != 0 || !exited ||
      !cleanup_handoff_expected) {
    return PROBE_STATUS_EXEC;
  }
  if (exit_status == PROBE_RESERVED_CLEAN_EXIT) {
    atomic_store_explicit(&mailbox->cleanup_proven, 1,
                          memory_order_release);
    return PROBE_STATUS_CLEAN_ABORT;
  }
  if (exit_status == PROBE_RESERVED_SUCCESS_EXIT) {
    atomic_store_explicit(&mailbox->success_proven, 1,
                          memory_order_release);
    return PROBE_STATUS_CLEAN_SUCCESS;
  }
  /* Generic exit 0 is deliberately not success. */
  return PROBE_STATUS_EXEC;
}

static int watcher_ack(const struct proof_mailbox *mailbox) {
  int dead = atomic_load_explicit(&mailbox->worker_dead,
                                  memory_order_acquire) == 1;
  int cleanup = atomic_load_explicit(&mailbox->cleanup_proven,
                                     memory_order_acquire) == 1;
  int success = atomic_load_explicit(&mailbox->success_proven,
                                     memory_order_acquire) == 1;
  if (!dead || cleanup == success) {
    return 0;
  }
  return success ? 2 : 1; /* FINAL : ABORT_CLEAN */
}

static int parent_pair_exact(const struct proof_mailbox *mailbox, int status) {
  int cleanup = atomic_load_explicit(&mailbox->cleanup_proven,
                                     memory_order_acquire) == 1;
  int success = atomic_load_explicit(&mailbox->success_proven,
                                     memory_order_acquire) == 1;
  return cleanup != success &&
         ((cleanup && status == PROBE_STATUS_CLEAN_ABORT) ||
          (success && status == PROBE_STATUS_CLEAN_SUCCESS));
}

static int exact_ksu_selinux_context_bytes(const unsigned char *context,
                                           size_t length) {
  static const unsigned char expected[] = "u:r:ksu:s0";
  return length == sizeof(expected) &&
         memcmp(context, expected, sizeof(expected)) == 0;
}

static int run_exact_selinux_context_bytes(void) {
  static const unsigned char exact[] = "u:r:ksu:s0";
  static const unsigned char newline[] = "u:r:ksu:s0\n";
  static const unsigned char double_nul[] = "u:r:ksu:s0\0";
  static const unsigned char suffix[] = "u:r:ksu:s0\0suffix";
  return exact_ksu_selinux_context_bytes(exact, sizeof(exact)) &&
         !exact_ksu_selinux_context_bytes(exact, sizeof(exact) - 1) &&
         !exact_ksu_selinux_context_bytes(newline, sizeof(newline)) &&
         !exact_ksu_selinux_context_bytes(double_nul, sizeof(double_nul)) &&
         !exact_ksu_selinux_context_bytes(suffix, sizeof(suffix));
}

static void init_mailbox(struct proof_mailbox *mailbox, int worker_dead) {
  atomic_init(&mailbox->cleanup_proven, 0);
  atomic_init(&mailbox->success_proven, 0);
  atomic_init(&mailbox->worker_dead, worker_dead);
}

static int run_cleanup_exact_handoff(void) {
  struct proof_mailbox mailbox;
  init_mailbox(&mailbox, 0);
  int cleanup_exit = simulated_cleanup_exit(
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
  int status =
      reap_exact_loader(&mailbox, 4101, 4101, 0, 1, cleanup_exit, 1);
  int premature = watcher_ack(&mailbox);
  atomic_store_explicit(&mailbox.worker_dead, 1, memory_order_release);
  return status == PROBE_STATUS_CLEAN_ABORT && !premature &&
         watcher_ack(&mailbox) == 1 && parent_pair_exact(&mailbox, status);
}

static int run_success_exact_handoff(void) {
  int predicates[SUCCESS_PREDICATE_COUNT];
  for (int i = 0; i < SUCCESS_PREDICATE_COUNT; i++) predicates[i] = 1;
  struct proof_mailbox mailbox;
  init_mailbox(&mailbox, 0);
  int status = reap_exact_loader(
      &mailbox, 4201, 4201, 0, 1,
      simulated_success_exit(predicates, 1), 1);
  int premature = watcher_ack(&mailbox);
  atomic_store_explicit(&mailbox.worker_dead, 1, memory_order_release);
  return status == PROBE_STATUS_CLEAN_SUCCESS && !premature &&
         watcher_ack(&mailbox) == 2 && parent_pair_exact(&mailbox, status);
}

static int run_authentication_rejections(void) {
  struct proof_mailbox mailbox;
  init_mailbox(&mailbox, 1);
  int wrong_pid = reap_exact_loader(&mailbox, 1, 2, 0, 1,
                                    PROBE_RESERVED_SUCCESS_EXIT, 1) ==
                  PROBE_STATUS_EXEC;
  int exec_error = reap_exact_loader(&mailbox, 1, 1, 4, 1,
                                     PROBE_RESERVED_SUCCESS_EXIT, 1) ==
                   PROBE_STATUS_EXEC;
  int exit0 = reap_exact_loader(&mailbox, 1, 1, 0, 1, 0, 1) ==
              PROBE_STATUS_EXEC;
  int signalled = reap_exact_loader(&mailbox, 1, 1, 0, 0,
                                    PROBE_RESERVED_SUCCESS_EXIT, 1) ==
                  PROBE_STATUS_EXEC;
  int unexpected = reap_exact_loader(&mailbox, 1, 1, 0, 1,
                                     PROBE_RESERVED_SUCCESS_EXIT, 0) ==
                   PROBE_STATUS_EXEC;
  return wrong_pid && exec_error && exit0 && signalled && unexpected &&
         watcher_ack(&mailbox) == 0;
}

static int run_cleanup_fault_rejections(void) {
  for (int missing = 0; missing < 12; missing++) {
    int predicates[12];
    for (int i = 0; i < 12; i++) predicates[i] = 1;
    predicates[missing] = 0;
    if (simulated_cleanup_exit(
            predicates[0], predicates[1], predicates[2], 1,
            predicates[3], predicates[4], predicates[5], predicates[6],
            predicates[7], predicates[8], predicates[9], predicates[10],
            predicates[11]) == PROBE_RESERVED_CLEAN_EXIT) {
      return 0;
    }
  }
  return simulated_cleanup_exit(1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1) ==
         PROBE_RESERVED_CLEAN_EXIT;
}

static int run_success_fault_rejections(void) {
  int predicates[SUCCESS_PREDICATE_COUNT];
  for (int missing = 0; missing < SUCCESS_PREDICATE_COUNT; missing++) {
    for (int i = 0; i < SUCCESS_PREDICATE_COUNT; i++) predicates[i] = 1;
    predicates[missing] = 0;
    if (simulated_success_exit(predicates, 1) ==
        PROBE_RESERVED_SUCCESS_EXIT) {
      return 0;
    }
  }
  return 1;
}

static int cleanup_private_run_model(int *nlink, int *exec_name,
                                     int *run_name, int fail_after_unlink) {
  if (*nlink == 2 && *exec_name) {
    *exec_name = 0;
    *nlink = 1;
    if (fail_after_unlink) return 0;
  } else if (!(*nlink == 1 && !*exec_name)) {
    return 0;
  }
  if (*run_name) *run_name = 0;
  return *nlink == 1 && !*exec_name && !*run_name;
}

static int run_partial_success_abort_reentry(void) {
  int nlink = 2, exec_name = 1, run_name = 1;
  int first = cleanup_private_run_model(&nlink, &exec_name, &run_name, 1);
  int second = cleanup_private_run_model(&nlink, &exec_name, &run_name, 0);
  int abort_exit = simulated_cleanup_exit(
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, second, 1);
  return !first && second && abort_exit == PROBE_RESERVED_CLEAN_EXIT;
}

static int run_status_proof_mismatch_rejections(void) {
  struct proof_mailbox mailbox;
  init_mailbox(&mailbox, 1);
  atomic_store_explicit(&mailbox.success_proven, 1, memory_order_release);
  int wrong_status = !parent_pair_exact(&mailbox, PROBE_STATUS_CLEAN_ABORT);
  atomic_store_explicit(&mailbox.cleanup_proven, 1, memory_order_release);
  int double_proof = !parent_pair_exact(&mailbox, PROBE_STATUS_CLEAN_SUCCESS) &&
                     watcher_ack(&mailbox) == 0;
  return wrong_status && double_proof;
}

static int run_success_watcher_delayed_ack(void) {
  int status = PROBE_STATUS_CLEAN_SUCCESS;
  int lock_held = 1;
  int returned = 0;
  for (int delayed = 0; delayed < 4; delayed++) {
    /* A delayed FINAL acknowledgement cannot normalize or release early. */
    if (status != PROBE_STATUS_CLEAN_SUCCESS || !lock_held || returned) {
      return 0;
    }
  }
  int ack = 2; /* LATE_LOAD_WATCH_ACK_FINAL */
  if (ack == 2) {
    status = 0;
    returned = 1;
    lock_held = 0;
  }
  return status == 0 && returned && !lock_held;
}

static int run_success_watcher_bad_ack_fail_stop(void) {
  int status = PROBE_STATUS_CLEAN_SUCCESS;
  int lock_held = 1;
  int returned = 0;
  int ack = 1; /* ABORT_CLEAN is invalid for a reserved-201 proof. */
  if (ack == 2) {
    status = 0;
    returned = 1;
    lock_held = 0;
  }
  return status == PROBE_STATUS_CLEAN_SUCCESS && lock_held && !returned;
}

static int run_panic_abort_false_proof_case(void) {
  struct proof_mailbox mailbox;
  init_mailbox(&mailbox, 1);
  int status = reap_exact_loader(&mailbox, 1, 1, 0, 0, 134, 1);
  return status == PROBE_STATUS_EXEC && watcher_ack(&mailbox) == 0;
}

int main(void) {
  int cleanup = run_cleanup_exact_handoff();
  int success = run_success_exact_handoff();
  int authentication = run_authentication_rejections();
  int cleanup_faults = run_cleanup_fault_rejections();
  int success_faults = run_success_fault_rejections();
  int reentry = run_partial_success_abort_reentry();
  int mismatch = run_status_proof_mismatch_rejections();
  int delayed_ack = run_success_watcher_delayed_ack();
  int bad_ack = run_success_watcher_bad_ack_fail_stop();
  int panic_abort = run_panic_abort_false_proof_case();
  int exact_context = run_exact_selinux_context_bytes();
  printf("ksu_cleanup_exact_handoff=%s\n", cleanup ? "PASS" : "FAIL");
  printf("ksu_success_exact_handoff=%s\n", success ? "PASS" : "FAIL");
  printf("ksu_success_exit0_rejected=%s\n", authentication ? "PASS" : "FAIL");
  printf("ksu_cleanup_fault_rejections=%s\n", cleanup_faults ? "PASS" : "FAIL");
  printf("ksu_success_fault_rejections=%s\n", success_faults ? "PASS" : "FAIL");
  printf("ksu_success_partial_abort_reentry=%s\n", reentry ? "PASS" : "FAIL");
  printf("ksu_status_proof_mismatch_rejections=%s\n", mismatch ? "PASS" : "FAIL");
  printf("ksu_success_watcher_delayed_ack=%s\n", delayed_ack ? "PASS" : "FAIL");
  printf("ksu_success_watcher_bad_ack_fail_stop=%s\n", bad_ack ? "PASS" : "FAIL");
  printf("ksu_cleanup_panic_abort_false_proof=%s\n", panic_abort ? "PASS" : "FAIL");
  printf("ksu_selinux_context_exact_bytes=%s\n", exact_context ? "PASS" : "FAIL");
  return cleanup && success && authentication && cleanup_faults &&
                 success_faults && reentry && mismatch && delayed_ack &&
                 bad_ack && panic_abort && exact_context
             ? 0
             : 2;
}
