#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

static int copy_all(int source, int destination) {
  unsigned char buffer[16384];
  for (;;) {
    ssize_t got = read(source, buffer, sizeof(buffer));
    if (got == 0) {
      return 1;
    }
    if (got < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    size_t done = 0;
    while (done < (size_t)got) {
      ssize_t wrote = write(destination, buffer + done, (size_t)got - done);
      if (wrote < 0 && errno == EINTR) continue;
      if (wrote <= 0) return 0;
      done += (size_t)wrote;
    }
  }
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--sealed-child") == 0) {
    puts("sealed-memfd-exec=OK");
    return 0;
  }

  /* /proc/self/exe is intentionally a procfs symlink.  The production helper
   * source is opened by its real pathname with O_NOFOLLOW; this probe only
   * needs stable bytes for the memfd/exec mechanism itself. */
  int source = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (source < 0) {
    perror("open self");
    return 1;
  }
  int memfd = (int)syscall(__NR_memfd_create, "rmop-helper-probe",
                           MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
  if (memfd < 0) {
    perror("memfd_create MFD_EXEC");
    close(source);
    return 2;
  }
  int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_EXEC |
              F_SEAL_SEAL;
  if (!copy_all(source, memfd)) {
    perror("copy memfd");
    close(source);
    close(memfd);
    return 3;
  }
  if (fsync(memfd) != 0) {
    perror("fsync memfd");
    close(source);
    close(memfd);
    return 3;
  }
  struct stat memfd_stat;
  if (fstat(memfd, &memfd_stat) != 0) {
    perror("fstat memfd");
    close(source);
    close(memfd);
    return 3;
  }
  int initial_seals = fcntl(memfd, F_GET_SEALS);
  printf("memfd-before-seal uid=%u gid=%u mode=%03o size=%lld "
         "self=%u:%u initial-seals=%#x\n",
         (unsigned)memfd_stat.st_uid, (unsigned)memfd_stat.st_gid,
         memfd_stat.st_mode & 0777, (long long)memfd_stat.st_size,
         (unsigned)getuid(), (unsigned)getgid(), initial_seals);
  if (fcntl(memfd, F_ADD_SEALS, seals) != 0) {
    perror("F_ADD_SEALS memfd");
    close(source);
    close(memfd);
    return 3;
  }
  int actual_seals = fcntl(memfd, F_GET_SEALS);
  if (actual_seals < 0 || (actual_seals & seals) != seals) {
    perror("F_GET_SEALS memfd");
    close(source);
    close(memfd);
    return 3;
  }
  if (fstat(memfd, &memfd_stat) != 0) {
    perror("fstat sealed memfd");
    close(source);
    close(memfd);
    return 3;
  }
  printf("memfd-after-seal uid=%u gid=%u mode=%03o size=%lld seals=%#x\n",
         (unsigned)memfd_stat.st_uid, (unsigned)memfd_stat.st_gid,
         memfd_stat.st_mode & 0777, (long long)memfd_stat.st_size,
         actual_seals);
  close(source);

  char path[96];
  int length = snprintf(path, sizeof(path), "/proc/%ld/fd/%d",
                        (long)getpid(), memfd);
  if (length <= 0 || length >= (int)sizeof(path)) {
    close(memfd);
    return 4;
  }
  execl(path, path, "--sealed-child", (char *)NULL);
  fprintf(stderr, "sealed memfd exec failed: %s\n", strerror(errno));
  close(memfd);
  return 5;
}
