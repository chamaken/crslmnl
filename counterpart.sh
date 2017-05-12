#!/bin/sh

UAPI_SRCDIR=$HOME/gitr/linux/include/uapi
LIBMNL_SRCDIR=$HOME/gitr/netfilter/libmnl
LIBMNL_SO=/usr/local/lib/libmnl.so

counter_sources() {
cat <<EOF
# UAPI
# linux UAPI
csrc/linux/netlink.h					$UAPI_SRCDIR/linux/netlink.h
csrc/linux/if_link.h                                    $UAPI_SRCDIR/linux/if_link.h
csrc/linux/rtnetlink.h                                  $UAPI_SRCDIR/linux/rtnetlink.h
csrc/linux/genetlink.h                                  $UAPI_SRCDIR/linux/genetlink.h
csrc/linux/if_addr.h                                    $UAPI_SRCDIR/linux/if_addr.h
csrc/linux/netfilter/nf_conntrack_common.h              $UAPI_SRCDIR/linux/netfilter/nf_conntrack_common.h
csrc/linux/netfilter/nf_conntrack_tcp.h                 $UAPI_SRCDIR/linux/netfilter/nf_conntrack_tcp.h
csrc/linux/netfilter/nfnetlink.h                        $UAPI_SRCDIR/linux/netfilter/nfnetlink.h
csrc/linux/netfilter/nfnetlink_compat.h                 $UAPI_SRCDIR/linux/netfilter/nfnetlink_compat.h
csrc/linux/netfilter/nfnetlink_conntrack.h              $UAPI_SRCDIR/linux/netfilter/nfnetlink_conntrack.h
csrc/linux/netfilter/nfnetlink_log.h                    $UAPI_SRCDIR/linux/netfilter/nfnetlink_log.h
csrc/linux/netfilter/nfnetlink_queue.h                  $UAPI_SRCDIR/linux/netfilter/nfnetlink_queue.h
csrc/linux/if.h                                         $UAPI_SRCDIR/linux/if.h
csrc/linux/netfilter.h                                  $UAPI_SRCDIR/linux/netfilter.h

# libmnl source
csrc/mnl/libmnl.h                                       $LIBMNL_SRCDIR/include/libmnl/libmnl.h
csrc/mnl/attr.c                                         $LIBMNL_SRCDIR/src/attr.c
csrc/mnl/socket.c                                       $LIBMNL_SRCDIR/src/socket.c
csrc/mnl/nlmsg.c                                        $LIBMNL_SRCDIR/src/nlmsg.c
csrc/mnl/callback.c                                     $LIBMNL_SRCDIR/src/callback.c

# libmnl examples
csrc/mnl/examples/netfilter/nfct-dump.c                 $LIBMNL_SRCDIR/examples/netfilter/nfct-dump.c
csrc/mnl/examples/netfilter/nfct-event.c                $LIBMNL_SRCDIR/examples/netfilter/nfct-event.c
csrc/mnl/examples/netfilter/nf-queue.c                  $LIBMNL_SRCDIR/examples/netfilter/nf-queue.c
csrc/mnl/examples/netfilter/nf-log.c                    $LIBMNL_SRCDIR/examples/netfilter/nf-log.c
csrc/mnl/examples/netfilter/nfct-daemon.c               $LIBMNL_SRCDIR/examples/netfilter/nfct-daemon.c
csrc/mnl/examples/netfilter/nfct-create-batch.c         $LIBMNL_SRCDIR/examples/netfilter/nfct-create-batch.c
csrc/mnl/examples/rtnl/rtnl-link-event.c                $LIBMNL_SRCDIR/examples/rtnl/rtnl-link-event.c
csrc/mnl/examples/rtnl/rtnl-addr-dump.c                 $LIBMNL_SRCDIR/examples/rtnl/rtnl-addr-dump.c
csrc/mnl/examples/rtnl/rtnl-link-dump.c                 $LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump.c
csrc/mnl/examples/rtnl/rtnl-route-add.c                 $LIBMNL_SRCDIR/examples/rtnl/rtnl-route-add.c
csrc/mnl/examples/rtnl/rtnl-route-event.c               $LIBMNL_SRCDIR/examples/rtnl/rtnl-route-event.c
csrc/mnl/examples/rtnl/rtnl-link-dump2.c                $LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump2.c
csrc/mnl/examples/rtnl/rtnl-route-dump.c                $LIBMNL_SRCDIR/examples/rtnl/rtnl-route-dump.c
csrc/mnl/examples/rtnl/rtnl-link-set.c                  $LIBMNL_SRCDIR/examples/rtnl/rtnl-link-set.c
csrc/mnl/examples/rtnl/rtnl-link-dump3.c                $LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump3.c
csrc/mnl/examples/kobject/kobject-event.c               $LIBMNL_SRCDIR/examples/kobject/kobject-event.c
csrc/mnl/examples/genl/genl-family-get.c                $LIBMNL_SRCDIR/examples/genl/genl-family-get.c
csrc/mnl/examples/genl/genl-group-events.c              $LIBMNL_SRCDIR/examples/genl/genl-group-events.c
EOF
}


libmnl_symbols() {
    nm -D --defined-only $LIBMNL_SO | awk '$2=="T" {print $3}' | sed -e 's/^mnl_//'
}

find src -name \*.h | while read i; do
    j=${i#src/}
    k=${j%/*}
    echo "pre:  $k"
    [ ${k##*/} = "ifh" ] && k=${k%h}
    diff -uw  $i ${UAPI_SRCDIR}/${k}.h
done

# libmnl_symbols | while read s; do
#     if ! grep $s src/lib.rs > /dev/null; then
# 	echo "not defined: $s"
#     fi
# done
