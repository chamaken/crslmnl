#include <stddef.h>
#include <stdbool.h>
#include <libmnl/libmnl.h>

struct nlmsghdr *mnl_nlmsg_put_header_check(void *buf, size_t buflen)
{
        if (MNL_NLMSG_HDRLEN < buflen)
                return NULL;

        return mnl_nlmsg_put_header(buf);
}

void *mnl_nlmsg_put_extra_header_check(struct nlmsghdr *nlh, size_t buflen, size_t size)
{
        if (nlh->nlmsg_len + MNL_ALIGN(size) > buflen)
                return NULL;

        return mnl_nlmsg_put_extra_header(nlh, size);
}

struct mnl_nlmsg_batch {
	/* the buffer that is used to store the batch. */
	void *buf;
	size_t limit;
	size_t buflen;
	/* the current netlink message in the batch. */
	void *cur;
	bool overflow;
};

size_t mnl_nlmsg_batch_rest(const struct mnl_nlmsg_batch *b)
{
        return b->limit - b->buflen;
}
