#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <libmnl/libmnl.h>

#define EXPORT_SYMBOL(x)

/**
 * mnl_nlmsg_put_header_check - reserve and prepare room for Netlink header
 * \param buf memory already allocated to store the Netlink header
 * \param buflen size of buffer which stores the message
 *
 * This function first checks that the Netlink header can be added to the memory
 * buffer passed as parameterthen sets to zero the buffer that is required to
 * put the Netlink header in it. This function also initializes the nlmsg_len
 * field to the size of the Netlink header. This function returns a pointer to
 * the Netlink header structure.
 * This function returns NULL on error and errno is set to EINVAL.
 */
EXPORT_SYMBOL(mnl_nlmsg_put_header_check);
struct nlmsghdr *mnl_nlmsg_put_header_check(void *buf, size_t buflen)
{
        if (buflen < MNL_NLMSG_HDRLEN) {
                errno = EINVAL;
                return NULL;
        }

        return mnl_nlmsg_put_header(buf);
}

/**
 * mnl_nlmsg_put_extra_header_check - reserve and prepare room for an extra header
 * \param nlh pointer to Netlink header
 * \param buflen size of buffer which stores the message
 * \param size size of the extra header that we want to put
 *
 * This function first checks the room that is required to put the extra header
 * after the initial Netlink header can be added (fits into the buffer) and then
 * sets to zero the room. This function also increases the nlmsg_len field. You
 * have to invoke mnl_nlmsg_put_header() before you call this function. This
 * function returns a pointer to the extra header.
 * This function returns NULL on error and errno is set to EINVAL.
 */
EXPORT_SYMBOL(mnl_nlmsg_put_extra_header_check);
void *mnl_nlmsg_put_extra_header_check(struct nlmsghdr *nlh, size_t buflen, size_t size)
{
        if (nlh->nlmsg_len + MNL_ALIGN(size) > buflen) {
                errno = EINVAL;
                return NULL;
        }

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

/**
 * mnl_nlmsg_batch_rest - get the rest of the batch buffer size
 * \param b pointer to batch
 *
 * This function returns the rest of the batch buffer size
 */
EXPORT_SYMBOL(mnl_nlmsg_batch_rest);
size_t mnl_nlmsg_batch_rest(const struct mnl_nlmsg_batch *b)
{
        return b->limit - b->buflen;
}

/*
 * Belows will not be merged to master.
 * Assume never overflow buffer.
 */
struct nlmsghdr *rsmnl_nlmsg_batch_next(struct mnl_nlmsg_batch *b)
{
	struct nlmsghdr *nlh = b->cur;

        if (b->buflen + nlh->nlmsg_len + MNL_NLMSG_HDRLEN > b->limit)
                return NULL;

        b->cur = b->buf + b->buflen + nlh->nlmsg_len;
	b->buflen += nlh->nlmsg_len;

        return (struct nlmsghdr *)b->cur;
}

/* adding clearing buffer to the original */
struct mnl_nlmsg_batch *rsmnl_nlmsg_batch_start(void *buf, size_t limit)
{
	struct mnl_nlmsg_batch *b;

	b = malloc(sizeof(struct mnl_nlmsg_batch));
	if (b == NULL)
		return NULL;

	b->buf = buf;
	b->limit = limit;
	b->buflen = 0;
	b->cur = buf;
	b->overflow = false;
        memset(b->buf, 0, b->limit);

	return b;
}

/* adding clearing buffer to the original */
void rsmnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)
{
	if (b->overflow) {
		struct nlmsghdr *nlh = b->cur;
		memcpy(b->buf, b->cur, nlh->nlmsg_len);
		b->buflen = nlh->nlmsg_len;
		b->cur = b->buf + b->buflen;
		b->overflow = false;
		memset(b->buf + b->buflen, 0, b->limit - b->buflen);
	} else {
		b->buflen = 0;
		b->cur = b->buf;
                memset(b->buf, 0, b->limit);
	}
}

/**
 * rsmnl_nlmsg_batch_laden_cap - cap the struct if nonempty
 * \param b pointer to batch
 *
 * This function is assumed to be used by crslmnl only, which
 * must not overflow the buffer since nlmsghdr returned by
 * NlmsgBatch Iterator has length acquired by mnl_nlmsg_batch_rest().
 * Otherwise, this function abort.
 *
 * The function do nothing and return false if the buffer is empty,
 * or set proper values then return true.
 */
bool rsmnl_nlmsg_batch_laden_cap(struct mnl_nlmsg_batch *b)
{
	struct nlmsghdr *nlh = b->cur;

	if (b->buflen == 0)
                return false;

        assert(b->buflen + nlh->nlmsg_len <= b->limit);

        b->cur = b->buf + b->buflen + nlh->nlmsg_len;
	b->buflen += nlh->nlmsg_len;

        return true;
}
