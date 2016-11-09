#ifndef _V4V_RING_H_
# define _V4V_RING_H_

#include <linux/skbuff.h>

#include <xen/v4v.h>

/*
 * Structure for ring management.
 */
typedef int (*v4v_recv_skb_cb)(void *priv, struct sk_buff *skb);
struct v4v_ring_hnd {
	struct list_head l;
	spinlock_t ring_lock;
	struct v4v_ring *ring;
	struct v4v_pfn_list *pfns;
	v4v_recv_skb_cb recv_cb;
	void *priv;		/* Passed to recv_cb as private argument. */
};

/* Messages on the ring are padded to 128 bits. */
#define V4V_RING_MAX_SIZE   (PAGE_SIZE * 4)

void v4v_ring_handle_free(struct v4v_ring_hnd *ring);
struct v4v_ring_hnd *v4v_ring_handle_alloc(unsigned int domain, unsigned int port, size_t len);

void v4v_ring_unregister(struct v4v_ring_hnd *ring);
int v4v_ring_register(struct v4v_ring_hnd *h, v4v_recv_skb_cb recv_cb, void *priv);

int v4v_ring_send_skb(struct v4v_ring_hnd *ring, const struct sk_buff *skb, unsigned int domain, unsigned int port);

int v4v_core_init(void);
void v4v_core_cleanup(void);

/*
 * Debugging stuffs...
 */
#define DPRINTK(fmt, ...) \
	pr_info(DTAG":%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

static inline void dprinthex(unsigned char *b, size_t len)
{
	size_t i;

	if (!b || !len)
		return;

	printk(KERN_INFO "%02x", b[0]);
	for (i = 1; i < len; ++i) {
		if (!(i % 16)) {
			printk(KERN_CONT "\n");
			printk(KERN_INFO "%02x", b[i]);
		} else if (!(i % 8)) {
			printk(KERN_CONT "  %02x", b[i]);
		} else
			printk(KERN_CONT " %02x", b[i]);
	}
	printk(KERN_CONT "\n");
}

static inline void dprint_ring(const struct v4v_ring_hnd *h)
{
	const struct v4v_ring *r = h->ring;
	size_t rx = r->rx_ptr;
	size_t tx = r->tx_ptr;

	pr_info("ring: { .id=dom%u:%u->%u .len=%u .rx=%zu .tx=%zu }\n",
		r->id.addr.domain, r->id.addr.port, r->id.partner,
		r->len, rx, tx);

#if 0
	if (rx < tx)
		dprinthex((void*)&r->ring[rx], tx - rx);
	else {
		dprinthex((void*)&r->ring[rx], r->len - rx);
		dprinthex((void*)&r->ring[0], tx);
	}
#endif
}


#endif /* !_V4V_RING_H_ */

