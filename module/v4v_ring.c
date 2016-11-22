#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>

#include <xen/events.h>
#include <xen/page.h>

#define DTAG "V4V-RING"
#include "v4v_ring.h"

/*
 * Global ring list.
 */
struct list_head v4v_rings;
rwlock_t v4v_rings_lock;

/*
 * Helpers for ring management with the hypervisor.
 */
static void v4v_ring_free(struct v4v_ring *ring)
{
	vfree(ring);
}
static struct v4v_ring *v4v_ring_alloc(unsigned int domain,
	unsigned int port, size_t len)
{
	struct v4v_ring *ring;

	if (len > V4V_RING_MAX_SIZE)
		return ERR_PTR(-E2BIG);
	if (len != V4V_ROUNDUP(len))
		return ERR_PTR(-EINVAL);

	ring = vmalloc(sizeof (*ring) + len);
	if (!ring)
		return ERR_PTR(-ENOMEM);

	ring->magic = V4V_RING_MAGIC;
	ring->id.partner = domain;
	ring->id.addr.domain = V4V_DOMID_ANY;
	ring->id.addr.port = port;
	ring->len = len;
	ring->rx_ptr = 0;
	ring->tx_ptr = 0;
	//memset(ring->ptr, 0, len);

	return ring;
}

static void v4v_pfn_list_free(struct v4v_pfn_list *pfns)
{
	kfree(pfns);
}
static struct v4v_pfn_list *v4v_pfn_list_alloc(volatile void *ring_ptr, size_t npages)
{
	struct v4v_pfn_list *pfns;
	unsigned char *p = (void*)ring_ptr;	// Only used for aritmetic.
	size_t i;

	pfns = kmalloc(sizeof (*pfns) +
		npages * sizeof (pfns->pages[0]), GFP_KERNEL);
	if (!pfns)
		return ERR_PTR(-ENOMEM);

	pfns->magic = V4V_PFN_LIST_MAGIC;
	pfns->npage = npages;
	for (i = 0; i < npages; ++i)
		pfns->pages[i] = pfn_to_mfn(vmalloc_to_pfn(p + i * PAGE_SIZE));

	return pfns;
}

/*
 * Ring interface.
 */
void v4v_ring_handle_free(struct v4v_ring_hnd *h)
{
	list_del(&h->l);

	v4v_pfn_list_free(h->pfns);
	v4v_ring_free(h->ring);

	kfree(h);
}

struct v4v_ring_hnd *v4v_ring_handle_alloc(unsigned int domain, unsigned int port,
	size_t len)
{
	struct v4v_ring_hnd *h;
	size_t npages = (len + sizeof (*(h->ring)) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	int rc;

	h = kmalloc(sizeof (*h), GFP_KERNEL);
	if (!h)
		return ERR_PTR(-ENOMEM);

	h->ring = v4v_ring_alloc(domain, port, len);
	if (!h->ring) {
		rc = PTR_ERR(h->ring);
		goto failed_ring;
	}

	h->pfns = v4v_pfn_list_alloc(h->ring->ring, npages);
	if (!h->pfns) {
		rc = PTR_ERR(h->pfns);
		goto failed_pfns;
	}

	spin_lock_init(&h->ring_lock);
	write_lock(&v4v_rings_lock);
	list_add_tail(&h->l, &v4v_rings);
	write_unlock(&v4v_rings_lock);

	DPRINTK("ring(dom%u:%u): %zuB, estimated %zu pages.",
		domain, port, len, npages);

	return h;

failed_pfns:
	v4v_ring_free(h->ring);
	h->ring = NULL;
failed_ring:
	kfree(h);
	return ERR_PTR(rc);
}

void v4v_ring_unregister(struct v4v_ring_hnd *h)
{
	int rc;

	if (!h->ring || !h->pfns)
		return;

	rc = HYPERVISOR_v4v_op(V4VOP_unregister_ring, h->ring, h->pfns,
				NULL, 0, 0);
	if (rc)
		pr_warn("Failed to unregister v4v ring with hypervisor "
				"for dom%u port %u (%d).\n",
			h->ring->id.partner, h->ring->id.addr.port, rc);
	else
		pr_info("Un-registered v4v ring with hypervisor for "
				"dom%u port %u.\n",
			h->ring->id.partner, h->ring->id.addr.port);
}

int v4v_ring_register(struct v4v_ring_hnd *h, v4v_recv_skb_cb recv_cb, void *priv)
{
	int rc;

	h->recv_cb = recv_cb;
	h->priv = priv;

	rc = HYPERVISOR_v4v_op(V4VOP_register_ring, h->ring, h->pfns,
				NULL, 0, 0);
	if (rc)
		pr_warn("Failed to register v4v ring with hypervisor "
			"for dom%u port %u (%d).\n",
			h->ring->id.partner, h->ring->id.addr.port, rc);
	else
		pr_info("Registered v4v ring with hypervisor for "
			"dom%u port %u.\n",
			h->ring->id.partner, h->ring->id.addr.port);
	return rc;
}

/*
 * Ring data handling helpers.
 */
// TODO: These two function should return only aligned size.
static inline size_t v4v_ring_has_data_no_wrap(const struct v4v_ring_hnd *ring)
{
	const struct v4v_ring *r = ring->ring;
	const size_t rx = r->rx_ptr;
	const size_t tx = r->tx_ptr;

	if (rx > tx)
		return r->len - rx;
	return rx - tx;
}

static inline size_t v4v_ring_has_data(const struct v4v_ring_hnd *ring)
{
	const struct v4v_ring *r = ring->ring;
	const size_t rx = r->rx_ptr;
	const size_t tx = r->tx_ptr;

	if (rx > tx)
		return r->len - (rx - tx);
	return tx - rx;
}

static inline size_t v4v_ring_has_space(const struct v4v_ring_hnd *ring)
{
	const struct v4v_ring *r = ring->ring;

	return r->len - v4v_ring_has_data(ring);
}

static inline const void *v4v_ring_peek_no_wrap(const struct v4v_ring_hnd *ring, size_t len)
{
	const struct v4v_ring *r = ring->ring;
	const size_t rx = r->rx_ptr;

	/* Not enough data before ring wrap. */
	if (len > v4v_ring_has_data_no_wrap(ring))
		return NULL;

	/* /!\ We return a pointer to shared ring memory. */
	return (void *)&r->ring[rx];
}

static int v4v_ring_recv(struct v4v_ring_hnd *h, void *buf, size_t len)
{
	struct v4v_ring *r = h->ring;
	unsigned char *p = buf;
	size_t chunk;
	size_t rx = r->rx_ptr;

	/* TODO: Support incomplete read? */
	if (len > v4v_ring_has_data(h))
		return -E2BIG;

	//dprint_ring(h);
	chunk = v4v_ring_has_data_no_wrap(h);
	if (len >= chunk) {
		memcpy(p, (void*)&r->ring[rx], chunk);
		memcpy(&p[chunk], (void*)&r->ring[0], len - chunk); /* Should handle (len == chunk). */
		rx = V4V_ROUNDUP(len - chunk);	/* Account for message padding. */
	} else {
		memcpy(p, (void*)&r->ring[rx], len);
		rx += V4V_ROUNDUP(len);	/* Account for message padding. */
	}

	mb();	// Commit all writes before updating the ring.
	r->rx_ptr = rx;

	//dprint_ring(h);

	return len;
}

static struct sk_buff *v4v_ring_recv_skb(struct v4v_ring_hnd *ring)
{
	const struct v4v_ring_msghdr *mh;
	struct sk_buff *skb;
	size_t msg_len;
	int rc = 0;

	/* See v4v_handle_rx(). There is at least sizeof (*mh) data. */
	skb = alloc_skb(sizeof (*mh), GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/* TODO: REMOVE. Tasklet is only scheduled once, even on SMP. */
	spin_lock(&ring->ring_lock);
	/* Fetch message header. */
	v4v_ring_recv(ring, skb_put(skb, sizeof (*mh)), sizeof (*mh));

	mh = (void*)skb->data;
	msg_len = mh->len - sizeof (*mh);

	//DPRINTK("packet from dom%u:%u, %#08x payload:%zuB (packet:%uB, round-up:%uB).",
	//	mh->source.domain, mh->source.port, mh->protocol, msg_len, mh->len, V4V_ROUNDUP(mh->len));
	if (msg_len > v4v_ring_has_data(ring)) {
		DPRINTK("Not enough data in V4V ring to fetch the entire message.");
		rc = E2BIG;
		goto out;
	}

	/* XXX: (msg_len == 0) should not happen, but nothing prevents it. */
	if (unlikely(msg_len)) {
		/* Fetch message content, if any. */
		if (pskb_expand_head(skb, 0, msg_len, GFP_ATOMIC)) {
			DPRINTK("Could not allocate the skb to copy the message.");
			rc = ENOMEM;
			goto out;
		}
		v4v_ring_recv(ring, skb_put(skb, msg_len), msg_len);
	}
	spin_unlock(&ring->ring_lock);

	return skb;

out:
	spin_unlock(&ring->ring_lock);
	kfree_skb(skb);
	return ERR_PTR(-rc);
}

/*
 * TODO: Refactor to send some datagram of ours... Like v4v_ring_msghdr, that sounds just fine.
 */
int v4v_ring_send_skb(struct v4v_ring_hnd *ring,
	const struct sk_buff *skb, unsigned int domain, unsigned int port)
{
	struct v4v_addr peer = {
		.port = port,
		.domain = domain
	};
	int rc;

	//DPRINTK("(dom%u:%u) has %zuB left, sending %uB payload (with hdr:%luB, round-up:%luB).",
	//	domain, port, v4v_ring_has_space(ring), skb->len,
	//	skb->len + sizeof (struct v4v_ring_msghdr),
	//	V4V_ROUNDUP(skb->len + sizeof (struct v4v_ring_msghdr)));
	if (v4v_ring_has_space(ring) < V4V_ROUNDUP(skb->len + sizeof (struct v4v_ring_msghdr)))
		return -ENOBUFS;

	//dprinthex(skb->data, skb->len);
	rc = HYPERVISOR_v4v_op(V4VOP_send, &ring->ring->id.addr, &peer,
			skb->data, skb->len, /* TODO: Change this misery */ V4V_PROTO_DGRAM);
	if (rc < 0)
		pr_warn("Failed to send packet (%uB) over V4V to dom%u:%u (%d).\n",
			skb->len, domain, port, -rc);

	return rc;
}


/*
 * Tasklet for packet handling.
 */
static void v4v_handle_rx(void)
{
	struct v4v_ring_hnd *r, *tmp;
	bool notify = false;
	int rc;

	read_lock(&v4v_rings_lock);
	list_for_each_entry_safe(r, tmp, &v4v_rings, l) {
		while (v4v_ring_has_data(r) >= sizeof (struct v4v_ring_msghdr)) {
			struct sk_buff *skb;

			skb = v4v_ring_recv_skb(r);
			if (IS_ERR(skb)) {
				pr_warn("Failed to retrieve packet "
					"from V4V ring (%ld).\n", -PTR_ERR(skb));
				break;
			}
			rc = r->recv_cb(r->priv, skb);
			if (rc) {
				pr_warn("Failed to queue received packet, dropping.\n");
				kfree_skb(skb);
				break;
			}
			notify = true;
		}
		//else
		//	DPRINTK("No data for ring { dom%u:%u -> %u }...",
		//		r->ring->id.addr.domain, r->ring->id.addr.port,
		//		r->ring->id.partner);
	}
	read_unlock(&v4v_rings_lock);
}

static void v4v_handle_event(unsigned long data)
{
	v4v_handle_rx();
}
DECLARE_TASKLET(v4v_event, v4v_handle_event, 0);

/*
 * V4V IRQ handler.
 */
static irqreturn_t v4v_interrupt_handler(int irq, void *devid)
{
	(void) irq;
	(void) devid;
	/* Defer to bottom-half tasklet. */
	tasklet_schedule(&v4v_event);
	return IRQ_HANDLED;
}

/*
 * Initialisation and cleanup of vIRQ.
 */
static int v4v_irq = -1;
int v4v_core_init(void)
{
	int rc;

	INIT_LIST_HEAD(&v4v_rings);
	rwlock_init(&v4v_rings_lock);

	rc = bind_virq_to_irqhandler(VIRQ_V4V, 0, v4v_interrupt_handler, 0,
		"v4v", NULL);
	if (rc < 0)
		return rc;

	v4v_irq = rc;
	return 0;
}

void v4v_core_cleanup(void)
{
	unbind_from_irqhandler(v4v_irq, NULL);
}

