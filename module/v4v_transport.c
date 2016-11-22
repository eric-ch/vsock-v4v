#include <linux/types.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/random.h>

#include <net/sock.h>
#include <net/af_vsock.h>
#include <net/vsock_addr.h>

#define DTAG "V4V-TRANS"
#include "v4v_ring.h"

/*
 * V4V private data.
 */
struct v4v_transport {
	struct list_head sockets;	// List of all v4v_transport.
	unsigned int id;		// Randomly generated connection id.
	struct v4v_ring_hnd *ring;	// V4V ring handle.
	struct vsock_sock *vsk;		// Parent vsock structure.
};

/*
 * Global sockets list.
 */
struct list_head sockets = LIST_HEAD_INIT(sockets);

/*
 * Private data helpers.
 */
#define v4v_trans(vsk)	((struct v4v_transport *)((vsk)->trans))
#define v4v_vsock(v4t)	(v4t->vsk)

/*
 * Initialize/tear-down socket.
 */
static int v4v_transport_socket_init(
	struct vsock_sock *vsk, struct vsock_sock *psk)
{
	vsk->trans = kmalloc(sizeof (struct v4v_transport), GFP_KERNEL);
	if (!vsk->trans)
		return -ENOMEM;
	INIT_LIST_HEAD(&v4v_trans(vsk)->sockets);
	list_add_tail(&v4v_trans(vsk)->sockets, &sockets);
	v4v_trans(vsk)->id = prandom_u32();
	v4v_trans(vsk)->vsk = vsk;   // Avoid state duplication, but that might be a mistake.
	v4v_trans(vsk)->ring = NULL;

	return 0;
}

static void v4v_transport_destruct(struct vsock_sock *vsk)
{
	v4v_trans(vsk)->vsk = NULL;
	list_del_init(&v4v_trans(vsk)->sockets);
	kfree(v4v_trans(vsk));
	vsk->trans = NULL;

	return;
}

static void v4v_transport_release(struct vsock_sock *vsk)
{
	struct v4v_transport *t = v4v_trans(vsk);

	vsock_remove_sock(vsk);

	/*
	 * Disconnect/detach before actual destruction of resources
	 * TODO: Send RST to peer for STREAM.
	 */

	if (t->ring) {
		v4v_ring_unregister(t->ring);
		v4v_ring_handle_free(t->ring);
	}

	return;
}

static inline bool sockaddr_vm_match(const struct sockaddr_vm *src,
	const struct sockaddr_vm *dst)
{
	return (src->svm_cid == dst->svm_cid) &&
		(src->svm_port == dst->svm_port);
}

/*
 * Connections.
 */
static int v4v_transport_connect(struct vsock_sock *vsk)
{
	/* af_vsock already hold lock on vsk. */
	//struct v4v_transport *v4t;

	if (!vsock_addr_bound(&vsk->local_addr))
		return -EINVAL;
	if (!vsock_addr_bound(&vsk->remote_addr))
		return -EINVAL;
	/* TODO: Handle connect for STREAM sockets mostly. Not sure what is
	 *	 expected for dgram... */

	return -ECONNREFUSED;
}

/*
 * DGRAM.
 */
#define TODO_DGRAM
#ifdef TODO_DGRAM
static int v4v_transport_recv_dgram_cb(void *priv, struct sk_buff *skb);
static int v4v_transport_dgram_bind(struct vsock_sock *vsk,
		struct sockaddr_vm *addr)
{
	struct v4v_transport *t = v4v_trans(vsk);
	struct sockaddr_vm addr_auto = {
		.svm_family = AF_VSOCK,
		.svm_cid = V4V_DOMID_ANY,
		.svm_port = 0,
		.svm_zero = { 0 },
	};
	size_t ring_len;
	int rc;

	/* TODO: That could be avoided and left up to VSOCK if V4V could agree
	 *       on the _ANY values. */
	if (addr->svm_cid == VMADDR_CID_ANY ||
		addr->svm_port == VMADDR_PORT_ANY)
		memcpy(addr, &addr_auto, sizeof (addr_auto));

	/* Make sure local_addr is bound. */
	memcpy(&vsk->local_addr, addr, sizeof (*addr));

	/* TODO: Ring size should have a default value... Configurable through
	 *       sysfs would be perfect. */
	ring_len = 4096;
	t->ring = v4v_ring_handle_alloc(addr->svm_cid, addr->svm_port, ring_len);
	if (IS_ERR(t->ring)) {
		rc = PTR_ERR(t->ring);
		DPRINTK("v4v_ring_alloc(dom%u:%u) %s (%d).",
			addr->svm_cid, addr->svm_port,
			rc ? "failed" : "succeed", -rc);
		goto failed_alloc;
	}

	rc = v4v_ring_register(t->ring, &v4v_transport_recv_dgram_cb, vsk);
	if (rc) {
		DPRINTK("v4v_ring_register(dom%u:%u) %s (%d).",
			addr->svm_cid, addr->svm_port,
			rc ? "failed" : "succeed", -rc);
		goto failed_register;
	}

	return 0;

failed_register:
	v4v_ring_handle_free(t->ring);
	t->ring = NULL;
failed_alloc:
	return rc;
}

static int v4v_transport_dgram_enqueue(struct vsock_sock *vsk,
	struct sockaddr_vm *remote_addr, struct msghdr *msg, size_t len)
{
	int rc = 0;
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		rc = -EMSGSIZE;
		goto out;
	}

	//DPRINTK("Send payload %uB (packet:%lu, round-up:%lu) `%s'.",
	//	skb->len, skb->len + sizeof (struct v4v_ring_msghdr),
	//	V4V_ROUNDUP(skb->len + sizeof (struct v4v_ring_msghdr)),
	//	(char*)skb->data);
	rc = v4v_ring_send_skb(v4v_trans(vsk)->ring, skb,
		remote_addr->svm_cid, remote_addr->svm_port);
	if (rc)
		goto out;

	return 0;

out:
	kfree_skb(skb);
	return rc;
}

static int v4v_transport_recv_dgram_cb(void *priv, struct sk_buff *skb)
{
	struct vsock_sock *vsk = priv;
	struct sock *sk = &vsk->sk;
	int rc;

	/* sk_receive_skb() does sock_put(). */
	sock_hold(sk);
	rc = sk_receive_skb(sk, skb, 0);
	if (rc != NET_RX_SUCCESS)
		pr_warn("dom%u:%u cannot queue packet, dropping.",
			vsk->local_addr.svm_cid,
			vsk->local_addr.svm_port);
	return rc == NET_RX_SUCCESS ? 0 : -1;
}

static int v4v_transport_dgram_dequeue(struct vsock_sock *vsk,
	struct msghdr *msg, size_t len, int flags)
{
	int rc = 0;
	struct sk_buff *skb;
	struct v4v_ring_msghdr *mh;
	size_t msg_len;

	skb = skb_recv_datagram(&vsk->sk, flags, flags & MSG_DONTWAIT, &rc);
	if (!skb) {
		DPRINTK("skb_recv_datagram() failed (%d).", rc);
		goto out;
	}

	//DPRINTK("skb_recv_datagram() returned skb(%p) %uB.", (void*)skb, skb->len);
	//dprinthex(skb->data, skb->len);

	/* TODO: Assume skb data are always in linear data area.
	 * skb_header_pointer() should be used instead. */
	mh = (void*)skb->data;
	msg_len = mh->len - sizeof (*mh);
	//DPRINTK("Packet from dom%u:%u, payload %uB.", mh->source.domain, mh->source.port, mh->len);
	rc = skb_copy_datagram_msg(skb, sizeof (*mh), msg, msg_len);
	if (rc)
		goto out;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_vm *, vm_addr, msg->msg_name);
		vsock_addr_init(vm_addr, mh->source.domain, mh->source.port);
		msg->msg_namelen = sizeof (*vm_addr);
	}

out:
	skb_free_datagram(&vsk->sk, skb);
	//DPRINTK("Finished: returning %d.", rc);
	return rc;
}

static bool v4v_transport_dgram_allow(u32 cid, u32 port)
{
	//DPRINTK("cid:%d, port:%d.", cid, port);
	return true;
}
#endif /* TODO_DGRAM */

/*
 * STREAM.
 */
#undef TODO_STREAM
#ifdef TODO_STREAM
static ssize_t v4v_transport_stream_dequeue(
	struct vsock_sock *vsk,
	struct msghdr *msg,
	size_t len,
	int flags)
{
	return -ENOTSUP;
}

static ssize_t v4v_transport_stream_enqueue(
	struct vsock_sock *vsk,
	struct msghdr *msg,
	size_t len)
{
	return -ENOTSUP;
}

static s64 v4v_transport_stream_has_data(struct vsock_sock *vsk)
{
	return -ENOTSUP;
}

static s64 v4v_transport_stream_has_space(struct vsock_sock *vsk)
{
	return -ENOTSUP;
}

static u64 v4v_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	return -ENOTSUP;
	/* TODO: Return high-watermark... probably something to frob around
	   with. */
}

static bool v4v_transport_stream_is_active(struct vsock_sock *vsk)
{
	return v4v_ring_exists(&vsk->local_addr);
}

static bool v4v_transport_stream_allow(u32 cid, u32 port)
{
	/* TODO: Pre-filtering can be done in here. */
	return true;
}
#endif /* TODO_STREAM */

/*
 * Notification.
 */
static int v4v_transport_notify_poll_in(
	struct vsock_sock *vsk,
	size_t target,
	bool *data_ready_now)
{
	*data_ready_now = vsock_stream_has_data(vsk);
	return 0;
}

static int v4v_transport_notify_poll_out(
	struct vsock_sock *vsk,
	size_t target,
	bool *space_available_now)
{
	*space_available_now = vsock_stream_has_space(vsk);
	return 0;
}

static int v4v_transport_notify_recv_init(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_recv_pre_block(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_recv_pre_dequeue(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_recv_post_dequeue(
	struct vsock_sock *vsk,
	size_t target,
	ssize_t copied,
	bool data_read,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_send_init(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_send_pre_block(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_send_pre_enqueue(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int v4v_transport_notify_send_post_enqueue(
	struct vsock_sock *vsk,
	ssize_t written,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

/*
 * Shutdown.
 */
static int v4v_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	/* TODO: That might be where we want to send RST instead... */
	return 0;
}

/*
 * Buffer sizes.
 */
static void v4v_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	/* TODO: Probably not usable in our case. */
}

static void v4v_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
}

static void v4v_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
}

static u64 v4v_transport_get_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u64 v4v_transport_get_min_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u64 v4v_transport_get_max_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u32 v4v_transport_get_local_cid(void)
{
	/* TODO: That might actually require svm_cid format instead of V4V. */
	return V4V_DOMID_ANY;
}

static struct vsock_transport v4v_transport = {
	.init = v4v_transport_socket_init,
	.destruct = v4v_transport_destruct,
	.release = v4v_transport_release,

	.connect = v4v_transport_connect,

#ifdef TODO_DGRAM
	.dgram_bind = v4v_transport_dgram_bind,
	.dgram_dequeue = v4v_transport_dgram_dequeue,
	.dgram_enqueue = v4v_transport_dgram_enqueue,
	.dgram_allow = v4v_transport_dgram_allow,
#endif

#ifdef TODO_STREAM
	.stream_dequeue = v4v_transport_stream_dequeue,
	.stream_enqueue = v4v_transport_stream_enqueue,
	.stream_has_data = v4v_transport_stream_has_data,
	.stream_has_space = v4v_transport_stream_has_space,
	.stream_rcvhiwat = v4v_transport_stream_rcvhiwat,
	.stream_is_active = v4v_transport_stream_is_active,
	.stream_allow = v4v_transport_stream_allow,
#endif
	.notify_poll_in = v4v_transport_notify_poll_in,
	.notify_poll_out = v4v_transport_notify_poll_out,
	.notify_recv_init = v4v_transport_notify_recv_init,
	.notify_recv_pre_block = v4v_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue = v4v_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = v4v_transport_notify_recv_post_dequeue,
	.notify_send_init = v4v_transport_notify_send_init,
	.notify_send_pre_block = v4v_transport_notify_send_pre_block,
	.notify_send_pre_enqueue = v4v_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue = v4v_transport_notify_send_post_enqueue,

	.shutdown = v4v_transport_shutdown,

	.set_buffer_size = v4v_transport_set_buffer_size,
	.set_min_buffer_size = v4v_transport_set_min_buffer_size,
	.set_max_buffer_size = v4v_transport_set_max_buffer_size,
	.get_buffer_size = v4v_transport_get_buffer_size,
	.get_min_buffer_size = v4v_transport_get_min_buffer_size,
	.get_max_buffer_size = v4v_transport_get_max_buffer_size,

	.get_local_cid = v4v_transport_get_local_cid,
};

static int __init v4v_transport_init(void)
{
	int rc;

	rc = vsock_core_init(&v4v_transport);
	if (rc) {
		pr_err("vsock_core_init() failed (%d).\n", rc);
		return rc;
	}
	rc = v4v_core_init();
	if (rc) {
		pr_err("v4v_core_init() failed (%d).\n", rc);
		vsock_core_exit();
		return rc;
	}
	pr_info("vsock_v4v_transport registered.\n");

	return 0;
}
module_init(v4v_transport_init);

static void __exit v4v_transport_exit(void)
{
	/* TODO: Flush sockets... */

	pr_info("vsock_v4v_transport unregistered.\n");
	v4v_core_cleanup();
	vsock_core_exit();
	return;
}
module_exit(v4v_transport_exit);

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("V4V transport for Virtual Socket.");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("GPL");
MODULE_ALIAS("v4v_vsock");
MODULE_ALIAS_NETPROTO(v4v_vsock);
