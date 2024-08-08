#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/err.h>

#include <net/inet_common.h>
#include <net/tcp.h>
#include <net/sock.h>

int shortcut_tcp_sendmsg(int fd, struct iovec *iov)
{
	struct fd f;
	struct socket *socket;
	struct sock *sk;
	struct kiocb kiocb;
	loff_t pos, *ppos;
	int ret = 0;

	f = fdget_pos(fd);
	ppos = file_ppos(f.file);
	if (ppos) {
		pos = *ppos;
		ppos = &pos;
	}

	socket = (struct socket *)f.file->private_data;
	sk = socket->sk;

	init_sync_kiocb(&kiocb, f.file);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	msg.msg_iocb = &kiocb;

	/* Up until now, this has all been setup, lock the socket and send */
	lock_sock(sk);
	ret = tcp_sendmsg_locked(sk, &msg, iov.iov_len);
	release_sock(sk);

	return ret;
}
EXPORT_SYMBOL(shortcut_tcp_sendmsg);

int shortcut_tcp_write(int fd, void *data, size_t len)
{
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = len;

	iov_iter_init(&msg.iter, ITER_SOURCE, &iov, 1, iov.iov_len);

	return shortcut_tcp_sendmsg(fd, &iov);
}
EXPORT_SYMBOL(shortcut_tcp_write);

int shortcut_tcp_recvmsg(int fd, void *buf, size_t len)
{
	struct iovec iov;
	struct msghdr msg;
	struct fd f;
	struct sock *sk;
	struct kiocb kiocb;
	loff_t pos, *ppos;
	int addr_len;
	int ret = 0;

	iov.iov_base = data;
	iov.iov_len = len;

	iov_iter_init(&msg.iter, ITER_DEST, &iov, 1, iov.iov_len);

	f = fdget_pos(fd);
	ppos = file_ppos(f.file);
	if (ppos) {
		pos = *ppos;
		ppos = &pos;
	}

	sk = ((struct socket *)f.file->private_data)->sk;

	init_sync_kiocb(&kiocb, f.file);
	kiocb.ki_pos = (ppos ? *ppos : 0);
	msg.msg_iocb = &kiocb;

	ret = tcp_recvmsg(sk, &msg, len, 0, &addr_len);

	return ret;
}
EXPORT_SYMBOL(shortcut_tcp_recvmsg)
