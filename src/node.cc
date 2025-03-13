#include <unistd.h>
#include <arpa/inet.h>
#include <xutil/util.h>
#include <xutil/endian.h>
#include <xutil/log.h>
#include <xe/error.h>
#include "node.h"
#include "client.h"

using namespace xxlink;
using namespace xurl;

enum{
	XE_DEFAULT_QUEUE_LENGTH = 1 << 9
};

void xe_link_node::accept_cb(xe_req& req, int fd){
	xe_link_node& node = xe_containerof(req, &xe_link_node::accept_req);
	int err = 0;

	node.accept_active = false;

	if(node.closing){
		node.check_close();

		return;
	}

	if(fd < 0){
		xe_log_error(&node, "accept failed: %s", xe_strerror(fd));

		if(fd != XE_ECONNABORTED) err = fd;
	}else{
		err = node.create_client(fd);
	}

	if(!err)
		err = node.server.accept(node.accept_req, null, null, 0);
	if(!err)
		return;
	xe_log_error(&node, "error: %s, exiting", xe_strerror(err));

	node.close_clients();
}

void xe_link_node::cancel_cb(xe_req& req, int res){
	xe_link_node& node = xe_containerof(req, &xe_link_node::cancel_req);

	node.cancel_active = false;
	node.check_close();
}

void xe_link_node::close_cb(xe_client& client){
	xe_link_node& node = *client.node;

	node.client_list.erase(client.link);
	node.clients--;

	xe_delete(&client);
	xe_log_info(&node, "client disconnected. %lu clients online", node.clients);

	if(node.closing) node.check_close();
}

int xe_link_node::create_client(int fd){
	xe_client* client;
	int err;

	client = xe_znew<xe_client>(*this, fd);

	if(!client){
		::close(fd);

		return XE_ENOMEM;
	}

	err = client -> start();

	if(err){
		client -> close();

		xe_delete(client);
	}else{
		clients++;
		client -> close_callback = close_cb;
		client_list.append(client -> link);

		xe_log_info(this, "new client connected. %zu clients online", clients);
	}

	return err;
}

void xe_link_node::check_close(){
	if(clients || accept_active || cancel_active)
		return;
	closing = false;

	closed();

	if(close_callback) close_callback(*this);
}

void xe_link_node::closed(){
	loop_.close();
	ctx_.close();
	shared.close();
	server.close();
}

void xe_link_node::close_clients(){
	auto cur = client_list.begin();

	while(cur != client_list.end()){
		xe_client& client = xe_containerof(*(cur++), &xe_client::link);

		client.close();
	}
}

xe_link_node::xe_link_node(): server(loop_){
	clients = 0;

	accept_req.callback = accept_cb;
	cancel_req.callback = cancel_cb;

	accept_active = false;
	cancel_active = false;
	closing = false;

	options.player_queue_length = XE_DEFAULT_QUEUE_LENGTH;
}

int xe_link_node::init(){
	xe_loop_options options;
	int err, yes = 1;

	options.entries = 1 << 8;
	options.cq_entries = 1 << 16;
	options.flag_cqsize = true;
	options.flag_iobuf = true;

	if((err = loop_.init_options(options)))
		return err;
	if((err = shared.init()))
		goto closeloop;
	if((err = ctx_.init(loop_, shared)))
		goto closeshared;
	if((err = server.init_sync(AF_INET, SOCK_STREAM, IPPROTO_TCP)))
		goto closectx;
	if(setsockopt(server.fd(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		goto syserr;
	return 0;
syserr:
	err = xe_errno();
	server.close();
closectx:
	ctx_.close();
closeshared:
	shared.close();
closeloop:
	loop_.close();

	return err;
}

int xe_link_node::listen(const xe_string_view& addr, ushort port){
	sockaddr_in in;

	xe_zero(&in);

	if(inet_pton(AF_INET, addr.data(), &in.sin_addr) != 1)
		return XE_EINVAL;
	in.sin_family = AF_INET;
	in.sin_port = xe_hton(port);

	xe_return_error(server.bind((sockaddr*)&in, sizeof(in)));
	xe_return_error(server.listen(SOMAXCONN));
	xe_return_error(server.accept(accept_req, null, null, 0));

	accept_active = true;

	xe_log_info(this, "listening on %s:%d", addr.data(), port);

	return 0;
}

int xe_link_node::run(){
	return loop_.run();
}

int xe_link_node::close(){
	if(closing)
		return XE_EALREADY;
	int res = 0;

	close_clients();

	if(accept_active){
		res = loop_.cancel(cancel_req, accept_req, xe_op::cancel(0), null, &info);

		if(res == XE_EINPROGRESS) cancel_active = true;
	}

	if(!clients && !accept_active && !cancel_active){
		closed();

		return 0;
	}

	closing = true;

	return res;
}

int xxlink::xe_link_init(){
	return xurl_init();
}

void xxlink::xe_link_cleanup(){
	return xurl_cleanup();
}