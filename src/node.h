#pragma once
#include <xstd/types.h>
#include <xurl/ctx.h>
#include <xe/loop.h>
#include <xe/io/socket.h>

namespace xxlink{

class xe_client;
class xe_link_node{
private:
	static void accept_cb(xe_req&, int);
	static void cancel_cb(xe_req&, int);
	static void close_cb(xe_client&);

	int create_client(int);
	void close_clients();
	void check_close();
	void closed();

	xe_loop loop_;

	xurl::xurl_ctx ctx_;
	xurl::xurl_shared shared;

	xe_linked_list client_list;
	size_t clients;

	xe_socket server;
	xe_req accept_req;
	xe_req cancel_req;
	xe_req_info info;

	bool accept_active: 1;
	bool cancel_active: 1;
	bool closing: 1;

	struct xe_options{
		uint player_queue_length;
	} options;
public:
	void (*close_callback)(xe_link_node& node);

	xe_link_node();

	int init();
	int set_player_queue_length(uint length);
	int listen(const xe_string_view& addr, ushort port);
	int run();
	int close();

	xe_loop& loop(){
		return loop_;
	}

	xurl::xurl_ctx& ctx(){
		return ctx_;
	}

	~xe_link_node() = default;

	static xe_cstr class_name(){
		return "xe_link_node";
	}
};

int xe_link_init();
void xe_link_cleanup();

}