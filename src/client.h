#pragma once
#include <xstd/types.h>
#include <xstd/linked_list.h>
#include <xe/loop.h>
#include <xe/io/socket.h>
#include <xstd/map.h>
#include <xstd/unique_ptr.h>
#include "node.h"
#include "session.h"

namespace xxlink{

class xe_client{
private:
	static void recv_cb(xe_req&, int);
	static void send_cb(xe_req&, int);

	void recv_cb(int);
	void send_cb(int);

	void check_close();
	int send(xe_ptr, size_t);

	int recv();
	void send();

	void process_message(xe_ptr, size_t);

	xe_link_node* node;
	xe_linked_node link;

	xe_socket socket;
	xe_req recv_req;
	xe_req send_req;

	size_t offset;
	size_t length;
	byte* buffer;

	bool recv_pending: 1;
	bool send_pending: 1;
	bool closing: 1;

	xe_map<uint, xe_unique_ptr<xe_session>> sessions;

	friend class xe_link_node;
public:
	void (*close_callback)(xe_client& client);

	xe_client(xe_link_node& node, int client);

	int start();
	int close();

	~xe_client();

	static xe_cstr class_name(){
		return "xe_link_client";
	}
};

}