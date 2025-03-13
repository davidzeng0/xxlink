#include <netinet/tcp.h>
#include <xe/error.h>
#include <xutil/log.h>
#include "client.h"
#include "proto/message.pb.h"

using namespace xxlink;

void xe_client::check_close(){
	if(recv_pending || send_pending)
		return;
	closing = false;

	if(close_callback) close_callback(*this);
}


int xe_client::send(xe_ptr msg, size_t len){
	return XE_ENOMEM;
}

void xe_client::recv_cb(xe_req& req, int result){
	xe_client& client = xe_containerof(req, &xe_client::recv_req);

	client.recv_cb(result);
}

void xe_client::send_cb(xe_req& req, int result){

}

void xe_client::recv_cb(int result){
	recv_pending = false;

	if(closing){
		check_close();

		return;
	}

	if(result <= 0)
		goto close;
	offset += result;

	xe_log_trace(this, ">> client %i", result);

	while(offset){
		if(!length){
			size_t msg_len = 0;

			for(uint i = 1; i < 11 && offset; i++){
				msg_len |= (ulong)(buffer[i] & 0x7f) << ((i - 1) * 7);

				if(!(buffer[i] & 0x80)){
					length = msg_len + i + 1;

					break;
				}
			}

			if(length){
				if(length > XE_LOOP_IOBUF_SIZE)
					goto close;
				xe_log_trace(this, "message length %zu", length);

				if(length > offset)
					break;
			}else{
				break;
			}
		}

		if(length && offset >= length){
			process_message(buffer, length);

			offset -= length;

			xe_memmove(buffer, buffer + length, offset);

			length = 0;
		}
	}

	result = recv();

	if(result)
		goto close;
	return;
close:
	close();
}

int xe_client::recv(){
	xe_return_error(socket.recv(recv_req, buffer + offset, XE_LOOP_IOBUF_SIZE - offset, 0));

	recv_pending = true;

	return 0;
}

void xe_client::process_message(xe_ptr data, size_t len){
	Message message;

	if(!message.ParseFromArray(data, len)){
		// handle error

		return;
	}

	if(message.has_session_message()){
		auto& session_message = *message.mutable_session_message();
		auto it = sessions.find(session_message.session());

		if(session_message.has_session_open()){
			if(it != sessions.end()){
				// close

				return;
			}

			xe_unique_ptr<xe_session> session(xe_znew<xe_session>(session_message.session(), *node));

			if(!session)
				return;
			it = sessions.insert(session_message.session());

			if(it == sessions.end())
				return;
			it -> second = std::move(session);

			return;
		}else if(it == sessions.end()){
			// invalid session, close

			return;
		}

		if(session_message.has_session_close()){
			it -> second -> close();
			sessions.erase(it);

			return;
		}

		it -> second -> process_message(session_message);
	}else if(message.has_ping()){
		// pong
	}else if(message.has_error()){
		// invalid message, close
	}
}

xe_client::xe_client(xe_link_node& node_, int client): socket(node_.loop()){
	node = &node_;
	socket.accept(client);
	recv_req.callback = recv_cb;
	close_callback = null;
	offset = 0;
	length = 0;
}

int xe_client::start(){
	buffer = xe_alloc<byte>(XE_LOOP_IOBUF_SIZE);

	if(!buffer)
		return XE_ENOMEM;
	return recv();
}

int xe_client::close(){
	if(closing)
		return XE_EALREADY;
	if(recv_pending || send_pending)
		return XE_EINPROGRESS;
	check_close();

	return 0;
}

xe_client::~xe_client(){
	socket.close();

	xe_dealloc(buffer);
}