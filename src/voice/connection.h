#pragma once
#include <xstd/types.h>
#include <xurl/ctx.h>
#include <xurl/request.h>
#include <xe/loop.h>
#include "encryption.h"
#include "message.h"
#include "../node.h"
#include "../proto/voice.pb.h"

namespace xxlink{

enum xe_voice_connection_state{
	XE_VOICE_CONNECTION_IDLE = 0,
	XE_VOICE_CONNECTION_CONNECTING,
	XE_VOICE_CONNECTION_IDENTIFYING,
	XE_VOICE_CONNECTION_RESUMING,
	XE_VOICE_CONNECTION_RTC_CONNECTING,
	XE_VOICE_CONNECTION_WAITING,
	XE_VOICE_CONNECTION_READY,
	XE_VOICE_CONNECTION_DISCONNECTED,
	XE_VOICE_CONNECTION_RECONNECTING
};

class xe_voice_connection{
public:
	typedef void (*close_cb)(xe_voice_connection& conn, int error);
	typedef void (*state_cb)(xe_voice_connection& conn, xe_voice_connection_state state);
private:
	static int ready(xurl::xe_request&);
	static int message(xurl::xe_request&, xurl::xe_websocket_op, xe_vector<byte>&);
	static int close(xurl::xe_request&, ushort, xe_slice<byte>);

	static int ws_timeout(xe_loop&, xe_timer&);
	static int rtc_timeout(xe_loop&, xe_timer&);

	static void rtc_poll_cb(xe_poll&, int);
	static void rtc_close_cb(xe_poll&);

	void set_state(xe_voice_connection_state state);
	void start_timer(xe_timer&, uint);

	int send_message(xe_message&);

	int create_rtc();
	int rtc_connect();

	void handle_ip_discovery(const xe_slice<byte>&);
	void handle_heartbeat(const xe_slice<byte>&);
	void handle_rtp(const xe_slice<byte>&);

	xe_link_node* node;

	std::string guild_id;
	std::string user_id;
	std::string session_id;
	std::string token;

	xurl::xe_request ws;
	xe_socket rtc;
	xe_poll rtc_poll;

	in_addr rtc_addr;
	ushort rtc_port;

	xe_timer ws_heartbeat;
	xe_timer rtc_heartbeat;

	uint ws_heartbeat_nonce;
	uint ws_heartbeat_ack;
	ulong ws_heartbeat_time;
	ulong ws_ping;

	uint rtc_heartbeat_nonce;
	uint rtc_heartbeat_ack;
	ulong rtc_heartbeat_time;
	ulong rtc_ping;

	xe_encryption encryption;
	xe_encryption_mode encryption_mode;
	uint ssrc;

	xe_voice_connection_state state;

	bool hello_received: 1;

	struct xe_callbacks{
		close_cb close;
		state_cb state;
	} callbacks;
public:
	xe_voice_connection(xe_link_node& node);

	void state_update(VoiceStateUpdate& update);
	void server_update(VoiceServerUpdate& update);
	void close();

	~xe_voice_connection();

	static xe_cstr class_name();
};

}