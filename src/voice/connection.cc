#include <arpa/inet.h>
#include <xe/error.h>
#include <xe/clock.h>
#include <xutil/log.h>
#include <xutil/endian.h>
#include <xutil/writer.h>
#include <xarch/arch.h>
#include <xstd/fla.h>
#include "connection.h"
#include "message.h"

using namespace xurl;
using namespace xxlink;

enum xe_rtp_packet_type{
	XE_RTP_OPUS = 120,
	XE_RTP_SENDER_REPORT = 200,
	XE_RTP_RECEIVER_REPORT = 201
};

enum xe_discord_extension_id{
	XE_DISCORD_AUDIO_LEVEL = 1,
	XE_DISCORD_SPEAKING_FLAGS = 9
};

enum xe_discord_extension_speaking_flags{
	XE_DISCORD_PRIORITY = 0x1,
	XE_DISCORD_MIC = 0x2,
	XE_DISCORD_SOUNDSHARE = 0x4
};

#pragma pack(push, 1)

struct xe_ip_discovery{
	ushort type;
	ushort length;
	uint ssrc;
	xe_fla<char, 64> ip;
	ushort port;
};

struct xe_rtp_extension_header{
	ushort extension;
	ushort length;
};

struct xe_rtp_header{
	byte flags;
	byte packet_type;

	union{
		ushort report_length;
		ushort sequence;
	};

	union{
		uint report_ssrc;
		uint timestamp;
	};

	uint ssrc;
	xe_rtp_extension_header extension_header;

	byte version(){
		return flags >> 6;
	}

	byte extension(){
		return (flags >> 4) & 1;
	}

	byte contributing_sources(){
		return flags & 0xf;
	}

	byte marker(){
		return packet_type >> 7;
	}

	byte report_count(){
		return flags & 0x3f;
	}
};

struct xe_rtp_receiver_report{
	uint ssrc;
	uint lost;
	uint highest_sequence;
	uint interarrival_jitter;
	uint last_sr;
	uint delay_since_last_sr;
};

#pragma pack(pop)

int xe_voice_connection::ready(xe_request& ws){
	xe_voice_connection& conn = xe_containerof(ws, &xe_voice_connection::ws);
	xe_message message;

	message.op = XE_OP_IDENTIFY;
	message.identify.server_id = xe_string_view(conn.guild_id.data(), conn.guild_id.size());
	message.identify.user_id = xe_string_view(conn.user_id.data(), conn.user_id.size());
	message.identify.session_id = xe_string_view(conn.session_id.data(), conn.session_id.size());
	message.identify.token = xe_string_view(conn.token.data(), conn.token.size());

	conn.send_message(message);
	conn.set_state(XE_VOICE_CONNECTION_IDENTIFYING);

	xe_log_verbose(&conn, "<< ws identify: "
		"server_id = %s, user_id = %s, session_id = %s, token = %s",
		conn.guild_id.data(),
		conn.user_id.c_str(),
		conn.session_id.c_str(),
		conn.token.c_str()
	);

	message.op = XE_OP_MEDIA_SINK_WANTS;
	message.media_sink_wants.want_audio = false;
	conn.send_message(message);

	xe_log_verbose(&conn, "<< ws media_sink_wants: audio = %s",
		message.media_sink_wants.want_audio ? "true" : "false"
	);

	return 0;
}

int xe_voice_connection::message(xe_request& ws, xe_websocket_op ws_op, xe_vector<byte>& data){
	xe_voice_connection& conn = xe_containerof(ws, &xe_voice_connection::ws);
	xe_message message;
	int err;

#ifdef XE_DEBUG
	char ip[INET6_ADDRSTRLEN];
#endif

	xe_log_trace(&conn, ">> ws raw: %.*s", data.size(), data.data());

	err = message.parse(data.data(), data.size());

	switch(message.op){
		case XE_OP_HELLO:
			if(conn.hello_received)
				return XE_INVALID_RESPONSE;
			conn.hello_received = true;

			if(message.hello.heartbeat_interval < 1000)
				return XE_INVALID_RESPONSE;
			xe_log_verbose(&conn, ">> ws hello: heartbeat_interval = %u ms", message.hello.heartbeat_interval);

			conn.ws_heartbeat_nonce = 0;
			conn.ws_heartbeat_ack = 0;
			conn.start_timer(conn.ws_heartbeat, message.hello.heartbeat_interval);

			break;
		case XE_OP_HEARTBEAT_ACK:
			if(message.heartbeat_ack.nonce != conn.ws_heartbeat_ack + 1){
				xe_log_error(&conn, ">> ws heartbeat: seq = %u, expected = %u, ack out of order, closing", message.heartbeat_ack.nonce, conn.ws_heartbeat_ack + 1);

				// todo close conn
			}else{
				conn.ws_heartbeat_ack = message.heartbeat_ack.nonce;
				conn.ws_ping = xe_time_ns() - conn.ws_heartbeat_time;

				xe_log_debug(&conn, ">> ws heartbeat: seq = %u, ping = %.3f ms", conn.ws_heartbeat_ack, conn.ws_ping / (float)XE_NANOS_PER_MS);
			}

			break;
		case XE_OP_READY:
			if(conn.state != XE_VOICE_CONNECTION_IDENTIFYING)
				return XE_INVALID_RESPONSE;
			if(!message.ready.encryption_modes)
				return XE_INVALID_RESPONSE;
			conn.set_state(XE_VOICE_CONNECTION_RTC_CONNECTING);

		#ifdef XE_DEBUG
			inet_ntop(AF_INET, &message.ready.ip, ip, sizeof(ip));
		#endif
			xe_log_verbose(&conn, ">> ws ready: ip = %s, port = %u, ssrc = %u, encryption_modes = %#x",
				ip, message.ready.port, message.ready.ssrc, message.ready.encryption_modes
			);

			conn.rtc_addr = message.ready.ip;
			conn.rtc_port = xe_hton(message.ready.port);
			conn.ssrc = message.ready.ssrc;
			/* pick the lowest bit set */
			conn.encryption_mode = (xe_encryption_mode)(1 << xe_ctz(message.ready.encryption_modes));

			/* send speaking now so that we can send voice as soon as we get the key */
			message.op = XE_OP_SPEAKING;
			message.speaking.delay = 0;
			message.speaking.speaking_flags = XE_SPEAKING_MIC;
			message.speaking.ssrc = conn.ssrc;

			conn.send_message(message);

			xe_log_verbose(&conn, "<< ws speaking: delay = %u, ssrc = %u, voice_types = %#x",
				message.speaking.delay,
				conn.ssrc,
				message.speaking.speaking_flags
			);

			conn.create_rtc();

			break;
		case XE_OP_SESSION_DESCRIPTION:
			xe_log_verbose(&conn, ">> ws session_description: encryption_mode = %s, secret_key = %08lx%08lx%08lx%08lx",
				xe_encryption_mode_to_string(message.session_description.encryption_mode),
				xe_ntoh(*(ulong*)&message.session_description.secret_key[0]),
				xe_ntoh(*(ulong*)&message.session_description.secret_key[8]),
				xe_ntoh(*(ulong*)&message.session_description.secret_key[16]),
				xe_ntoh(*(ulong*)&message.session_description.secret_key[24])
			);

			conn.encryption.init(message.session_description.encryption_mode, message.session_description.secret_key);

			break;
	}

	return 0;
}

int xe_voice_connection::close(xe_request& ws, ushort code, xe_slice<byte> data){
	xe_voice_connection& conn = xe_containerof(ws, &xe_voice_connection::ws);

	xe_log_debug(&conn, "close: code = %u, text = %.*s", code, data.size(), data.data());

	conn.close();

	return 0;
}

int xe_voice_connection::ws_timeout(xe_loop& loop, xe_timer& timer){
	xe_voice_connection& conn = xe_containerof(timer, &xe_voice_connection::ws_heartbeat);
	xe_message message;

	if(conn.ws_heartbeat_nonce - conn.ws_heartbeat_ack > 0){
		conn.ws.ws_close(1000, null, 0);

		xe_log_error(&conn, "heartbeat ack timed out");
	}else{
		message.op = XE_OP_HEARTBEAT;
		message.heartbeat.nonce = ++conn.ws_heartbeat_nonce;

		conn.ws_heartbeat_time = xe_time_ns();
		conn.send_message(message);

		xe_log_debug(&conn, "<< ws heartbeat: seq = %u", message.heartbeat.nonce);
	}

	return 0;
}

int xe_voice_connection::rtc_timeout(xe_loop& loop, xe_timer& timer){
	xe_voice_connection& conn = xe_containerof(timer, &xe_voice_connection::rtc_heartbeat);

	if(conn.state == XE_VOICE_CONNECTION_RTC_CONNECTING){
		conn.rtc_connect();

		return 0;
	}

	xe_fla<byte, 8> payload;
	xe_writer writer(payload);
	int err;

	err = XE_ETIMEDOUT;

	if(conn.rtc_heartbeat_nonce - conn.rtc_heartbeat_ack > 12){
		// close

		return 0;
	}

	if(conn.rtc_heartbeat_nonce != conn.rtc_heartbeat_ack)
		conn.rtc_ping += 5ul * XE_NANOS_PER_SEC;
	writer.w64le(++conn.rtc_heartbeat_nonce);
	err = conn.rtc.send_sync(payload.data(), payload.size(), MSG_DONTWAIT);
	conn.rtc_heartbeat_time = xe_time_ns();

	if(err < 0)
		xe_log_error(&conn, "<< udp %i (%s)", err, xe_strerror(err));
	else
		xe_log_debug(&conn, "<< udp heartbeat: seq = %lu", conn.rtc_heartbeat_nonce);
	return 0;
}

void xe_voice_connection::set_state(xe_voice_connection_state state_){
	state = state_;

	if(callbacks.state) callbacks.state(*this, state_);
}

void xe_voice_connection::handle_ip_discovery(const xe_slice<byte>& data){
	xe_ip_discovery& discovery = *(xe_ip_discovery*)data.data();
	uint mlen, iplen;
	ushort port;
	in_addr addr;
	xe_message message;

	if(data.size() != 74)
		return;
	mlen = xe_ntoh(discovery.length) + 4;

	if(xe_ntoh(discovery.type) != 0x02 ||
		xe_hton(discovery.ssrc) != ssrc ||
		mlen != 74)
		return;
	xe_string_view ip(discovery.ip.begin(), discovery.ip.size());

	iplen = ip.index_of(0);

	if(iplen == (uint)-1 || inet_pton(AF_INET, (char*)&data[8], &addr) != 1)
		return;
	port = xe_ntoh(discovery.port);

	start_timer(rtc_heartbeat, 5'000);
	xe_log_verbose(this, ">> udp ip discovery: ip = %s port = %u", ip.data(), port);

	message.select_protocol.protocol = "udp";
	message.select_protocol.address = ip.substring(0, iplen);
	message.select_protocol.port = port;
	message.select_protocol.mode = encryption_mode;
	message.op = XE_OP_SELECT_PROTOCOL;

	set_state(XE_VOICE_CONNECTION_WAITING);
	send_message(message);

	xe_log_verbose(this, "<< ws select_protocol: protocol = %s, ip = %s port = %u, encryption_mode = %s",
		message.select_protocol.protocol.data(),
		message.select_protocol.address.data(),
		port,
		xe_encryption_mode_to_string(encryption_mode)
	);
}

void xe_voice_connection::handle_heartbeat(const xe_slice<byte>& data){
	ulong value = xe_htole(*(ulong*)&data[0]);

	if(value - rtc_heartbeat_ack <= rtc_heartbeat_nonce - rtc_heartbeat_ack){
		rtc_heartbeat_ack = value;
		rtc_ping = xe_time_ns() - rtc_heartbeat_time + (rtc_heartbeat_nonce - value) * 5ul * XE_NANOS_PER_SEC;

		xe_log_debug(this, ">> udp heartbeat: seq = %lu, ping = %.3f ms", value, rtc_ping / (float)XE_NANOS_PER_MS);
	}
}

void xe_voice_connection::handle_rtp(const xe_slice<byte>& data){
	xe_rtp_header& header = *(xe_rtp_header*)&data[0];
	xe_fla<byte, 1500> plaintext;
	int plaintext_len;
	uint header_size = 8;

	if(data.size() < header_size || header.version() != 2)
		return;
	if(header.packet_type == XE_RTP_RECEIVER_REPORT){
		if(xe_ntoh(header.report_ssrc) != ssrc) return;
	}else if(header.packet_type == XE_RTP_OPUS){
		header_size = 12;

		if(header.extension())
			header_size += 4;
		if(data.size() < header_size)
			return;
	}else{
		return;
	}

	plaintext_len = encryption.decrypt(plaintext.data(), data.data(), data.size(), header_size);

	if(plaintext_len < 0)
		return;
	if(header.packet_type == XE_RTP_RECEIVER_REPORT){
		constexpr uint report_size = 24;
		uint length = (xe_ntoh(header.report_length) + 1) * 4,
			report_count = header.report_count();
		if(length > plaintext_len + header_size || length < report_count * report_size + header_size)
			return;
		xe_rtp_receiver_report* reports = (xe_rtp_receiver_report*)&plaintext[0];

		for(uint i = 0; i < report_count; i++){
			xe_rtp_receiver_report& report = reports[i];

			if(xe_ntoh(report.ssrc) != ssrc)
				continue;
			uint lost = xe_ntoh(report.lost);

			xe_log_debug(this, ">> rtcp receiver report: "
				"lost = %i (%.3f\%), jitter = %i, highest_seq = %u",
				(int)(lost << 8) >> 8,
				(lost >> 24) * 100.0f / 255,
				xe_ntoh(report.interarrival_jitter),
				xe_ntoh(report.highest_sequence)
			);
		}

		return;
	}

	xe_slice<byte> opus_data = plaintext.slice(0, plaintext_len);
	int loudness = 0;
	uint speaking_flags = 0;

	if(header.extension()){
		uint profile = xe_hton(header.extension_header.extension),
			length = xe_hton(header.extension_header.length) * 4;
		if(plaintext_len < length)
			return;
		if(profile == 0xbede){
			for(uint i = 0; i < length; i++){
				uint id, len;

				if(!plaintext[i])
					continue;
				id = plaintext[i] >> 4;
				len = (plaintext[i] & 0xf) + 1;

				if(i + len + 1 > length)
					return;
				if(id == XE_DISCORD_AUDIO_LEVEL)
					loudness = -(plaintext[i + 1] & 0x7f);
				else if(id == XE_DISCORD_SPEAKING_FLAGS)
					speaking_flags = plaintext[i + 1];
				i += len;
			}
		}

		opus_data = plaintext.slice(length, plaintext_len);
	}

	xe_log_debug(this, ">> rtp opus: sequence = %u, timestamp = %u, ssrc = %u, loudness = %i dBov, speaking_flags = %#0x, len = %u",
		xe_hton(header.sequence),
		xe_hton(header.timestamp),
		xe_hton(header.ssrc),
		loudness,
		speaking_flags,
		opus_data.size()
	);
}

void xe_voice_connection::rtc_poll_cb(xe_poll& poll, int result){
	xe_voice_connection& conn = xe_containerof(poll, &xe_voice_connection::rtc_poll);
	xe_fla<byte, 1500> buf;
	xe_slice<byte> data;

	ssize_t msglen;
	sockaddr_in in;
	msghdr hdr;
	iovec vec;

	xe_zero(&hdr);

	vec.iov_base = buf.data();
	vec.iov_len = buf.size();
	hdr.msg_iov = &vec;
	hdr.msg_iovlen = 1;
	hdr.msg_name = &in;
	hdr.msg_namelen = sizeof(in);
	msglen = conn.rtc.recvmsg_sync(&hdr, MSG_DONTWAIT);

	if(msglen < 0)
		goto error;
	data = buf.slice(0, msglen);

	if(hdr.msg_namelen != sizeof(in) ||
		in.sin_family != AF_INET ||
		in.sin_addr.s_addr != conn.rtc_addr.s_addr ||
		in.sin_port != conn.rtc_port ||
		(hdr.msg_flags & MSG_TRUNC)){
		return;
	}

	if(conn.state == XE_VOICE_CONNECTION_RTC_CONNECTING)
		conn.handle_ip_discovery(data);
	else if(data.size() == 8)
		conn.handle_heartbeat(data);
	else
		conn.handle_rtp(data);
	return;
error:
	return;
}

int xe_voice_connection::send_message(xe_message& message){
	std::string serialized;
	int err = 0;

	if(!message.serialize(serialized))
		err = XE_ENOMEM;
	if(!err)
		err = ws.ws_send(XE_WEBSOCKET_TEXT, serialized.data(), serialized.size());
	if(err)
		xe_log_error(this, "<< ws %i (%s)", err, xe_strerror(err));
	else
		xe_log_trace(this, "<< ws raw: %s", serialized.c_str());
	return err;
}

int xe_voice_connection::create_rtc(){
	sockaddr_in in;

	xe_zero(&in);

	in.sin_family = AF_INET;
	in.sin_addr = rtc_addr;
	in.sin_port = rtc_port;

	if(rtc.fd() == -1){
		xe_return_error(rtc.init_sync(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

		rtc_poll.set_fd(rtc.fd());

		xe_return_error(rtc_poll.poll(XE_POLL_IN));
	}

	xe_return_error(rtc.connect_sync((sockaddr*)&in, sizeof(in)));
	xe_return_error(rtc_connect());

	start_timer(rtc_heartbeat, 10'000);

	return 0;
}

int xe_voice_connection::rtc_connect(){
	xe_fla<byte, 74> payload;
	xe_writer writer(payload);
	int sent;

	writer.w16be(1);
	writer.w16be(70);
	writer.w32be(ssrc);

	sent = rtc.send_sync(payload.data(), payload.size(), MSG_DONTWAIT);

	if(sent < 0){
		xe_log_error(this, "<< udp %i (%s)", sent, xe_strerror(sent));

		return sent;
	}

	xe_log_verbose(this, "<< udp ip discovery (%i)", sent);

	return 0;
}

void xe_voice_connection::start_timer(xe_timer& timer, uint interval){
	if(timer.active())
		node -> loop().cancel(timer);
	node -> loop().timer_ms(timer, interval, interval, XE_TIMER_REPEAT);
}

xe_voice_connection::xe_voice_connection(xe_link_node& node_){
	node = &node_;

	ws_heartbeat.callback = ws_timeout;
	rtc_heartbeat.callback = rtc_timeout;

	rtc_poll.set_loop(node -> loop());
	rtc_poll.poll_callback = rtc_poll_cb;
}

void xe_voice_connection::state_update(VoiceStateUpdate& update){
	guild_id = std::move(*update.mutable_guild_id());
	session_id = std::move(*update.mutable_session_id());
	user_id = std::move(*update.mutable_user_id());

	if(!update.has_channel_id()) close();
}

void xe_voice_connection::server_update(VoiceServerUpdate& update){
	xe_string_view prefix = "wss://", suffix = "/?v=4", endpoint = xe_string_view(update.endpoint().data(), update.endpoint().size());
	xe_string url;

	close();

	if(!update.has_token())
		return;
	token = std::move(*update.mutable_token());

	if(!url.resize(prefix.size() + endpoint.size() + suffix.size()))
		return;
	xe_writer writer(url);

	writer.write(prefix);
	writer.write(endpoint);
	writer.write(suffix);

	node -> ctx().open(ws, xe_string_view(url.data(), url.size()));
	ws.set_ws_ready_cb(ready);
	ws.set_ws_message_cb(message);
	ws.set_ws_close_cb(close);
	node -> ctx().start(ws);
	hello_received = false;
}

void xe_voice_connection::close(){
	node -> ctx().end(ws);

	if(ws_heartbeat.active())
		node -> loop().cancel(ws_heartbeat);
	if(rtc_heartbeat.active())
		node -> loop().cancel(rtc_heartbeat);
}

xe_voice_connection::~xe_voice_connection(){

}

xe_cstr xe_voice_connection::class_name(){
	return "xe_voice_connection";
}