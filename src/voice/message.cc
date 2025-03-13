#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <xutil/endian.h>
#include <xe/error.h>
#include "message.h"

using namespace xxlink;
using json = nlohmann::json;

static xe_encryption_mode encryption_mode_from_string(const std::string& mode){
	if(mode == "aead_aes256_gcm_rtpsize")
		return XE_AEAD_AES256_GCM_RTPSIZE;
	else if(mode == "aead_aes256_gcm")
		return XE_AEAD_AES256_GCM;
	else if(mode == "xsalsa20_poly1305_lite_rtpsize")
		return XE_XSALSA20_POLY1305_LITE_RTPSIZE;
	else if(mode == "xsalsa20_poly1305_lite")
		return XE_XSALSA20_POLY1305_LITE;
	else if(mode == "xsalsa20_poly1305_suffix")
		return XE_XSALSA20_POLY1305_SUFFIX;
	else if(mode == "xsalsa20_poly1305")
		return XE_XSALSA20_POLY1305;
	return XE_ENCRYPTION_NONE;
}

static int parse_ready(xe_message& message, json& payload){
	std::string& ip = payload["ip"].get_ref<std::string&>();

	message.ready.ssrc = payload["ssrc"].get<uint>();
	message.ready.port = payload["port"].get<uint>();
	message.ready.encryption_modes = 0;

	if(inet_pton(AF_INET, ip.c_str(), &message.ready.ip) != 1)
		return XE_INVALID_RESPONSE;
	for(auto& mode : payload["modes"])
		message.ready.encryption_modes |= encryption_mode_from_string(mode.get_ref<std::string&>());
	return 0;
}

static int parse_session_description(xe_message& message, json& payload){
	uint i = 0;
	auto key = payload["secret_key"];

	message.session_description.encryption_mode = encryption_mode_from_string(payload["mode"]);

	if(message.session_description.encryption_mode == XE_ENCRYPTION_NONE ||
		!key.is_array() || key.size() != XE_ENCRYPT_KEY_SIZE)
		return XE_INVALID_RESPONSE;
	for(auto& val : key)
		message.session_description.secret_key[i++] = val.get<uint>();
	return 0;
}

static int parse_speaking(xe_message& message, json& payload){
	return 0;
}

static int parse_heartbeat_ack(xe_message& message, json& payload){
	message.heartbeat_ack.nonce = payload.get<uint>();

	return 0;
}

static int parse_hello(xe_message& message, json& payload){
	double interval = payload["heartbeat_interval"].get<double>();

	message.hello.heartbeat_interval = interval;

	return interval < 0 || interval > xe_max_value<uint>() ? XE_INVALID_RESPONSE : 0;
}

static int parse_resumed(xe_message& message, json& payload){
	return 0;
}

static int parse_client_disconnect(xe_message& message, json& payload){
	return 0;
}

static std::string make_string(const xe_string_view& str){
	return std::string(str.data(), str.size());
}

static json serialize_identify(xe_message& message){
	return {
		{"server_id", make_string(message.identify.server_id)},
		{"user_id", make_string(message.identify.user_id)},
		{"session_id", make_string(message.identify.session_id)},
		{"token", make_string(message.identify.token)}
	};
}

static json serialize_select_protocol(xe_message& message){
	return {
		{"protocol", make_string(message.select_protocol.protocol)},
		{"data", {
			{"address", make_string(message.select_protocol.address)},
			{"port", message.select_protocol.port},
			{"mode", xe_encryption_mode_to_string(message.select_protocol.mode)},
		}}
	};
}

static json serialize_heartbeat(xe_message& message){
	return message.heartbeat.nonce;
}

static json serialize_speaking(xe_message& message){
	return {
		{"speaking", message.speaking.speaking_flags},
		{"delay", message.speaking.delay},
		{"ssrc", message.speaking.ssrc}
	};
}

static json serialize_resume(xe_message& message){
	return {};
}

static json serialize_media_sink_wants(xe_message& message){
	return {
		{"any", message.media_sink_wants.want_audio ? 100 : 0}
	};
}

static json make_json(xe_message& message){
	switch(message.op){
		case XE_OP_IDENTIFY:
			return serialize_identify(message);
		case XE_OP_SELECT_PROTOCOL:
			return serialize_select_protocol(message);
		case XE_OP_HEARTBEAT:
			return serialize_heartbeat(message);
		case XE_OP_SPEAKING:
			return serialize_speaking(message);
		case XE_OP_RESUME:
			return serialize_resume(message);
		case XE_OP_MEDIA_SINK_WANTS:
			return serialize_media_sink_wants(message);
		default:
			return {};
	}
}

int xe_message::parse(xe_ptr data, size_t size){
	json message;

	try{
		message = json::parse((char*)data, (char*)data + size);
	}catch(json::exception& e){
		return XE_INVALID_RESPONSE;
	}catch(std::bad_alloc& e){
		return XE_ENOMEM;
	}

	json& payload = message["d"];

	try{
		op = (xe_message_opcode)message["op"].get<uint>();

		switch(op){
			case XE_OP_IDENTIFY:
			case XE_OP_SELECT_PROTOCOL:
			case XE_OP_HEARTBEAT:
			case XE_OP_RESUME:
				break;
			case XE_OP_READY:
				return parse_ready(*this, payload);
			case XE_OP_SESSION_DESCRIPTION:
				return parse_session_description(*this, payload);
			case XE_OP_SPEAKING:
				return parse_speaking(*this, payload);
			case XE_OP_HEARTBEAT_ACK:
				return parse_heartbeat_ack(*this, payload);
			case XE_OP_HELLO:
				return parse_hello(*this, payload);
			case XE_OP_RESUMED:
				return parse_resumed(*this, payload);
			case XE_OP_CLIENT_DISCONNECT:
				return parse_client_disconnect(*this, payload);
		}
	}catch(json::exception& e){}

	return XE_INVALID_RESPONSE;
}

bool xe_message::serialize(std::string& out){
	try{
		json message = {
			{"op", op},
			{"d", make_json(*this)}
		};

		out = message.dump();

		return true;
	}catch(std::bad_alloc& e){
		return false;
	}
}