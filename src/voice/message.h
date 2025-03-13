#pragma once
#include <netdb.h>
#include <xstd/types.h>
#include <xstd/string.h>
#include "encryption.h"

namespace xxlink{

enum xe_message_opcode{
	XE_OP_IDENTIFY = 0,
	XE_OP_SELECT_PROTOCOL = 1,
	XE_OP_READY = 2,
	XE_OP_HEARTBEAT = 3,
	XE_OP_SESSION_DESCRIPTION = 4,
	XE_OP_SPEAKING = 5,
	XE_OP_HEARTBEAT_ACK = 6,
	XE_OP_RESUME = 7,
	XE_OP_HELLO = 8,
	XE_OP_RESUMED = 9,
	XE_OP_VIDEO = 12,
	XE_OP_CLIENT_DISCONNECT = 13,
	XE_OP_SESSION_UPDATE = 14,
	XE_OP_MEDIA_SINK_WANTS = 15,
	XE_OP_VOICE_BACKEND_VERSION = 16,
	XE_OP_CHANNEL_OPTIONS_UPDATE = 17
};

struct xe_message_identify{
	xe_string_view server_id;
	xe_string_view user_id;
	xe_string_view session_id;
	xe_string_view token;
};

struct xe_message_select_protocol{
	xe_string_view protocol;
	xe_string_view address;
	xe_encryption_mode mode;
	ushort port;
};

struct xe_message_ready{
	in_addr ip;
	uint ssrc;
	uint encryption_modes;
	ushort port;
};

struct xe_message_heartbeat{
	uint nonce;
};

struct xe_message_session_description{
	xe_encryption_mode encryption_mode;
	byte secret_key[XE_ENCRYPT_KEY_SIZE];
};

enum xe_speaking_flags{
	XE_SPEAKING_NONE = 0x0,
	XE_SPEAKING_MIC = 0x1,
	XE_SPEAKING_SOUNDSHARE = 0x2,
	XE_SPEAKING_PRIO = 0x4
};

struct xe_message_speaking{
	uint speaking_flags;
	uint delay;
	uint ssrc;
};

struct xe_message_heartbeat_ack{
	uint nonce;
};

struct xe_message_resume{
	xe_string_view server_id;
	xe_string_view session_id;
	xe_string_view token;
};

struct xe_message_hello{
	uint heartbeat_interval;
};

struct xe_message_resumed{
	/* intentionally empty */
};

struct xe_message_client_disconnect{

};

struct xe_message_media_sink_wants{
	bool want_audio;
};

class xe_message{
public:
	xe_message_opcode op;

	union{
		xe_message_identify identify;
		xe_message_select_protocol select_protocol;
		xe_message_ready ready;
		xe_message_heartbeat heartbeat;
		xe_message_session_description session_description;
		xe_message_speaking speaking;
		xe_message_heartbeat_ack heartbeat_ack;
		xe_message_resume resume;
		xe_message_hello hello;
		xe_message_resumed resumed;
		xe_message_client_disconnect disconnect;
		xe_message_media_sink_wants media_sink_wants;
	};

	xe_message(){}

	int parse(xe_ptr data, size_t size);

	bool serialize(std::string& out);

	~xe_message(){}
};

}