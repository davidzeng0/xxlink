#pragma once
#include "node.h"
#include "voice/connection.h"
#include "voice/player.h"
#include "proto/session.pb.h"

namespace xxlink{

class xe_session{
private:
	xe_voice_connection connection;
	xe_player player;
	uint session;
public:
	void (*close_callback)(xe_session& session);

	xe_session(uint session, xe_link_node& node);

	int process_message(SessionMessage& message);
	int close();

	~xe_session();
};

}