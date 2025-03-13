#include "session.h"

using namespace xxlink;

xe_session::xe_session(uint session_, xe_link_node& node): connection(node){
	session = session_;
}

int xe_session::process_message(SessionMessage& message){
	if(message.has_voice_connection_control()){
		auto& control = *message.mutable_voice_connection_control();

		if(control.has_server_update())
			connection.server_update(*control.mutable_server_update());
		else if(control.has_state_update())
			connection.state_update(*control.mutable_state_update());
	}

	return 0;
}

int xe_session::close(){
	// todo
}

xe_session::~xe_session(){
	// todo
}