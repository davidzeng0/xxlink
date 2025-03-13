#include <xutil/log.h>
#include <xxlink/node.h>

using namespace xxlink;

static xe_link_node node;

void handle_error(xe_cstr where, int err){
	if(!err)
		return;
	xe_log_error(&node, "%s: %s", where, xe_strerror(err));
	exit(EXIT_FAILURE);
}

int main(){
	xe_log_set_level(XE_LOG_DEBUG);

	handle_error("init", node.init());
	handle_error("listen", node.listen("127.0.0.1", 5360));
	handle_error("run", node.run());

	node.close();

	return 0;
}