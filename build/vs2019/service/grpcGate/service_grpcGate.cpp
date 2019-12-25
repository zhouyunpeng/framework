#include "gateDef.h"
#include "skynet_socket.h"

#include <pthread.h>
#include <unistd.h>

#include <grpcpp/grpcpp.h>
#include <string>

#include "protocol/gateway.grpc.pb.h"
#include "API_Service_Impl.h"
#include "protocol/bom.pb.h"
#include "test.h"

using grpc::Server;
using grpc::ServerBuilder;

#define BACKLOG 128

#ifdef __cplusplus 
extern "C" {
#endif

	struct grpcGate*
		grpcGate_create(void) {
		struct grpcGate* g = (struct grpcGate*)skynet_malloc(sizeof(*g));
		if (g) {
			memset(g, 0, sizeof(*g));
			g->listen_id = -1;
			g->mongoDB = new MongoDB();
		}
		return g;
	}

	void
		grpcGate_release(struct grpcGate* g) {
		int i;
		struct skynet_context* ctx = g->ctx;
		for (i = 0; i < g->max_connection; i++) {
			struct connection* c = &g->conn[i];
			if (c->id >= 0) {
				skynet_socket_close(ctx, c->id);
			}
		}
		if (g->listen_id >= 0) {
			skynet_socket_close(ctx, g->listen_id);
		}
		messagepool_free(&g->mp);
		hashid_clear(&g->hash);
		skynet_free(g->conn);
		delete g->mongoDB;
		skynet_free(g);
	}

	static void* thread_grpc(void* p) 
	{
		grpcGate* gGate = (struct grpcGate*)p;
		std::string server_address("0.0.0.0:9090");
		APIServiceImpl service(gGate);
		ServerBuilder builder;
		builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		builder.RegisterService(&service);
		
		gGate->grpcServer = builder.BuildAndStart();
		std::cout << "skynet:BomServer listening on\r\n" << server_address << std::endl;
		gGate->grpcServer->Wait();
		_endthreadex(0);
		return 0;
	}

	static void
		_parm(char* msg, int sz, int command_sz) {
		while (command_sz < sz) {
			if (msg[command_sz] != ' ')
				break;
			++command_sz;
		}
		int i;
		for (i = command_sz; i < sz; i++) {
			msg[i - command_sz] = msg[i];
		}
		msg[i - command_sz] = '\0';
	}

	static void
		_forward_agent(struct grpcGate* g, int fd, uint32_t agentaddr, uint32_t clientaddr) {
		int id = hashid_lookup(&g->hash, fd);
		if (id >= 0) {
			struct connection* agent = &g->conn[id];
			agent->agent = agentaddr;
			agent->client = clientaddr;
		}
	}

	static void
		_ctrl(struct grpcGate* g, const void* msg, int sz) {
		struct skynet_context* ctx = g->ctx;
#ifdef _MSC_VER
		assert(sz <= 1024);
		char tmp[1024 + 1];
#else
		char tmp[sz + 1];
#endif
		memcpy(tmp, msg, sz);
		tmp[sz] = '\0';
		char* command = tmp;
		int i;
		if (sz == 0)
			return;
		for (i = 0; i < sz; i++) {
			if (command[i] == ' ') {
				break;
			}
		}
		if (memcmp(command, "kick", i) == 0) {
			_parm(tmp, sz, i);
			int uid = strtol(command, NULL, 10);
			int id = hashid_lookup(&g->hash, uid);
			if (id >= 0) {
				skynet_socket_close(ctx, uid);
			}
			return;
		}
		if (memcmp(command, "forward", i) == 0) {
			_parm(tmp, sz, i);
			char* client = tmp;
			char* idstr = strsep(&client, " ");
			if (client == NULL) {
				return;
			}
			int id = strtol(idstr, NULL, 10);
			char* agent = strsep(&client, " ");
			if (client == NULL) {
				return;
			}
			uint32_t agent_handle = strtoul(agent + 1, NULL, 16);
			uint32_t client_handle = strtoul(client + 1, NULL, 16);
			_forward_agent(g, id, agent_handle, client_handle);
			return;
		}
		if (memcmp(command, "broker", i) == 0) {
			_parm(tmp, sz, i);
			g->broker = skynet_queryname(ctx, command);
			return;
		}
		if (memcmp(command, "start", i) == 0) {
			_parm(tmp, sz, i);
			int uid = strtol(command, NULL, 10);
			int id = hashid_lookup(&g->hash, uid);
			if (id >= 0) {
				skynet_socket_start(ctx, uid);
			}
			return;
		}
		if (memcmp(command, "close", i) == 0) {
			if (g->listen_id >= 0) {
				skynet_socket_close(ctx, g->listen_id);
				g->listen_id = -1;
			}
			return;
		}
		skynet_error(ctx, "[gate] Unkown command : %s", command);
	}

	static void
		_report(struct grpcGate* g, const char* data, ...) {
		if (g->watchdog == 0) {
			return;
		}
		struct skynet_context* ctx = g->ctx;
		va_list ap;
		va_start(ap, data);
		char tmp[1024];
		int n = vsnprintf(tmp, sizeof(tmp), data, ap);
		va_end(ap);

		skynet_send(ctx, 0, g->watchdog, PTYPE_TEXT, 0, tmp, n);
	}

	static void
		_forward(struct grpcGate* g, struct connection* c, int size) {
		struct skynet_context* ctx = g->ctx;
		int fd = c->id;
		if (fd <= 0) {
			// socket error
			return;
		}
		if (g->broker) {
			void* temp = skynet_malloc(size);
			databuffer_read(&c->buffer, &g->mp, temp, size);
			skynet_send(ctx, 0, g->broker, g->client_tag | PTYPE_TAG_DONTCOPY, fd, temp, size);
			return;
		}
		if (c->agent) {
			void* temp = skynet_malloc(size);
			databuffer_read(&c->buffer, &g->mp, temp, size);
			skynet_send(ctx, c->client, c->agent, g->client_tag | PTYPE_TAG_DONTCOPY, fd, temp, size);
		}
		else if (g->watchdog) {
			char* tmp = (char*)skynet_malloc(size + 32);
			int n = _snprintf_s(tmp, 32, 32, "%d data ", c->id);
			databuffer_read(&c->buffer, &g->mp, tmp + n, size);
			skynet_send(ctx, 0, g->watchdog, PTYPE_TEXT | PTYPE_TAG_DONTCOPY, fd, tmp, size + n);
		}
	}

	static void
		dispatch_message(struct grpcGate* g, struct connection* c, int id, void* data, int sz) {
		databuffer_push(&c->buffer, &g->mp, data, sz);
		for (;;) {
			int size = databuffer_readheader(&c->buffer, &g->mp, g->header_size);
			if (size < 0) {
				return;
			}
			else if (size > 0) {
				if (size >= 0x1000000) {
					struct skynet_context* ctx = g->ctx;
					databuffer_clear(&c->buffer, &g->mp);
					skynet_socket_close(ctx, id);
					skynet_error(ctx, "Recv socket message > 16M");
					return;
				}
				else {
					_forward(g, c, size);
					databuffer_reset(&c->buffer);
				}
			}
		}
	}

	static void
		dispatch_socket_message(struct grpcGate* g, const struct skynet_socket_message* message, int sz) {
		struct skynet_context* ctx = g->ctx;
		switch (message->type) {
		case SKYNET_SOCKET_TYPE_DATA: {
			int id = hashid_lookup(&g->hash, message->id);
			if (id >= 0) {
				struct connection* c = &g->conn[id];
				dispatch_message(g, c, message->id, message->buffer, message->ud);
			}
			else {
				skynet_error(ctx, "Drop unknown connection %d message", message->id);
				skynet_socket_close(ctx, message->id);
				skynet_free(message->buffer);
			}
			break;
		}
		case SKYNET_SOCKET_TYPE_CONNECT: {
			if (message->id == g->listen_id) {
				// start listening
				break;
			}
			int id = hashid_lookup(&g->hash, message->id);
			if (id < 0) {
				skynet_error(ctx, "Close unknown connection %d", message->id);
				skynet_socket_close(ctx, message->id);
			}
			break;
		}
		case SKYNET_SOCKET_TYPE_CLOSE:
		case SKYNET_SOCKET_TYPE_ERROR: {
			int id = hashid_remove(&g->hash, message->id);
			if (id >= 0) {
				struct connection* c = &g->conn[id];
				databuffer_clear(&c->buffer, &g->mp);
				memset(c, 0, sizeof(*c));
				c->id = -1;
				_report(g, "%d close", message->id);
			}
			break;
		}
		case SKYNET_SOCKET_TYPE_ACCEPT:
			// report accept, then it will be get a SKYNET_SOCKET_TYPE_CONNECT message
			assert(g->listen_id == message->id);
			if (hashid_full(&g->hash)) {
				skynet_socket_close(ctx, message->ud);
			}
			else {
				struct connection* c = &g->conn[hashid_insert(&g->hash, message->ud)];
				if (sz >= sizeof(c->remote_name)) {
					sz = sizeof(c->remote_name) - 1;
				}
				c->id = message->ud;
				memcpy(c->remote_name, message + 1, sz);
				c->remote_name[sz] = '\0';
				_report(g, "%d open %d %s:0", c->id, c->id, c->remote_name);
				skynet_error(ctx, "socket open: %x", c->id);
			}
			break;
		case SKYNET_SOCKET_TYPE_WARNING:
			skynet_error(ctx, "fd (%d) send buffer (%d)K", message->id, message->ud);
			break;
		}
	}

	static const char* collection_name = "Component";
	static const char* uri_string = "mongodb://192.168.1.5/?authSource=BOM&appname=client-example";

	static int
		_cb(struct skynet_context* ctx, void* ud, int type, int session, uint32_t source, const void* msg, size_t sz) {
		struct grpcGate* g = (struct grpcGate*)ud;

		const char* agentc = skynet_command(ctx, "LAUNCH", "agentc freeCAD");
		uint32_t handle_id = strtoul(agentc + 1, NULL, 16);

		/*std::string jsonProto = test::makeProto();
		std::string jsonIns = test::makeIns();

		g->mongoDB->Connect(uri_string, "BOM");
		g->mongoDB->InsertOne(collection_name, jsonIns, "");*/

		switch (type) {
		case PTYPE_TEXT: 
		{
			std::string strParam((char*)msg, sz);
			int iRet = pthread_create(&g->grpcThreadId, NULL, thread_grpc, g);
			skynet_error(ctx, "thread_grpc started");
		}
			//_ctrl(g, msg, (int)sz);
			break;
		case PTYPE_CLIENT: {
			if (sz <= 4) {
				skynet_error(ctx, "Invalid client message from %x", source);
				break;
			}
			// The last 4 bytes in msg are the id of socket, write following bytes to it
			const uint8_t* idbuf = (const uint8_t*)msg + sz - 4;
			uint32_t uid = idbuf[0] | idbuf[1] << 8 | idbuf[2] << 16 | idbuf[3] << 24;
			int id = hashid_lookup(&g->hash, uid);
			if (id >= 0) {
				// don't send id (last 4 bytes)
				skynet_socket_send(ctx, uid, (void*)msg, sz - 4);
				// return 1 means don't free msg
				return 1;
			}
			else {
				skynet_error(ctx, "Invalid client id %d from %x", (int)uid, source);
				break;
			}
		}
		case PTYPE_SOCKET:
			// recv socket message from skynet_socket
			dispatch_socket_message(g, (struct skynet_socket_message*)msg, (int)(sz - sizeof(struct skynet_socket_message)));
			break;
		}
		return 0;
	}

	int grpcGate_init(struct grpcGate* g, struct skynet_context* ctx, char* parm) 
	{
		int client_tag = 0;
		if (client_tag == 0) {
			client_tag = PTYPE_CLIENT;
		}

		g->watchdog = skynet_queryname(ctx, "watchdog");
		g->ctx = ctx;

		hashid_init(&g->hash, 5);
		g->conn = (struct connection*)skynet_malloc(5 * sizeof(struct connection));
		memset(g->conn, 0, 5 * sizeof(struct connection));
		g->max_connection = 5;
		int i;
		for (i = 0; i < 5; i++) {
			g->conn[i].id = -1;
		}

		g->client_tag = client_tag;
		g->header_size = 2;

		skynet_callback(ctx, g, _cb);
		const char* self = skynet_command(ctx, "REG", NULL);
		uint32_t handle_id = strtoul(self + 1, NULL, 16);
		// it must be first message
		std::string strParam;
		if (parm) {
			strParam = parm;
		}
		skynet_send(ctx, 0, handle_id, PTYPE_TEXT, 0, (void*)strParam.c_str(), strParam.length());
		return 0;
	}
#ifdef __cplusplus 
}
#endif
