#pragma once
#include "skynet.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#include "databuffer.h"
#include "hashid.h"
#include <mongodb.h>
#include <grpcpp/grpcpp.h>

class APIServiceImpl;
#ifdef __cplusplus 
extern "C" {
	struct connection {
		int id;	// skynet_socket id
		uint32_t agent;
		uint32_t client;
		char remote_name[32];
		struct databuffer buffer;
	};

	struct grpcGate {
		struct skynet_context* ctx;
		int listen_id;
		uint32_t watchdog;
		uint32_t broker;
		int client_tag;
		int header_size;
		int max_connection;
		struct hashid hash;
		struct connection* conn;
		// todo: save message pool ptr for release
		struct messagepool mp;
		pthread_t grpcThreadId;
		MongoDB* mongoDB;
		std::unique_ptr<grpc::Server> grpcServer;
	};
}
#endif