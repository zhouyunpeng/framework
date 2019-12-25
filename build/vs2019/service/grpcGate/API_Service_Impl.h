#ifndef L3DEDITOR_SKYNET_GATEWAY_BOM_SERVICE_IMPL_H_
#define L3DEDITOR_SKYNET_GATEWAY_BOM_SERVICE_IMPL_H_

/**
 *
 * Copyright 2019 L3DEditorOnline Group
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <grpcpp/grpcpp.h>
#include <string>

#include "protocol/gateway.grpc.pb.h"
#include "gateDef.h"

class APIServiceImpl final :
	public l3deditor::Gateway::APIService::Service
{
public:
	APIServiceImpl(struct grpcGate* pGate);
	~APIServiceImpl() override;
private:
	struct grpcGate* m_pGate;
public:
	void CopyClientMetadataToResponse(grpc::ServerContext* context);
	virtual ::grpc::Status CreateAppIns(::grpc::ServerContext* context, const ::l3deditor::Gateway::ClinetInfo* request, ::l3deditor::Gateway::ClinetInfo* response) override;
	virtual ::grpc::Status CmdRun(::grpc::ServerContext* context, const ::l3deditor::Gateway::CmdRequest* request, ::l3deditor::Base::CommandRet* response) override;
	virtual ::grpc::Status CmdRunbat(::grpc::ServerContext* context, ::grpc::ServerReaderWriter<::l3deditor::Base::CommandRet, ::l3deditor::Gateway::CmdRequest>* stream) override;
	virtual ::grpc::Status ListDocIds(::grpc::ServerContext* context, const ::l3deditor::Gateway::Empty* request, ::grpc::ServerWriter<::l3deditor::Gateway::DocIdStreamingResponse>* writer) override;
	virtual ::grpc::Status GetBom(::grpc::ServerContext* context, const ::l3deditor::Gateway::BomRequest* request, ::l3deditor::Gateway::BomResponse* response) override;
	virtual ::grpc::Status GetChildren(::grpc::ServerContext* context, const ::l3deditor::Gateway::BomRequest* request, ::grpc::ServerWriter<::l3deditor::Gateway::CompStreamingResponse>* writer) override;
};
#endif //L3DEDITOR_SKYNET_GATEWAY_BOM_SERVICE_IMPL_H_

