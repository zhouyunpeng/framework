#include "API_Service_Impl.h"
#include <google\protobuf\message.h>

using namespace std;
using namespace google::protobuf;
using google::protobuf::util::JsonStringToMessage;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;
using l3deditor::Gateway::BomRequest;
using l3deditor::Gateway::BomResponse;
using l3deditor::Gateway::APIService;
using l3deditor::Gateway::Empty;
using l3deditor::Gateway::DocIdStreamingResponse;
using l3deditor::Gateway::CompStreamingResponse;
using l3deditor::Bom::Document;


APIServiceImpl::APIServiceImpl(struct grpcGate* pGate) 
{
	m_pGate = pGate;
}
APIServiceImpl::~APIServiceImpl() {}

void APIServiceImpl::CopyClientMetadataToResponse(grpc::ServerContext* context)
{
	for (auto& client_metadata : context->client_metadata()) {
		context->AddInitialMetadata(std::string(client_metadata.first.data(),
			client_metadata.first.length()),
			std::string(client_metadata.second.data(),
				client_metadata.second.length()));
		context->AddTrailingMetadata(
			std::string(client_metadata.first.data(),
				client_metadata.first.length()),
			std::string(client_metadata.second.data(),
				client_metadata.second.length()));
	}
}

::grpc::Status APIServiceImpl::CreateAppIns(::grpc::ServerContext* context, const ::l3deditor::Gateway::ClinetInfo* request, ::l3deditor::Gateway::ClinetInfo* response)
{
	throw std::logic_error("The method or operation is not implemented.");
}

::grpc::Status APIServiceImpl::CmdRun(::grpc::ServerContext* context, const ::l3deditor::Gateway::CmdRequest* request, ::l3deditor::Base::CommandRet* response)
{
	throw std::logic_error("The method or operation is not implemented.");
}

::grpc::Status APIServiceImpl::CmdRunbat(::grpc::ServerContext* context, ::grpc::ServerReaderWriter<::l3deditor::Base::CommandRet, ::l3deditor::Gateway::CmdRequest>* stream)
{
	throw std::logic_error("The method or operation is not implemented.");
}

::grpc::Status APIServiceImpl::ListDocIds(::grpc::ServerContext* context, const ::l3deditor::Gateway::Empty* request, ::grpc::ServerWriter<::l3deditor::Gateway::DocIdStreamingResponse>* writer)
{
	CopyClientMetadataToResponse(context);

	MongoDB* pMongoDB = m_pGate->mongoDB;
	string strOptions = "{\"projection\":{\"field\":0}}";
	struct QueryContext* queryCtx = pMongoDB->QueryCollections("Doc", "", strOptions.c_str());
	int iDocCnt = 1;
	string jsonDoc;
	::grpc::Status grpcStatus;
	util::JsonParseOptions jsonParseOp;
	jsonParseOp.ignore_unknown_fields = true;
	while (pMongoDB->CursorNext(queryCtx, jsonDoc))
	{
		if (context->IsCancelled()) {
			std::cout << "skynet:Call ListDocIds_Cancelled" << std::endl;
			grpcStatus = Status::CANCELLED;
			break;
		}
		Document doc;
		util::Status parseStatus = JsonStringToMessage(jsonDoc, &doc, jsonParseOp);
		if (!parseStatus.ok()) {
			continue;
		}

		DocIdStreamingResponse response;
		auto idMap = doc._id();
		auto idItor = idMap.find("$oid");
		std::string objId;
		if (idItor != idMap.cend()) {
			response.set_documentid(idItor->second);
			writer->Write(response);
		}
	}
	pMongoDB->QueryCtxDestory(queryCtx);
	std::cout << "skynet:ListDocIds" << std::endl;
	return Status::OK;
}

::grpc::Status APIServiceImpl::GetBom(::grpc::ServerContext* context, const ::l3deditor::Gateway::BomRequest* request, ::l3deditor::Gateway::BomResponse* response)
{
	CopyClientMetadataToResponse(context);
	std::cout << "skynet:GetBom" << std::endl;
	return Status::OK;
}

::grpc::Status APIServiceImpl::GetChildren(::grpc::ServerContext* context, const ::l3deditor::Gateway::BomRequest* request, ::grpc::ServerWriter<::l3deditor::Gateway::CompStreamingResponse>* writer)
{
	CopyClientMetadataToResponse(context);
	
	switch (request->bom_oneof_case())
	{
	case BomRequest::BomOneofCase::kDocumentId:
		break;
	case BomRequest::BomOneofCase::kComponentId:
		break;
	default:
		break;
	}

	int bomCoun = 1;
	for (int i = 0; i < bomCoun; i++) {
		if (context->IsCancelled()) {
			std::cout << "skynet:Call GetChildren_Cancelled" << std::endl;
			return Status::CANCELLED;
		}
		CompStreamingResponse response;
		std::cout << "skynet:Call GetChildren" << std::endl;
		writer->Write(response);
	}
	return Status::OK;
}
