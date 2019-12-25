local skynet = require "skynet"
require "skynet.manager"	-- import skynet.launch, ...

local globalname = {}
local queryname = {}
local grpc = {}
local grpc_service


skynet.start(function()
	grpc_service = assert(skynet.launch("grpcGate", "BomService"))
	skynet.error("grpcGateC start")
	skynet.exit()
end)
