#include "test.h"
#include "protocol/bom.pb.h"
#include "google/protobuf/util/json_util.h"

using namespace l3deditor::Bom;
using namespace l3deditor::Base;
std::string test::makeProto()
{
	Component topProto;
	topProto.set_name("JZ25-1");
	topProto.set_ctype(Component_CType_CTPrototype);
	Component_Prototype* protype = topProto.mutable_prototype();
	protype->set_cunits(Component_Prototype_CUnits_CUMM);
	protype->set_rootnodeid("5dd8c90da205c1868c6898bc");
	protype->add_childinsid("5dd8db8ca205c1868c6898c0");
	protype->add_childinsid("5dd8f1e77214f8868c19a3d2");
	topProto.set_drawstyle(DSFILLED);
	l3deditor::Bom::AnyValue* keyVal = topProto.add_property();
	keyVal->set_key("key1");
	keyVal->set_fval(10.0f);

	keyVal = topProto.add_property();
	keyVal->set_key("key2");
	keyVal->set_strval("StrVal");

	std::string outMsg;
	google::protobuf::util::JsonPrintOptions gjsonOp;
	gjsonOp.always_print_enums_as_ints = false;
	gjsonOp.always_print_primitive_fields = false;
	gjsonOp.preserve_proto_field_names = false;
	google::protobuf::util::Status stst = google::protobuf::util::MessageToJsonString(topProto, &outMsg, gjsonOp);
	return outMsg;
}

std::string test::makeIns()
{
	Component instant;
	instant.set_name("JZ25-1");
	instant.set_ctype(Component_CType_CTInstant);
	Component_Instant* ins = instant.mutable_instant();
	ins->set_prototypeid("5dd8c90da205c1868c6898bc");
	ins->set_plcid("1");
	Matrix44* mat4 = ins->mutable_transmatrix();
	mat4->set_m00(1.0f);
	mat4->set_m01(0.0f);
	mat4->set_m02(0.0f);
	mat4->set_m03(0.0f);

	mat4->set_m10(0.0f);
	mat4->set_m11(1.0f);
	mat4->set_m12(0.0f);
	mat4->set_m13(0.0f);

	mat4->set_m20(0.0f);
	mat4->set_m21(0.0f);
	mat4->set_m22(1.0f);
	mat4->set_m23(0.0f);

	mat4->set_m30(0.0f);
	mat4->set_m31(0.0f);
	mat4->set_m32(0.0f);
	mat4->set_m33(1.0f);

	l3deditor::Bom::AnyValue*  keyVal = instant.add_property();
	keyVal->set_key("key2");
	keyVal->set_strval("StrVal");

	std::string outMsg;
	google::protobuf::util::JsonPrintOptions gjsonOp;
	gjsonOp.always_print_enums_as_ints = false;
	gjsonOp.always_print_primitive_fields = false;
	gjsonOp.preserve_proto_field_names = false;
	google::protobuf::util::Status stst = google::protobuf::util::MessageToJsonString(instant, &outMsg, gjsonOp);
	return outMsg;
}
