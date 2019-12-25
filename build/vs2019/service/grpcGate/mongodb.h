#pragma once
#include <string>

struct QueryContext;
class MongoDbImpl;
class MongoDB
{
public:
	MongoDB();
	~MongoDB();
private:
	MongoDbImpl* m_impl;
	friend class MongoDbImpl;
public:
	int					 Connect(const std::string& dbAddr, const std::string& dbName);
	struct QueryContext* QueryCollections(const std::string& colName, const std::string& query, const std::string& options);
	bool				 CursorNext(struct QueryContext* ioContext, std::string& oResult);
	void				 QueryCtxDestory(struct QueryContext* iContext);
	int					 InsertOne(const std::string& colName, const std::string& jsonDoc, const std::string& options);
	bool				 IsConnected();
};

