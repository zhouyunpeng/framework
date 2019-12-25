#include "mongodb.h"
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <mongoc/mongoc.h>
using namespace std;

struct QueryContext {
	mongoc_client_t* client;
	mongoc_collection_t* collection;
	mongoc_cursor_t* cursor;
};

class MongoDbImpl {
public:
	MongoDB* publ;
	MongoDbImpl(MongoDB* pOwn);
	~MongoDbImpl();
	bool _bConnect = false;
	mongoc_client_pool_t* pool;
	//mongoc_client_t* client;
	mongoc_database_t* database;
	mongoc_uri_t* uri;
};

MongoDbImpl::MongoDbImpl(MongoDB* pOwn) :publ(pOwn)
{

}

MongoDbImpl::~MongoDbImpl()
{	
	if (_bConnect) {
		mongoc_database_destroy(database);
		//mongoc_client_destroy(client);
		mongoc_client_pool_destroy(pool);
		mongoc_uri_destroy(uri);
		mongoc_cleanup();
	}
	_bConnect = false;
}

MongoDB::MongoDB()
{
	m_impl = new MongoDbImpl(this);
	
}
MongoDB::~MongoDB() 
{
	delete m_impl;
}

int MongoDB::Connect(const std::string& dbAddr, const std::string& dbName)
{
	bson_t* command, reply;
	bson_error_t          err;
	bool                  retval;
	if (m_impl->_bConnect) { return true; };
	mongoc_init();

	m_impl->uri = mongoc_uri_new_with_error(dbAddr.c_str(), &err);
	if (!m_impl->uri) {
		fprintf(stderr,
			"failed to parse URI: %s\n"
			"error message:       %s\n",
			dbAddr.c_str(),
			err.message);
		mongoc_uri_destroy(m_impl->uri);
		return EXIT_FAILURE;
	}
	m_impl->pool = mongoc_client_pool_new(m_impl->uri);
	mongoc_client_pool_set_error_api(m_impl->pool, 2);
	
	bson_t ping = BSON_INITIALIZER;
	BSON_APPEND_INT32(&ping, "ping", 1);
	command = BCON_NEW("ping", BCON_INT32(1));

	mongoc_client_t* client = mongoc_client_pool_pop(m_impl->pool);

	m_impl->database = mongoc_client_get_database(client, dbName.c_str());
	if (!m_impl->database) {
		mongoc_client_pool_push(m_impl->pool, client);
		mongoc_uri_destroy(m_impl->uri);
		mongoc_cleanup();
		return false;
	}
	
	retval = mongoc_client_command_simple(
		client, dbName.c_str(), &ping, NULL, NULL, &err);
	bson_destroy(&ping);
	if (!retval) {
		mongoc_database_destroy(m_impl->database);
		mongoc_client_pool_push(m_impl->pool, client);
		mongoc_uri_destroy(m_impl->uri);
		mongoc_cleanup();
		return EXIT_FAILURE;
	}
	mongoc_client_pool_push(m_impl->pool, client);
	m_impl->_bConnect = true;
	return EXIT_SUCCESS;
}

struct QueryContext* MongoDB::QueryCollections(const std::string& colName, const std::string& query, const std::string& options)
{
	if (!m_impl->_bConnect) { return nullptr; };
	const char* dbName = mongoc_database_get_name(m_impl->database);

	mongoc_client_t* client = mongoc_client_pool_pop(m_impl->pool);
	mongoc_collection_t* collection = mongoc_client_get_collection(client, dbName, colName.c_str());
	if (!collection) 
	{ 
		mongoc_client_pool_push(m_impl->pool, client);
		return nullptr; 
	}

	bson_error_t err;
	bson_t* bsQuery = nullptr;
	bson_t* bsOptions = nullptr;
	if (query.empty()) {
		bsQuery = new bson_t();
		bson_init(bsQuery);
	}
	else {
		bsQuery = bson_new_from_json((const uint8_t*)query.c_str(), query.length(), &err);
	}

	if (!bsQuery) {
		mongoc_client_pool_push(m_impl->pool, client);
		mongoc_collection_destroy(collection);
		return nullptr;
	}

	if (!options.empty()) {
		bsOptions = bson_new_from_json((const uint8_t*)options.c_str(), options.length(), &err);
	}
			
	mongoc_cursor_t* cursor = mongoc_collection_find_with_opts(
		collection,
		bsQuery,
		bsOptions,  /* additional options */
		NULL); /* read prefs, NULL for default */

	if (!cursor) {
		bson_destroy(bsQuery);
		if (bsOptions) {
			bson_destroy(bsQuery);
		}
		mongoc_client_pool_push(m_impl->pool, client);
		mongoc_collection_destroy(collection);
		return nullptr;
	}
	QueryContext* oContext = new QueryContext();
	oContext->client = client;
	oContext->collection = collection;
	oContext->cursor = cursor;

	bson_destroy(bsQuery);
	if (bsOptions) {
		bson_destroy(bsOptions);
	}
	return oContext;
}

bool MongoDB::CursorNext(struct QueryContext* ioContext, string& oResult)
{
	if (!ioContext) {
		return false;
	}
	const bson_t* doc;
	bool bRet = mongoc_cursor_next(ioContext->cursor, &doc);
	if (bRet) 
	{
		//char* str = bson_as_canonical_extended_json(doc, NULL);
		char* str = bson_as_relaxed_extended_json(doc, NULL);
		if (str) {
			oResult = str;
			bson_free(str);
		}
	}
	return bRet;
}

void MongoDB::QueryCtxDestory(struct QueryContext* iContext)
{
	if (!iContext || !iContext->collection) {
		return;
	}
	mongoc_client_pool_push(m_impl->pool, iContext->client);
	mongoc_cursor_destroy(iContext->cursor);
	mongoc_collection_destroy(iContext->collection);
	delete iContext;
}

int MongoDB::InsertOne(const std::string& colName, const std::string& jsonDoc, const std::string& options)
{
	if (!m_impl->_bConnect) { return -1; };
	const char* dbName = mongoc_database_get_name(m_impl->database);

	mongoc_client_t* client = mongoc_client_pool_pop(m_impl->pool);
	mongoc_collection_t* collection = mongoc_client_get_collection(client, dbName, colName.c_str());
	if (!collection)
	{
		mongoc_client_pool_push(m_impl->pool, client);
		return -1;
	}

	bson_error_t error;

	bson_t* bstDoc = bson_new_from_json((const uint8_t*)jsonDoc.c_str(), jsonDoc.length(), &error);
	
	if (!bstDoc) {
		mongoc_client_pool_push(m_impl->pool, client);
		mongoc_collection_destroy(collection);
		return -1;
	}

	bson_t* bsOptions = nullptr;
	if (!options.empty()) {
		bsOptions = bson_new_from_json((const uint8_t*)options.c_str(), options.length(), &error);
	}

	if (!mongoc_collection_insert_one(
		collection, bstDoc, NULL, NULL, &error)) {
		fprintf(stderr, "%s\n", error.message);
	}

	mongoc_collection_destroy(collection);
	mongoc_client_pool_push(m_impl->pool, client);
	
	bson_destroy(bstDoc);
	if (bsOptions) {
		bson_destroy(bsOptions);
	}
}

bool MongoDB::IsConnected()
{
	return m_impl->_bConnect;
}
