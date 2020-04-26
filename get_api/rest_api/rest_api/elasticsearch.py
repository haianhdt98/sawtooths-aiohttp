from elasticsearch import Elasticsearch
import uuid
import logging

es = Elasticsearch([{"host":"178.128.217.254", "port":"9200"}])

def create_user_index():
    if not es.indices.exists(index="polls_user"):
        body = {
            "mappings":{
                "properties":{
                    "username":{"type":"keyword"},
                    "hashed_password":{"type":"text"},
                    "encrypted_private_key":{"type":"text"},
                    "public_key":{"type":"text"},
                    "transactionIdBlockchain":{"type":"text"}
                }
            }
        }
        try:
            res = es.indices.create(index='polls_user', body=body)
            return res
        except Exception as e:
            print("already exist")

create_user_index()

async def getUserByUsername(
          username,):
    body = {
        "query": {
            "match": {
                "username": username
            }
        }
    }
    res = es.search(index='polls_user', body=body)

    try:
      return res['hits']['hits'][0]['_source']
    except:
      return []

async def createUser(
          username,
          hashed_password,
          encrypted_private_key,
          public_key,
          transactionIdBlockchain):
    body={
        "transactionIdBlockchain":transactionIdBlockchain,
        "username":username,
        "hashed_password":hashed_password.hex(),
        "encrypted_private_key":encrypted_private_key.hex(),
        "public_key":public_key
    }
    res = es.index(index='polls_user', doc_type='_doc', body=body)
    return res

def get_data(index, endpoint_url, public_key ):
    query = {
        'query': {
            'bool':{
                'should': [
                    {'match': {'index': index}},
                    {'match': {'public_key': public_key}},
                    {'match': {'endpoint_url': endpoint_url}}
                ]
            }
        }
    }
    res = es.search(index="data-eth-test", body=query)
    try:
        result = res['hits']['hits'][0]
        data = result['_source']['data']['data']
        return data
    except:
        return {'status': 'fall'}

def create_transaction_index():
  if not es.indices.exists(index="transaction"):
    body={
    "mappings": {
      "properties": {
        "transactionIdBlockchain":{"type":"text"},
        "timestamp":{"type":"date","format":"epoch_second"},
          "id":{"type":"keyword"},
          "name":{"type":"text"}
        }
      }
    }
    try:
        res = es.indices.create(index='transaction', body=body)
        return res
    except Exception as e:
        print("already exist")
# Create index if not exist
create_transaction_index()



