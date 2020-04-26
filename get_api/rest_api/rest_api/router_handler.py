import datetime
from json.decoder import JSONDecodeError
import logging
import time
import json

from aiohttp.web import json_response
from aiohttp.web_request import Request
import bcrypt
import swagger
from Crypto.Cipher import AES
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
from google.protobuf.json_format import MessageToDict


# defined in [[errors.py]]
from rest_api.errors import ApiBadRequest
from rest_api.errors import ApiNotFound
from rest_api.errors import ApiUnauthorized
from rest_api.errors import TransactionInvalid
# defined in [[elasticsearch.py]]
from rest_api import elasticsearch

# generated from **Protobuf**
from protobuf import user_pb2

from jsonschema import validate
from jsonschema import ValidationError

from rest_api.ipfs_services.main import *

LOGGER = logging.getLogger(__name__)


class RouteHandler(object):
    def __init__(self, loop, messenger):
        self._loop = loop
        self._messenger = messenger

    async def all_transactions(self, request):
        requests = await Request.text(request)
        requests_content = json.loads(requests.content)
        transaction_box = requests_content['data']

        transaction_list = []

        try:
            for trans in transaction_box:
                trans_index = trans['index']
                trans_endpoint = trans['url']
                trans_publickey = trans['publicKey']

                data = elasticsearch.get_data(trans_index, trans_endpoint, trans_publickey)

                transaction_list.append({
                    "index" : trans_index,
                    "data" : data
                })
            
            result_json = json.loads(json.dumps(transaction_list))
            return get_response(result_json)
        except Exception as e:
            LOGGER.error(err)
            return json_response({"status": "failed"})



    async def create_user(self, request):
        
        body = await decode_request(request)
        required_fields = ['username','password','data']
        validate_fields(required_fields, body)

        schema = {"type":"object", "properties":{"username":{"type":"string"},"password":{"type":"string"},"data":{"type":"string"} }}
        validate_types(schema, body)

        public_key, private_key = self._messenger.get_new_key_pair()
        
        username = body.get('username')
        password = body.get('password')
        data = body.get('data')

        user = await elasticsearch.getUserByUsername(username)
        if user:
            return json_response({'status': 'Failure',
                                  'statusCode': 3,
                                  'details': 'Username already existed'})
        
        transactionUnique = await self._messenger.send_create_user_transaction(
            private_key=private_key,
            username=username,
            data = data,
            timestamp=get_time(),
        )

        transactionUniqueId = transactionUnique.transactions[0].header_signature
        encrypted_private_key = encrypt_private_key(
            request.app['aes_key'], public_key, private_key)
        hashed_password = hash_password(body.get('password'))

        await elasticsearch.create_user(
            username=body.get('username'),
            data = data,
            hashed_password=hashed_password,
            encrypted_private_key=encrypted_private_key,
            public_key=public_key,
            transactionIdBlockchain = transactionUniqueId
        )

        return json_response({
            "status": "Success",
            "statusCode": 0,
            "details": "User created",
            "transaction_Id":transactionUniqueId
        })
    async def query_elasticsearch(self, request):
        body = await decode_request(request)
        data_return =  await elasticsearch.query_elasticsearch(body = body)
        return json_response(data_return)


    async def authenticate(self, request):
        
        body = await decode_request(request)
        required_fields = ['username', 'password']
        validate_fields(required_fields, body)

        schema = {"type":"object", "properties":{"username":{"type":"string"},"password":{"type":"string"}}}
        validate_types(schema, body)

        username = body.get('username')
        password = bytes(body.get('password'), 'utf-8')

        user = await elasticsearch.getUserByUsername(username)
        if len(user) == 0:
            return json_response({'status': 'Failure',
                                 'statusCode': 2,
                                 'details': 'Username does not exist'})

        hashed_password = user['hashed_password']
        if not bcrypt.checkpw(password, bytes.fromhex(hashed_password)):
            return json_response({'status': 'Failure',
                                 'statusCode': 4,
                                 'details': 'Wrong password'})

        token = generate_auth_token(
            request.app['secret_key'], user['username'])

        return json_response({"result": "Success", "statusCode": 0, 'authorization': token})


async def decode_request(request):
    try:
        return await request.json()
    except JSONDecodeError:
        raise ApiBadRequest('Improper JSON format')


def validate_fields(required_fields, body):
    for field in required_fields:
        if body.get(field) is None:
            raise ApiBadRequest(
                "'{}' parameter is required".format(field))

def validate_types(schema, body):
    try:
        validate(instance=body, schema=schema)
    except ValidationError as e:
        string_array_error = str(e).split("\n")
        array = {"On instance","[","]","'",":"," "}
        for a in array:
            string_array_error[5] = string_array_error[5].replace(a,"")
        message = string_array_error[0]+" on field '"+ string_array_error[5] +"'"

        raise ApiBadRequest(message)


def encrypt_private_key(aes_key, public_key, private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    return cipher.encrypt(private_key)


def decrypt_private_key(aes_key, public_key, encrypted_private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    private_key = cipher.decrypt(bytes.fromhex(encrypted_private_key))
    return private_key


def hash_password(password):
    return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())


def get_time():
    dts = datetime.datetime.utcnow()
    return round(time.mktime(dts.timetuple()) + dts.microsecond/1e6)


def generate_auth_token(secret_key, username):
    serializer = Serializer(secret_key)
    token = serializer.dumps({'username': username})
    return token.decode('ascii')


def deserialize_auth_token(secret_key, token):
    serializer = Serializer(secret_key)
    return serializer.loads(token)