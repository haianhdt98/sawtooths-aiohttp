# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protobuf/product.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='protobuf/product.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x16protobuf/product.proto\"\xed\x01\n\x07Product\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12 \n\x07statuss\x18\x03 \x03(\x0b\x32\x0f.Product.Status\x12$\n\tlocations\x18\x04 \x03(\x0b\x32\x11.Product.Location\x1a<\n\x06Status\x12\x11\n\ttimestamp\x18\x01 \x01(\x04\x12\x10\n\x08quantity\x18\x02 \x01(\t\x12\r\n\x05price\x18\x03 \x01(\t\x1a\x42\n\x08Location\x12\x11\n\ttimestamp\x18\x01 \x01(\x04\x12\x11\n\tlongitude\x18\x02 \x01(\t\x12\x10\n\x08latitude\x18\x03 \x01(\t\"-\n\x10ProductContainer\x12\x19\n\x07\x65ntries\x18\x01 \x03(\x0b\x32\x08.Productb\x06proto3'
)




_PRODUCT_STATUS = _descriptor.Descriptor(
  name='Status',
  full_name='Product.Status',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='Product.Status.timestamp', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='quantity', full_name='Product.Status.quantity', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='price', full_name='Product.Status.price', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=136,
  serialized_end=196,
)

_PRODUCT_LOCATION = _descriptor.Descriptor(
  name='Location',
  full_name='Product.Location',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='Product.Location.timestamp', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='longitude', full_name='Product.Location.longitude', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='latitude', full_name='Product.Location.latitude', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=198,
  serialized_end=264,
)

_PRODUCT = _descriptor.Descriptor(
  name='Product',
  full_name='Product',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='Product.id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='name', full_name='Product.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='statuss', full_name='Product.statuss', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='locations', full_name='Product.locations', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_PRODUCT_STATUS, _PRODUCT_LOCATION, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=27,
  serialized_end=264,
)


_PRODUCTCONTAINER = _descriptor.Descriptor(
  name='ProductContainer',
  full_name='ProductContainer',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='entries', full_name='ProductContainer.entries', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=266,
  serialized_end=311,
)

_PRODUCT_STATUS.containing_type = _PRODUCT
_PRODUCT_LOCATION.containing_type = _PRODUCT
_PRODUCT.fields_by_name['statuss'].message_type = _PRODUCT_STATUS
_PRODUCT.fields_by_name['locations'].message_type = _PRODUCT_LOCATION
_PRODUCTCONTAINER.fields_by_name['entries'].message_type = _PRODUCT
DESCRIPTOR.message_types_by_name['Product'] = _PRODUCT
DESCRIPTOR.message_types_by_name['ProductContainer'] = _PRODUCTCONTAINER
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Product = _reflection.GeneratedProtocolMessageType('Product', (_message.Message,), {

  'Status' : _reflection.GeneratedProtocolMessageType('Status', (_message.Message,), {
    'DESCRIPTOR' : _PRODUCT_STATUS,
    '__module__' : 'protobuf.product_pb2'
    # @@protoc_insertion_point(class_scope:Product.Status)
    })
  ,

  'Location' : _reflection.GeneratedProtocolMessageType('Location', (_message.Message,), {
    'DESCRIPTOR' : _PRODUCT_LOCATION,
    '__module__' : 'protobuf.product_pb2'
    # @@protoc_insertion_point(class_scope:Product.Location)
    })
  ,
  'DESCRIPTOR' : _PRODUCT,
  '__module__' : 'protobuf.product_pb2'
  # @@protoc_insertion_point(class_scope:Product)
  })
_sym_db.RegisterMessage(Product)
_sym_db.RegisterMessage(Product.Status)
_sym_db.RegisterMessage(Product.Location)

ProductContainer = _reflection.GeneratedProtocolMessageType('ProductContainer', (_message.Message,), {
  'DESCRIPTOR' : _PRODUCTCONTAINER,
  '__module__' : 'protobuf.product_pb2'
  # @@protoc_insertion_point(class_scope:ProductContainer)
  })
_sym_db.RegisterMessage(ProductContainer)


# @@protoc_insertion_point(module_scope)
