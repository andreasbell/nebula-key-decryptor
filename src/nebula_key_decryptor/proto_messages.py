from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

# 1. Create a FileDescriptorProto
proto = descriptor_pb2.FileDescriptorProto()
proto.name = 'cert_v1.proto'
proto.package = 'cert'
proto.syntax = 'proto3'

# 2. Add a message descriptor manually
Argon2Parameters = proto.message_type.add()
Argon2Parameters.name = "Argon2Parameters"

version = Argon2Parameters.field.add()
version.name = "version"
version.number = 1
version.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_INT32

memory = Argon2Parameters.field.add()
memory.name = "memory"
memory.number = 2
memory.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_UINT32

iterations = Argon2Parameters.field.add()
iterations.name = "iterations"
iterations.number = 3
iterations.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_UINT32

parallelism = Argon2Parameters.field.add()
parallelism.name = "parallelism"
parallelism.number = 4
parallelism.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_UINT32

salt = Argon2Parameters.field.add()
salt.name = "salt"
salt.number = 5
salt.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_BYTES

EncryptionMetadata = proto.message_type.add()
EncryptionMetadata.name = "EncryptionMetadata"

encryptionAlgorithm = EncryptionMetadata.field.add()
encryptionAlgorithm.name = "encryptionAlgorithm"
encryptionAlgorithm.number = 1
encryptionAlgorithm.type = encryptionAlgorithm.TYPE_STRING

argon2Parameters = EncryptionMetadata.field.add()
argon2Parameters.name = "argon2Parameters"
argon2Parameters.number = 2
argon2Parameters.type =descriptor_pb2.FieldDescriptorProto.Type.TYPE_MESSAGE
argon2Parameters.type_name = ".cert.Argon2Parameters"

EncryptedData = proto.message_type.add()
EncryptedData.name = "EncryptedData"

encryptionMetadata = EncryptedData.field.add()
encryptionMetadata.name = "encryptionMetadata"
encryptionMetadata.number = 1
encryptionMetadata.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_MESSAGE
encryptionMetadata.type_name = ".cert.EncryptionMetadata"

ciphertext = EncryptedData.field.add()
ciphertext.name = "ciphertext"
ciphertext.number = 2
ciphertext.type = descriptor_pb2.FieldDescriptorProto.Type.TYPE_BYTES

# Create Messages
pool = descriptor_pool.DescriptorPool()
pool.Add(proto)
EncryptedKey = message_factory.GetMessageClass(pool.FindMessageTypeByName("cert.EncryptedData"))