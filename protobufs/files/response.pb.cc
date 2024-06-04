// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: response.proto

#include "response.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

PROTOBUF_CONSTEXPR CarrotFileResponse::CarrotFileResponse(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.buffer_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.return__)*/0
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct CarrotFileResponseDefaultTypeInternal {
  PROTOBUF_CONSTEXPR CarrotFileResponseDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~CarrotFileResponseDefaultTypeInternal() {}
  union {
    CarrotFileResponse _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 CarrotFileResponseDefaultTypeInternal _CarrotFileResponse_default_instance_;
static ::_pb::Metadata file_level_metadata_response_2eproto[1];
static constexpr ::_pb::EnumDescriptor const** file_level_enum_descriptors_response_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const** file_level_service_descriptors_response_2eproto = nullptr;

const uint32_t TableStruct_response_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::CarrotFileResponse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::CarrotFileResponse, _impl_.return__),
  PROTOBUF_FIELD_OFFSET(::CarrotFileResponse, _impl_.buffer_),
};
static const ::_pbi::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::CarrotFileResponse)},
};

static const ::_pb::Message* const file_default_instances[] = {
  &::_CarrotFileResponse_default_instance_._instance,
};

const char descriptor_table_protodef_response_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\016response.proto\"4\n\022CarrotFileResponse\022\016"
  "\n\006return\030\001 \001(\005\022\016\n\006buffer\030\002 \001(\tb\006proto3"
  ;
static ::_pbi::once_flag descriptor_table_response_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_response_2eproto = {
    false, false, 78, descriptor_table_protodef_response_2eproto,
    "response.proto",
    &descriptor_table_response_2eproto_once, nullptr, 0, 1,
    schemas, file_default_instances, TableStruct_response_2eproto::offsets,
    file_level_metadata_response_2eproto, file_level_enum_descriptors_response_2eproto,
    file_level_service_descriptors_response_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_response_2eproto_getter() {
  return &descriptor_table_response_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_response_2eproto(&descriptor_table_response_2eproto);

// ===================================================================

class CarrotFileResponse::_Internal {
 public:
};

CarrotFileResponse::CarrotFileResponse(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:CarrotFileResponse)
}
CarrotFileResponse::CarrotFileResponse(const CarrotFileResponse& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  CarrotFileResponse* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.buffer_){}
    , decltype(_impl_.return__){}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.buffer_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.buffer_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_buffer().empty()) {
    _this->_impl_.buffer_.Set(from._internal_buffer(), 
      _this->GetArenaForAllocation());
  }
  _this->_impl_.return__ = from._impl_.return__;
  // @@protoc_insertion_point(copy_constructor:CarrotFileResponse)
}

inline void CarrotFileResponse::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.buffer_){}
    , decltype(_impl_.return__){0}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.buffer_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.buffer_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

CarrotFileResponse::~CarrotFileResponse() {
  // @@protoc_insertion_point(destructor:CarrotFileResponse)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void CarrotFileResponse::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.buffer_.Destroy();
}

void CarrotFileResponse::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void CarrotFileResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:CarrotFileResponse)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.buffer_.ClearToEmpty();
  _impl_.return__ = 0;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* CarrotFileResponse::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // int32 return = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 8)) {
          _impl_.return__ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // string buffer = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_buffer();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "CarrotFileResponse.buffer"));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* CarrotFileResponse::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:CarrotFileResponse)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // int32 return = 1;
  if (this->_internal_return_() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt32ToArray(1, this->_internal_return_(), target);
  }

  // string buffer = 2;
  if (!this->_internal_buffer().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_buffer().data(), static_cast<int>(this->_internal_buffer().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "CarrotFileResponse.buffer");
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_buffer(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:CarrotFileResponse)
  return target;
}

size_t CarrotFileResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:CarrotFileResponse)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string buffer = 2;
  if (!this->_internal_buffer().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_buffer());
  }

  // int32 return = 1;
  if (this->_internal_return_() != 0) {
    total_size += ::_pbi::WireFormatLite::Int32SizePlusOne(this->_internal_return_());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData CarrotFileResponse::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    CarrotFileResponse::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*CarrotFileResponse::GetClassData() const { return &_class_data_; }


void CarrotFileResponse::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<CarrotFileResponse*>(&to_msg);
  auto& from = static_cast<const CarrotFileResponse&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:CarrotFileResponse)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_buffer().empty()) {
    _this->_internal_set_buffer(from._internal_buffer());
  }
  if (from._internal_return_() != 0) {
    _this->_internal_set_return_(from._internal_return_());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void CarrotFileResponse::CopyFrom(const CarrotFileResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:CarrotFileResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CarrotFileResponse::IsInitialized() const {
  return true;
}

void CarrotFileResponse::InternalSwap(CarrotFileResponse* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.buffer_, lhs_arena,
      &other->_impl_.buffer_, rhs_arena
  );
  swap(_impl_.return__, other->_impl_.return__);
}

::PROTOBUF_NAMESPACE_ID::Metadata CarrotFileResponse::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_response_2eproto_getter, &descriptor_table_response_2eproto_once,
      file_level_metadata_response_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::CarrotFileResponse*
Arena::CreateMaybeMessage< ::CarrotFileResponse >(Arena* arena) {
  return Arena::CreateMessageInternal< ::CarrotFileResponse >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>