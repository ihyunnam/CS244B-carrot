// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: message.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_message_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_message_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3021000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3021012 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_message_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_message_2eproto {
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_message_2eproto;
class CarrotMessage;
struct CarrotMessageDefaultTypeInternal;
extern CarrotMessageDefaultTypeInternal _CarrotMessage_default_instance_;
PROTOBUF_NAMESPACE_OPEN
template<> ::CarrotMessage* Arena::CreateMaybeMessage<::CarrotMessage>(Arena*);
PROTOBUF_NAMESPACE_CLOSE

// ===================================================================

class CarrotMessage final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:CarrotMessage) */ {
 public:
  inline CarrotMessage() : CarrotMessage(nullptr) {}
  ~CarrotMessage() override;
  explicit PROTOBUF_CONSTEXPR CarrotMessage(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  CarrotMessage(const CarrotMessage& from);
  CarrotMessage(CarrotMessage&& from) noexcept
    : CarrotMessage() {
    *this = ::std::move(from);
  }

  inline CarrotMessage& operator=(const CarrotMessage& from) {
    CopyFrom(from);
    return *this;
  }
  inline CarrotMessage& operator=(CarrotMessage&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const CarrotMessage& default_instance() {
    return *internal_default_instance();
  }
  static inline const CarrotMessage* internal_default_instance() {
    return reinterpret_cast<const CarrotMessage*>(
               &_CarrotMessage_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(CarrotMessage& a, CarrotMessage& b) {
    a.Swap(&b);
  }
  inline void Swap(CarrotMessage* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(CarrotMessage* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  CarrotMessage* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<CarrotMessage>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const CarrotMessage& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const CarrotMessage& from) {
    CarrotMessage::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(CarrotMessage* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "CarrotMessage";
  }
  protected:
  explicit CarrotMessage(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kIpAddressFieldNumber = 1,
    kMessageFieldNumber = 3,
    kPortFieldNumber = 2,
  };
  // string ip_address = 1;
  void clear_ip_address();
  const std::string& ip_address() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_ip_address(ArgT0&& arg0, ArgT... args);
  std::string* mutable_ip_address();
  PROTOBUF_NODISCARD std::string* release_ip_address();
  void set_allocated_ip_address(std::string* ip_address);
  private:
  const std::string& _internal_ip_address() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_ip_address(const std::string& value);
  std::string* _internal_mutable_ip_address();
  public:

  // string message = 3;
  void clear_message();
  const std::string& message() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_message(ArgT0&& arg0, ArgT... args);
  std::string* mutable_message();
  PROTOBUF_NODISCARD std::string* release_message();
  void set_allocated_message(std::string* message);
  private:
  const std::string& _internal_message() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_message(const std::string& value);
  std::string* _internal_mutable_message();
  public:

  // int32 port = 2;
  void clear_port();
  int32_t port() const;
  void set_port(int32_t value);
  private:
  int32_t _internal_port() const;
  void _internal_set_port(int32_t value);
  public:

  // @@protoc_insertion_point(class_scope:CarrotMessage)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr ip_address_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr message_;
    int32_t port_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_message_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// CarrotMessage

// string ip_address = 1;
inline void CarrotMessage::clear_ip_address() {
  _impl_.ip_address_.ClearToEmpty();
}
inline const std::string& CarrotMessage::ip_address() const {
  // @@protoc_insertion_point(field_get:CarrotMessage.ip_address)
  return _internal_ip_address();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CarrotMessage::set_ip_address(ArgT0&& arg0, ArgT... args) {
 
 _impl_.ip_address_.Set(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:CarrotMessage.ip_address)
}
inline std::string* CarrotMessage::mutable_ip_address() {
  std::string* _s = _internal_mutable_ip_address();
  // @@protoc_insertion_point(field_mutable:CarrotMessage.ip_address)
  return _s;
}
inline const std::string& CarrotMessage::_internal_ip_address() const {
  return _impl_.ip_address_.Get();
}
inline void CarrotMessage::_internal_set_ip_address(const std::string& value) {
  
  _impl_.ip_address_.Set(value, GetArenaForAllocation());
}
inline std::string* CarrotMessage::_internal_mutable_ip_address() {
  
  return _impl_.ip_address_.Mutable(GetArenaForAllocation());
}
inline std::string* CarrotMessage::release_ip_address() {
  // @@protoc_insertion_point(field_release:CarrotMessage.ip_address)
  return _impl_.ip_address_.Release();
}
inline void CarrotMessage::set_allocated_ip_address(std::string* ip_address) {
  if (ip_address != nullptr) {
    
  } else {
    
  }
  _impl_.ip_address_.SetAllocated(ip_address, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.ip_address_.IsDefault()) {
    _impl_.ip_address_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:CarrotMessage.ip_address)
}

// int32 port = 2;
inline void CarrotMessage::clear_port() {
  _impl_.port_ = 0;
}
inline int32_t CarrotMessage::_internal_port() const {
  return _impl_.port_;
}
inline int32_t CarrotMessage::port() const {
  // @@protoc_insertion_point(field_get:CarrotMessage.port)
  return _internal_port();
}
inline void CarrotMessage::_internal_set_port(int32_t value) {
  
  _impl_.port_ = value;
}
inline void CarrotMessage::set_port(int32_t value) {
  _internal_set_port(value);
  // @@protoc_insertion_point(field_set:CarrotMessage.port)
}

// string message = 3;
inline void CarrotMessage::clear_message() {
  _impl_.message_.ClearToEmpty();
}
inline const std::string& CarrotMessage::message() const {
  // @@protoc_insertion_point(field_get:CarrotMessage.message)
  return _internal_message();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CarrotMessage::set_message(ArgT0&& arg0, ArgT... args) {
 
 _impl_.message_.Set(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:CarrotMessage.message)
}
inline std::string* CarrotMessage::mutable_message() {
  std::string* _s = _internal_mutable_message();
  // @@protoc_insertion_point(field_mutable:CarrotMessage.message)
  return _s;
}
inline const std::string& CarrotMessage::_internal_message() const {
  return _impl_.message_.Get();
}
inline void CarrotMessage::_internal_set_message(const std::string& value) {
  
  _impl_.message_.Set(value, GetArenaForAllocation());
}
inline std::string* CarrotMessage::_internal_mutable_message() {
  
  return _impl_.message_.Mutable(GetArenaForAllocation());
}
inline std::string* CarrotMessage::release_message() {
  // @@protoc_insertion_point(field_release:CarrotMessage.message)
  return _impl_.message_.Release();
}
inline void CarrotMessage::set_allocated_message(std::string* message) {
  if (message != nullptr) {
    
  } else {
    
  }
  _impl_.message_.SetAllocated(message, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.message_.IsDefault()) {
    _impl_.message_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:CarrotMessage.message)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)


// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_message_2eproto
