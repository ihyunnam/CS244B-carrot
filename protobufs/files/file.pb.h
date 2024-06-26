// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: file.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_file_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_file_2eproto

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
#define PROTOBUF_INTERNAL_EXPORT_file_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_file_2eproto {
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_file_2eproto;
class CarrotFileRequest;
struct CarrotFileRequestDefaultTypeInternal;
extern CarrotFileRequestDefaultTypeInternal _CarrotFileRequest_default_instance_;
class CarrotFileResponse;
struct CarrotFileResponseDefaultTypeInternal;
extern CarrotFileResponseDefaultTypeInternal _CarrotFileResponse_default_instance_;
PROTOBUF_NAMESPACE_OPEN
template<> ::CarrotFileRequest* Arena::CreateMaybeMessage<::CarrotFileRequest>(Arena*);
template<> ::CarrotFileResponse* Arena::CreateMaybeMessage<::CarrotFileResponse>(Arena*);
PROTOBUF_NAMESPACE_CLOSE

// ===================================================================

class CarrotFileRequest final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:CarrotFileRequest) */ {
 public:
  inline CarrotFileRequest() : CarrotFileRequest(nullptr) {}
  ~CarrotFileRequest() override;
  explicit PROTOBUF_CONSTEXPR CarrotFileRequest(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  CarrotFileRequest(const CarrotFileRequest& from);
  CarrotFileRequest(CarrotFileRequest&& from) noexcept
    : CarrotFileRequest() {
    *this = ::std::move(from);
  }

  inline CarrotFileRequest& operator=(const CarrotFileRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline CarrotFileRequest& operator=(CarrotFileRequest&& from) noexcept {
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
  static const CarrotFileRequest& default_instance() {
    return *internal_default_instance();
  }
  static inline const CarrotFileRequest* internal_default_instance() {
    return reinterpret_cast<const CarrotFileRequest*>(
               &_CarrotFileRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(CarrotFileRequest& a, CarrotFileRequest& b) {
    a.Swap(&b);
  }
  inline void Swap(CarrotFileRequest* other) {
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
  void UnsafeArenaSwap(CarrotFileRequest* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  CarrotFileRequest* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<CarrotFileRequest>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const CarrotFileRequest& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const CarrotFileRequest& from) {
    CarrotFileRequest::MergeImpl(*this, from);
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
  void InternalSwap(CarrotFileRequest* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "CarrotFileRequest";
  }
  protected:
  explicit CarrotFileRequest(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kBufferFieldNumber = 2,
    kSyscallNumFieldNumber = 1,
    kArgOneFieldNumber = 3,
    kArgTwoFieldNumber = 4,
    kArgThreeFieldNumber = 5,
    kArgFourFieldNumber = 6,
    kArgFiveFieldNumber = 7,
    kArgSixFieldNumber = 8,
  };
  // bytes buffer = 2;
  void clear_buffer();
  const std::string& buffer() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_buffer(ArgT0&& arg0, ArgT... args);
  std::string* mutable_buffer();
  PROTOBUF_NODISCARD std::string* release_buffer();
  void set_allocated_buffer(std::string* buffer);
  private:
  const std::string& _internal_buffer() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_buffer(const std::string& value);
  std::string* _internal_mutable_buffer();
  public:

  // int32 syscall_num = 1;
  void clear_syscall_num();
  int32_t syscall_num() const;
  void set_syscall_num(int32_t value);
  private:
  int32_t _internal_syscall_num() const;
  void _internal_set_syscall_num(int32_t value);
  public:

  // int32 arg_one = 3;
  void clear_arg_one();
  int32_t arg_one() const;
  void set_arg_one(int32_t value);
  private:
  int32_t _internal_arg_one() const;
  void _internal_set_arg_one(int32_t value);
  public:

  // int32 arg_two = 4;
  void clear_arg_two();
  int32_t arg_two() const;
  void set_arg_two(int32_t value);
  private:
  int32_t _internal_arg_two() const;
  void _internal_set_arg_two(int32_t value);
  public:

  // int32 arg_three = 5;
  void clear_arg_three();
  int32_t arg_three() const;
  void set_arg_three(int32_t value);
  private:
  int32_t _internal_arg_three() const;
  void _internal_set_arg_three(int32_t value);
  public:

  // int32 arg_four = 6;
  void clear_arg_four();
  int32_t arg_four() const;
  void set_arg_four(int32_t value);
  private:
  int32_t _internal_arg_four() const;
  void _internal_set_arg_four(int32_t value);
  public:

  // int32 arg_five = 7;
  void clear_arg_five();
  int32_t arg_five() const;
  void set_arg_five(int32_t value);
  private:
  int32_t _internal_arg_five() const;
  void _internal_set_arg_five(int32_t value);
  public:

  // int32 arg_six = 8;
  void clear_arg_six();
  int32_t arg_six() const;
  void set_arg_six(int32_t value);
  private:
  int32_t _internal_arg_six() const;
  void _internal_set_arg_six(int32_t value);
  public:

  // @@protoc_insertion_point(class_scope:CarrotFileRequest)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr buffer_;
    int32_t syscall_num_;
    int32_t arg_one_;
    int32_t arg_two_;
    int32_t arg_three_;
    int32_t arg_four_;
    int32_t arg_five_;
    int32_t arg_six_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_file_2eproto;
};
// -------------------------------------------------------------------

class CarrotFileResponse final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:CarrotFileResponse) */ {
 public:
  inline CarrotFileResponse() : CarrotFileResponse(nullptr) {}
  ~CarrotFileResponse() override;
  explicit PROTOBUF_CONSTEXPR CarrotFileResponse(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  CarrotFileResponse(const CarrotFileResponse& from);
  CarrotFileResponse(CarrotFileResponse&& from) noexcept
    : CarrotFileResponse() {
    *this = ::std::move(from);
  }

  inline CarrotFileResponse& operator=(const CarrotFileResponse& from) {
    CopyFrom(from);
    return *this;
  }
  inline CarrotFileResponse& operator=(CarrotFileResponse&& from) noexcept {
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
  static const CarrotFileResponse& default_instance() {
    return *internal_default_instance();
  }
  static inline const CarrotFileResponse* internal_default_instance() {
    return reinterpret_cast<const CarrotFileResponse*>(
               &_CarrotFileResponse_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(CarrotFileResponse& a, CarrotFileResponse& b) {
    a.Swap(&b);
  }
  inline void Swap(CarrotFileResponse* other) {
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
  void UnsafeArenaSwap(CarrotFileResponse* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  CarrotFileResponse* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<CarrotFileResponse>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const CarrotFileResponse& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const CarrotFileResponse& from) {
    CarrotFileResponse::MergeImpl(*this, from);
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
  void InternalSwap(CarrotFileResponse* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "CarrotFileResponse";
  }
  protected:
  explicit CarrotFileResponse(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kBufferFieldNumber = 2,
    kReturnValFieldNumber = 1,
  };
  // bytes buffer = 2;
  void clear_buffer();
  const std::string& buffer() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_buffer(ArgT0&& arg0, ArgT... args);
  std::string* mutable_buffer();
  PROTOBUF_NODISCARD std::string* release_buffer();
  void set_allocated_buffer(std::string* buffer);
  private:
  const std::string& _internal_buffer() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_buffer(const std::string& value);
  std::string* _internal_mutable_buffer();
  public:

  // int32 return_val = 1;
  void clear_return_val();
  int32_t return_val() const;
  void set_return_val(int32_t value);
  private:
  int32_t _internal_return_val() const;
  void _internal_set_return_val(int32_t value);
  public:

  // @@protoc_insertion_point(class_scope:CarrotFileResponse)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr buffer_;
    int32_t return_val_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_file_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// CarrotFileRequest

// int32 syscall_num = 1;
inline void CarrotFileRequest::clear_syscall_num() {
  _impl_.syscall_num_ = 0;
}
inline int32_t CarrotFileRequest::_internal_syscall_num() const {
  return _impl_.syscall_num_;
}
inline int32_t CarrotFileRequest::syscall_num() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.syscall_num)
  return _internal_syscall_num();
}
inline void CarrotFileRequest::_internal_set_syscall_num(int32_t value) {
  
  _impl_.syscall_num_ = value;
}
inline void CarrotFileRequest::set_syscall_num(int32_t value) {
  _internal_set_syscall_num(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.syscall_num)
}

// bytes buffer = 2;
inline void CarrotFileRequest::clear_buffer() {
  _impl_.buffer_.ClearToEmpty();
}
inline const std::string& CarrotFileRequest::buffer() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.buffer)
  return _internal_buffer();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CarrotFileRequest::set_buffer(ArgT0&& arg0, ArgT... args) {
 
 _impl_.buffer_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:CarrotFileRequest.buffer)
}
inline std::string* CarrotFileRequest::mutable_buffer() {
  std::string* _s = _internal_mutable_buffer();
  // @@protoc_insertion_point(field_mutable:CarrotFileRequest.buffer)
  return _s;
}
inline const std::string& CarrotFileRequest::_internal_buffer() const {
  return _impl_.buffer_.Get();
}
inline void CarrotFileRequest::_internal_set_buffer(const std::string& value) {
  
  _impl_.buffer_.Set(value, GetArenaForAllocation());
}
inline std::string* CarrotFileRequest::_internal_mutable_buffer() {
  
  return _impl_.buffer_.Mutable(GetArenaForAllocation());
}
inline std::string* CarrotFileRequest::release_buffer() {
  // @@protoc_insertion_point(field_release:CarrotFileRequest.buffer)
  return _impl_.buffer_.Release();
}
inline void CarrotFileRequest::set_allocated_buffer(std::string* buffer) {
  if (buffer != nullptr) {
    
  } else {
    
  }
  _impl_.buffer_.SetAllocated(buffer, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.buffer_.IsDefault()) {
    _impl_.buffer_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:CarrotFileRequest.buffer)
}

// int32 arg_one = 3;
inline void CarrotFileRequest::clear_arg_one() {
  _impl_.arg_one_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_one() const {
  return _impl_.arg_one_;
}
inline int32_t CarrotFileRequest::arg_one() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_one)
  return _internal_arg_one();
}
inline void CarrotFileRequest::_internal_set_arg_one(int32_t value) {
  
  _impl_.arg_one_ = value;
}
inline void CarrotFileRequest::set_arg_one(int32_t value) {
  _internal_set_arg_one(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_one)
}

// int32 arg_two = 4;
inline void CarrotFileRequest::clear_arg_two() {
  _impl_.arg_two_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_two() const {
  return _impl_.arg_two_;
}
inline int32_t CarrotFileRequest::arg_two() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_two)
  return _internal_arg_two();
}
inline void CarrotFileRequest::_internal_set_arg_two(int32_t value) {
  
  _impl_.arg_two_ = value;
}
inline void CarrotFileRequest::set_arg_two(int32_t value) {
  _internal_set_arg_two(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_two)
}

// int32 arg_three = 5;
inline void CarrotFileRequest::clear_arg_three() {
  _impl_.arg_three_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_three() const {
  return _impl_.arg_three_;
}
inline int32_t CarrotFileRequest::arg_three() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_three)
  return _internal_arg_three();
}
inline void CarrotFileRequest::_internal_set_arg_three(int32_t value) {
  
  _impl_.arg_three_ = value;
}
inline void CarrotFileRequest::set_arg_three(int32_t value) {
  _internal_set_arg_three(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_three)
}

// int32 arg_four = 6;
inline void CarrotFileRequest::clear_arg_four() {
  _impl_.arg_four_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_four() const {
  return _impl_.arg_four_;
}
inline int32_t CarrotFileRequest::arg_four() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_four)
  return _internal_arg_four();
}
inline void CarrotFileRequest::_internal_set_arg_four(int32_t value) {
  
  _impl_.arg_four_ = value;
}
inline void CarrotFileRequest::set_arg_four(int32_t value) {
  _internal_set_arg_four(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_four)
}

// int32 arg_five = 7;
inline void CarrotFileRequest::clear_arg_five() {
  _impl_.arg_five_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_five() const {
  return _impl_.arg_five_;
}
inline int32_t CarrotFileRequest::arg_five() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_five)
  return _internal_arg_five();
}
inline void CarrotFileRequest::_internal_set_arg_five(int32_t value) {
  
  _impl_.arg_five_ = value;
}
inline void CarrotFileRequest::set_arg_five(int32_t value) {
  _internal_set_arg_five(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_five)
}

// int32 arg_six = 8;
inline void CarrotFileRequest::clear_arg_six() {
  _impl_.arg_six_ = 0;
}
inline int32_t CarrotFileRequest::_internal_arg_six() const {
  return _impl_.arg_six_;
}
inline int32_t CarrotFileRequest::arg_six() const {
  // @@protoc_insertion_point(field_get:CarrotFileRequest.arg_six)
  return _internal_arg_six();
}
inline void CarrotFileRequest::_internal_set_arg_six(int32_t value) {
  
  _impl_.arg_six_ = value;
}
inline void CarrotFileRequest::set_arg_six(int32_t value) {
  _internal_set_arg_six(value);
  // @@protoc_insertion_point(field_set:CarrotFileRequest.arg_six)
}

// -------------------------------------------------------------------

// CarrotFileResponse

// int32 return_val = 1;
inline void CarrotFileResponse::clear_return_val() {
  _impl_.return_val_ = 0;
}
inline int32_t CarrotFileResponse::_internal_return_val() const {
  return _impl_.return_val_;
}
inline int32_t CarrotFileResponse::return_val() const {
  // @@protoc_insertion_point(field_get:CarrotFileResponse.return_val)
  return _internal_return_val();
}
inline void CarrotFileResponse::_internal_set_return_val(int32_t value) {
  
  _impl_.return_val_ = value;
}
inline void CarrotFileResponse::set_return_val(int32_t value) {
  _internal_set_return_val(value);
  // @@protoc_insertion_point(field_set:CarrotFileResponse.return_val)
}

// bytes buffer = 2;
inline void CarrotFileResponse::clear_buffer() {
  _impl_.buffer_.ClearToEmpty();
}
inline const std::string& CarrotFileResponse::buffer() const {
  // @@protoc_insertion_point(field_get:CarrotFileResponse.buffer)
  return _internal_buffer();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void CarrotFileResponse::set_buffer(ArgT0&& arg0, ArgT... args) {
 
 _impl_.buffer_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:CarrotFileResponse.buffer)
}
inline std::string* CarrotFileResponse::mutable_buffer() {
  std::string* _s = _internal_mutable_buffer();
  // @@protoc_insertion_point(field_mutable:CarrotFileResponse.buffer)
  return _s;
}
inline const std::string& CarrotFileResponse::_internal_buffer() const {
  return _impl_.buffer_.Get();
}
inline void CarrotFileResponse::_internal_set_buffer(const std::string& value) {
  
  _impl_.buffer_.Set(value, GetArenaForAllocation());
}
inline std::string* CarrotFileResponse::_internal_mutable_buffer() {
  
  return _impl_.buffer_.Mutable(GetArenaForAllocation());
}
inline std::string* CarrotFileResponse::release_buffer() {
  // @@protoc_insertion_point(field_release:CarrotFileResponse.buffer)
  return _impl_.buffer_.Release();
}
inline void CarrotFileResponse::set_allocated_buffer(std::string* buffer) {
  if (buffer != nullptr) {
    
  } else {
    
  }
  _impl_.buffer_.SetAllocated(buffer, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.buffer_.IsDefault()) {
    _impl_.buffer_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:CarrotFileResponse.buffer)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)


// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_file_2eproto
