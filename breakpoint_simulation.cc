#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <include/v8.h>
#include <include/v8-debug.h>
#include <include/libplatform/libplatform.h>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace std;
using namespace v8;

int AsciiToUtf16(const char* input_buffer, uint16_t* output_buffer) {
  int i;
  for (i = 0; input_buffer[i] != '\0'; ++i) {
    // ASCII does not use chars > 127, but be careful anyway.
    output_buffer[i] = static_cast<unsigned char>(input_buffer[i]);
  }
  output_buffer[i] = 0;
  return i;
}

const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

const char* ToJson(Isolate* isolate, Handle<Value> object) {
  HandleScope handle_scope(isolate);

  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> global = context->Global();

  Local<Object> JSON = global->Get(String::NewFromUtf8(isolate, "JSON"))->ToObject();
  Local<Function> JSON_stringify = Local<Function>::Cast(
                                          JSON->Get(
                                              String::NewFromUtf8(isolate, "stringify")));

  Local<Value> result;
  Local<Value> args[1];
  args[0] = { object };
  result = JSON_stringify->Call(context->Global(), 1, args);
  String::Utf8Value str(result->ToString());
  return ToCString(str);
}

string ObjectToString(Local<Value> value) {
    String::Utf8Value utf8_value(value);
    return string(*utf8_value);
}

string ToString(Isolate* isolate, Handle<Value> object) {
  HandleScope handle_scope(isolate);

  Local<Context> context = isolate->GetCurrentContext();
  Local<Object> global = context->Global();

  Local<Object> JSON = global->Get(String::NewFromUtf8(isolate, "JSON"))->ToObject();
  Local<Function> JSON_stringify =
      Local<Function>::Cast(JSON->Get(
                  String::NewFromUtf8(isolate, "stringify")));

  Local<Value> result;
  Local<Value> args[1];
  args[0] = { object };
  result = JSON_stringify->Call(context->Global(), 1, args);
  return ObjectToString(result);
}

void Print(const FunctionCallbackInfo<Value>& args) {
  bool first = true;
  for (int i = 0; i < args.Length(); i++) {
    HandleScope handle_scope(args.GetIsolate());
    if (first) {
      first = false;
    } else {
      printf(" ");
    }
    String::Utf8Value str(args[i]);
    const char* cstr = ToJson(args.GetIsolate(), args[i]);
    printf("%s", cstr);
  }
  printf("\n");
  fflush(stdout);
}

// ================================================================
string set_breakpoint_result;

bool SetBreakpointResult(char* message) {
  if (strstr(message, "\"command\":\"setbreakpoint\"") == NULL) {
    return false;
  }
  if (strstr(message, "\"type\":\"") == NULL) {
    return false;
  }
  cout << __FUNCTION__ << " Message dump: " << message << endl;

  string msg(message);
  rapidjson::Document doc;
  if (doc.Parse(msg.c_str()).HasParseError()) {
      cerr << "Failed to parse v8 debug JSON response" << endl;
  }

  assert(doc.IsObject());
  {
      rapidjson::Value& line = doc["body"]["line"];
      rapidjson::Value& column = doc["body"]["column"];
      char buf[10];
      // TODO: more error checking or using a safe wrapper on top of
      // standard sprintf
      sprintf(buf, "%d:%d", line.GetInt(), column.GetInt());
      set_breakpoint_result.assign(buf);
  }
  return true;
}

static void DebugSetBreakpointHandler(const v8::Debug::Message& message) {
  v8::Local<v8::String> json = message.GetJSON();
  v8::String::Utf8Value utf8(json);

  SetBreakpointResult(*utf8);
}

// ================================================================

class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  virtual void* Allocate(size_t length) {
    void* data = AllocateUninitialized(length);
    return data == NULL ? data : memset(data, 0, length);
  }
  virtual void* AllocateUninitialized(size_t length) { return malloc(length); }
  virtual void Free(void* data, size_t) { free(data); }
};

const char* js_function =
    "function DebugUserRequest(doc) {"
    "   if (doc.type === 'json')"
    "       log(doc.client, doc.counter);"
    "}";

int main(int argc, char* argv[]) {

  const int kBufferSize = 1000;
  uint16_t buffer[kBufferSize];

  V8::InitializeICU();
  V8::InitializeExternalStartupData(argv[0]);
  Platform* platform = platform::CreateDefaultPlatform();
  V8::InitializePlatform(platform);
  V8::Initialize();

  ArrayBufferAllocator allocator;
  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = &allocator;
  Isolate* isolate = Isolate::New(create_params);
  {
    Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(isolate);
    Local<ObjectTemplate> global = ObjectTemplate::New(isolate);

    global->Set(String::NewFromUtf8(isolate, "log"),
              FunctionTemplate::New(isolate, Print));

    Local<Context> context = Context::New(isolate, NULL, global);
    Context::Scope context_scope(context);

    Local<String> source =
        String::NewFromUtf8(isolate, js_function,
                            NewStringType::kNormal).ToLocalChecked();
    Local<Script> script = Script::Compile(context,
            source).ToLocalChecked();
    Local<Value> result = script->Run(context).ToLocalChecked();


    Handle<Value> args[1];

    Local<String> handle_user_req =
        String::NewFromUtf8(isolate,
                "DebugUserRequest", NewStringType::kNormal)
        .ToLocalChecked();
    Local<Value> handle_user_req_val;
    if(!context->Global()->Get(context,
                handle_user_req).ToLocal(&handle_user_req_val))
        cout << "Failed to grab DebugUserRequest function " << endl;

    assert(handle_user_req_val->IsFunction());

    Local<Function> handle_user_req_fun =
        Local<Function>::Cast(handle_user_req_val);

    Debug::SetMessageHandler(isolate,
            DebugSetBreakpointHandler);

    string debug_cmd("{\"command\": \"setbreakpoint\", \"type\": \"request\", \"arguments\": {\"type\": \"function\", \"target\": \"DebugUserRequest\"}, \"seq\": 1}");

    string prefix("{\"type\": \"json\", \"client\": \"Chrome Canary\", \"counter\":");
    for (int i = 0; i < 10; i++) {
        if (i != 0 && i % 5 == 0) {
            Debug::SendCommand(isolate, buffer, AsciiToUtf16(
                        debug_cmd.c_str(), buffer));
            Debug::ProcessDebugMessages(isolate);
        } else {
            string request;
            request.append(prefix);
            request.append(to_string(i));
            request.append("}");
            args[0] = JSON::Parse(
                    String::NewFromUtf8(isolate, request.c_str()));
            cout << "Going to call DebugUserRequest function, request: "
                 << request << endl;
            handle_user_req_fun->Call(context->Global(), 1, args);
        }
    }
  }

  isolate->Dispose();
  V8::Dispose();
  V8::ShutdownPlatform();
  delete platform;
  return 0;
}
