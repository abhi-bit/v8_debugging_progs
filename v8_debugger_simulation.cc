#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <streambuf>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>

#include <include/v8.h>
#include <include/v8-debug.h>
#include <include/libplatform/libplatform.h>

using namespace std;
using namespace v8;

Isolate* isolate;
Persistent<Context> context_;
Persistent<Function> debug_user_request;
volatile std::atomic<bool> exitflag;

const string currentDateTime() {
  time_t     now = time(0);
  struct tm  tstruct;
  char       buf[80];
  tstruct = *localtime(&now);
  strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

  return buf;
}


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
static void DebugSetBreakpointHandler(const v8::Debug::Message& message) {
  v8::Local<v8::String> json = message.GetJSON();
  v8::String::Utf8Value utf8(json);

  cout << currentDateTime() << " " << __FUNCTION__
       << " " << *utf8 << endl;
}

static void DebugClearBreakpointHandler(const v8::Debug::Message& message) {
  v8::Local<v8::String> json = message.GetJSON();
  v8::String::Utf8Value utf8(json);

  cout << currentDateTime() << " " << __FUNCTION__
       << " " << *utf8 << endl;
}

static void DebugListBreakpointHandler(const v8::Debug::Message& message) {
  v8::Local<v8::String> json = message.GetJSON();
  v8::String::Utf8Value utf8(json);

  cout << currentDateTime() << " " <<  __FUNCTION__
       << " " << *utf8 << endl;
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

void ProcessDebugUserRequest(string request) {
  Locker locker(isolate);
  Isolate::Scope isolate_Scope(isolate);
  HandleScope handle_Scope(isolate);

  Local<Context> context = Local<Context>::New(isolate, context_);
  Context::Scope context_scope(context);

  Handle<Value> args[1];
  args[0] = JSON::Parse(
          String::NewFromUtf8(isolate, request.c_str()));
  cout << currentDateTime() << __FUNCTION__
       << request << " " << endl;
  Local<Function> handle_user_req_fun = Local<Function>::New(
          isolate, debug_user_request);
  handle_user_req_fun->Call(context->Global(), 1, args);
  Debug::ProcessDebugMessages(isolate);
}

void ProcessRequest() {
  string prefix("{\"type\": \"json\", \"client\": \"Chrome Canary\", \"counter\":");
  int i = 0;
  while(exitflag) {
      string request;
      request.append(prefix);
      request.append(to_string(i++));
      request.append("}");
      cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
      ProcessDebugUserRequest(request);
    }
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
}

void TestSetBreakPoints() {

  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  const int kBufferSize = 1000;
  uint16_t buffer[kBufferSize];

  string brkp_cmd("{\"command\": \"setbreakpoint\", \"type\": \"request\", \"arguments\": {\"type\": \"function\", \"target\": \"DebugUserRequest\", \"line\":1, \"column\": 0}, \"seq\": 1}");
  Debug::SetMessageHandler(isolate,
          DebugSetBreakpointHandler);
  Debug::SendCommand(isolate, buffer, AsciiToUtf16(
              brkp_cmd.c_str(), buffer));
}

void TestListBreakPoints() {
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  const int kBufferSize = 1000;
  uint16_t buffer[kBufferSize];
  string lbrkp_cmd("{\"command\": \"listbreakpoints\", \"type\": \"request\", \"seq\": 3}");
  Debug::SetMessageHandler(isolate,
          DebugListBreakpointHandler);
  Debug::SendCommand(isolate, buffer, AsciiToUtf16(
              lbrkp_cmd.c_str(), buffer));
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
}

void TestClearBreakPoints() {
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  const int kBufferSize = 1000;
  uint16_t buffer[kBufferSize];

  string clear_brkp_cmd("{\"seq\":10,\"type\":\"request\",\"command\":\"clearbreakpoint\",\"arguments\":{\"type\":\"function\",\"breakpoint\":1}}");
  Debug::SetMessageHandler(isolate, DebugClearBreakpointHandler);
  Debug::SendCommand(isolate, buffer, AsciiToUtf16(
              clear_brkp_cmd.c_str(), buffer));
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
}

void TestContinue() {
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  const int kBufferSize = 1000;
  uint16_t buffer[kBufferSize];

  string continue_cmd("{\"seq\":117,\"type\":\"request\",\"command\":\"continue\"}");
  Debug::SetMessageHandler(isolate, DebugClearBreakpointHandler);
  Debug::SendCommand(isolate, buffer, AsciiToUtf16(
              continue_cmd.c_str(), buffer));
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
}



int main(int argc, char* argv[]) {
  std::cout.setf( std::ios_base::unitbuf );

  V8::InitializeICU();
  V8::InitializeExternalStartupData(argv[0]);
  Platform* platform = platform::CreateDefaultPlatform();
  V8::InitializePlatform(platform);
  V8::Initialize();

  ArrayBufferAllocator allocator;
  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = &allocator;
  isolate = Isolate::New(create_params);
  {
    Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(isolate);
    Local<ObjectTemplate> global = ObjectTemplate::New(isolate);

    global->Set(String::NewFromUtf8(isolate, "log"),
              FunctionTemplate::New(isolate, Print));

    Local<Context> context = Context::New(isolate, NULL, global);
    context_.Reset(isolate, context);
    Context::Scope context_scope(context);

    ifstream file_name(argv[1]);
    string src((istreambuf_iterator<char>(file_name)),
               istreambuf_iterator<char>());

    Local<String> source =
        String::NewFromUtf8(isolate, src.c_str(),
                            NewStringType::kNormal).ToLocalChecked();
    Local<Script> script = Script::Compile(context,
            source).ToLocalChecked();
    Local<Value> result = script->Run(context).ToLocalChecked();

    Local<String> handle_user_req =
        String::NewFromUtf8(isolate,
                "DebugUserRequest", NewStringType::kNormal)
        .ToLocalChecked();
    Local<Value> handle_user_req_val;
    if(!context->Global()->Get(context,
                handle_user_req).ToLocal(&handle_user_req_val))
        cout << "Failed to grab DebugUserRequest function " << endl;

    Local<Function> handle_user_req_fun =
        Local<Function>::Cast(handle_user_req_val);

    assert(handle_user_req_fun->IsFunction());
    debug_user_request.Reset(isolate, handle_user_req_fun);
  }

  exitflag = true;
  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP Process thread" << endl;
  thread send_debug_user_req_thr(ProcessRequest);
  sleep(1);

  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP Set breakpoint thread" << endl;
  thread set_break_point(TestSetBreakPoints);
  sleep(1);

  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP List breakpoint thread" << endl;
  thread set_listbp2(TestListBreakPoints);
  sleep(3);
  set_listbp2.join();

  sleep(1);
  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP clear breakpoint thread" << endl;
  thread clear_break_point(TestClearBreakPoints);
  sleep(3);

  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP AGAIN List breakpoint thread" << endl;
  thread set_listbp3(TestListBreakPoints);
  sleep(3);
  set_listbp3.join();

  cout << __FILE__ << __FUNCTION__ << __LINE__
       << "STARTING UP continue thread" << endl;
  thread cont_thr(TestContinue);
  sleep(1);
  cont_thr.join();

  exitflag = false;
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  set_break_point.join();
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  clear_break_point.join();
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;
  send_debug_user_req_thr.join();
  cout << __FILE__ << __FUNCTION__ << __LINE__ << endl;

  isolate->Dispose();
  V8::Dispose();
  V8::ShutdownPlatform();
  delete platform;
  return 0;
}
