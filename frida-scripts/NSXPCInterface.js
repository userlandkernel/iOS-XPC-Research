// Work In Progress

var protocol_getName = Module.findExportByName("/usr/lib/libobjc.A.dylib", "protocol_getName");
// const char * protocol_getName(Protocol *proto);
var my_protocol_getName = new NativeFunction(protocol_getName, 'pointer', ['pointer']);
var interfaceWithProtocol = ObjC.classes.NSXPCInterface["+ interfaceWithProtocol:"];

Interceptor.attach(interfaceWithProtocol.implementation, {
    onEnter: function(args) {
      console.log("[+] Hooked interfaceWithProtocol [!]");
      console.log("[+] Protocol => " + args[2]);
      // Returns a const char *
      var name = my_protocol_getName(args[2]);
      console.log("[+] Protocol Name => " + Memory.readUtf8String(name));
    }
  })
