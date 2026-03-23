import frida, time
d = frida.get_usb_device()
s = d.attach('com.tencent.tmgp.pubgmhd')
sc = s.create_script('var m=Process.findModuleByName("libUE4.so"); if(m) send({base:m.base.toString(),size:m.size});')
result = {}
def on_msg(msg, data):
    if msg["type"] == "send":
        result.update(msg["payload"])
sc.on("message", on_msg)
sc.load()
time.sleep(2)
sc.unload()
s.detach()
print(f"base={result.get('base')}, size={result.get('size')}")
