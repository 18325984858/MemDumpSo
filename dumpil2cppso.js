// =============================================================
//  dump_so.js — 通用 SO 内存 Dump 脚本（支持加壳/加固）
//  场景：SO 运行时才解密，需等待解密完成后从内存 dump
//
//  用法 (attach 模式，推荐用于加固场景):
//    frida -U <包名> -l dumpil2cppso.js
//  用法 (spawn 模式):
//    frida -U -f <包名> -l dumpil2cppso.js --no-pause
//
//  dump 指定 SO (通过环境变量由 Python 脚本注入):
//    Python 端会替换 CONFIG.moduleName
//
//  配合 Python 编排脚本使用:
//    python dump_and_fix.py --so libFEProj.so
//    python dump_and_fix.py --so libtersafe.so
// =============================================================

var CONFIG = {
  moduleName: "__TARGET_SO__", // 由 Python 脚本注入，或手动修改
  packageName: "com.tencent.lolm", // 目标包名
  waitDecryptDelay: 10000, // 等待解密完成的延迟(ms)
  dumpBlockSize: 4096, // 内存读取块大小
  saveTo: "file", // "file" 保存到设备 | "send" 通过frida传输
};

// ======================== 工具函数 ========================

function getPackageName() {
  // 优先使用配置中的包名
  if (CONFIG.packageName && CONFIG.packageName !== "") {
    return CONFIG.packageName;
  }
  // 回退：尝试 Java API
  try {
    if (Java.available) {
      var pkg = "";
      Java.perform(function () {
        var ctx = Java.use("android.app.ActivityThread")
          .currentApplication()
          .getApplicationContext();
        pkg = ctx.getPackageName();
      });
      if (pkg) return pkg;
    }
  } catch (e) {
    console.log("[!] Java API 不可用: " + e);
  }
  // 最终回退：从 /proc/self/cmdline 读取
  try {
    var cmdline = new File("/proc/self/cmdline", "r");
    var name = cmdline.readLine();
    cmdline.close();
    if (name) return name.replace(/\0/g, "");
  } catch (e) {}
  return "unknown";
}

function getSavePath(moduleName) {
  return "/data/data/" + getPackageName() + "/" + moduleName + ".dump";
}

// ======================== 解密检测 ========================

function checkDecrypted(module) {
  // 检查 ELF magic 是否存在于内存基地址
  try {
    var magic = module.base.readByteArray(4);
    var view = new Uint8Array(magic);
    if (
      view[0] === 0x7f &&
      view[1] === 0x45 &&
      view[2] === 0x4c &&
      view[3] === 0x46
    ) {
      console.log("[*] ELF magic 正常 (7f 45 4c 46)");
      return true;
    } else {
      console.log(
        "[!] ELF magic 异常: " +
          view[0].toString(16) +
          " " +
          view[1].toString(16) +
          " " +
          view[2].toString(16) +
          " " +
          view[3].toString(16),
      );
      return false;
    }
  } catch (e) {
    console.log("[!] 读取基地址失败: " + e);
    return false;
  }
}

// 解析 ELF header 获取关键信息（用于后续 SoFixer 修复）
function parseElfHeader(base) {
  var info = {};
  try {
    var eiClass = base.add(4).readU8(); // EI_CLASS
    info.is64 = eiClass === 2;
    console.log("[*] 架构: " + (info.is64 ? "ELF64 (arm64)" : "ELF32 (arm)"));

    if (info.is64) {
      info.phoff = base.add(0x20).readU64();
      info.shoff = base.add(0x28).readU64();
      info.phnum = base.add(0x38).readU16();
      info.shnum = base.add(0x3c).readU16();
    } else {
      info.phoff = base.add(0x1c).readU32();
      info.shoff = base.add(0x20).readU32();
      info.phnum = base.add(0x2c).readU16();
      info.shnum = base.add(0x30).readU16();
    }

    console.log(
      "[*] Program Headers: offset=0x" +
        info.phoff.toString(16) +
        " count=" +
        info.phnum,
    );
    console.log(
      "[*] Section Headers: offset=0x" +
        info.shoff.toString(16) +
        " count=" +
        info.shnum,
    );

    // 加固后 section header 通常被抹掉
    if (info.shnum === 0 || info.shoff === 0) {
      console.log(
        "[!] Section Header 已被抹除（典型加固特征），需要 SoFixer 修复",
      );
    }
  } catch (e) {
    console.log("[!] 解析 ELF header 失败: " + e);
  }
  return info;
}

// 枚举内存段，获取真实的内存布局（比 module.size 更准确）
function getMemoryRanges(moduleName) {
  var ranges = Process.findModuleByName(moduleName).enumerateRanges("r--");
  console.log("[*] 内存段数量: " + ranges.length);
  ranges.forEach(function (range, idx) {
    console.log(
      "    段[" +
        idx +
        "] base=" +
        range.base +
        " size=0x" +
        range.size.toString(16) +
        " prot=" +
        range.protection,
    );
  });
  return ranges;
}

// ======================== Dump 核心逻辑 ========================

function dumpToFile(module) {
  var savePath = getSavePath(module.name);
  console.log("[*] 开始 dump 到文件: " + savePath);

  var fd = new File(savePath, "wb");
  var baseAddr = module.base;
  var remaining = module.size;
  var offset = 0;
  var blockSize = CONFIG.dumpBlockSize;
  var failedBlocks = 0;

  while (remaining > 0) {
    var readSize = Math.min(blockSize, remaining);
    try {
      var buf = baseAddr.add(offset).readByteArray(readSize);
      fd.write(buf);
    } catch (e) {
      fd.write(new ArrayBuffer(readSize));
      failedBlocks++;
    }
    offset += readSize;
    remaining -= readSize;
  }

  fd.flush();
  fd.close();

  console.log(
    "[+] Dump 完成! 大小: " + (module.size / 1024 / 1024).toFixed(2) + " MB",
  );
  if (failedBlocks > 0) {
    console.log("[!] 有 " + failedBlocks + " 个块不可读，已填充零字节");
  }
  console.log("[+] 设备路径: " + savePath);
  return savePath;
}

function dumpViaSend(module) {
  console.log("[*] 通过 send() 传输 dump 数据到 Python 端...");
  var baseAddr = module.base;
  var total = module.size;
  var blockSize = 1024 * 1024; // 1MB
  var blocks = Math.ceil(total / blockSize);

  // 先发送元信息
  send({
    type: "dump_start",
    name: module.name,
    base: module.base.toString(),
    size: total,
    blocks: blocks,
  });

  for (var i = 0; i < blocks; i++) {
    var offset = i * blockSize;
    var readSize = Math.min(blockSize, total - offset);
    try {
      var buf = baseAddr.add(offset).readByteArray(readSize);
      send(
        { type: "dump_block", index: i, total: blocks, offset: offset },
        buf,
      );
    } catch (e) {
      send(
        { type: "dump_block", index: i, total: blocks, offset: offset },
        new ArrayBuffer(readSize),
      );
    }
  }

  send({ type: "dump_complete", name: module.name, size: total });
  console.log("[+] 数据传输完成，共 " + blocks + " 个块");
}

// ======================== 主流程 ========================

function doDump(moduleName) {
  var module = Process.findModuleByName(moduleName);
  if (!module) {
    console.log("[!] 模块未找到: " + moduleName);
    return;
  }

  console.log("──────────────────────────────────────");
  console.log("[*] 模块: " + module.name);
  console.log("[*] 基址: " + module.base);
  console.log(
    "[*] 大小: 0x" +
      module.size.toString(16) +
      " (" +
      (module.size / 1024 / 1024).toFixed(2) +
      " MB)",
  );
  console.log("[*] 路径: " + module.path);
  console.log("──────────────────────────────────────");

  // 步骤1: 检查是否已解密
  if (!checkDecrypted(module)) {
    console.log("[!] 模块可能尚未解密，dump 的数据可能不完整");
  }

  // 步骤2: 解析 ELF header
  var elfInfo = parseElfHeader(module.base);

  // 步骤3: 枚举内存段
  getMemoryRanges(moduleName);

  // 步骤4: 执行 dump
  if (CONFIG.saveTo === "file") {
    var path = dumpToFile(module);
    console.log("\n[+] ===== 后续操作 =====");
    console.log("[+] 1. 拉取 dump 文件:");
    console.log(
      "    adb shell su -c 'cp " + path + " /sdcard/" + moduleName + ".dump'",
    );
    console.log(
      "    adb pull /sdcard/" + moduleName + ".dump ./" + moduleName + ".dump",
    );
    console.log("[+] 2. 使用 SoFixer 修复 ELF:");
    console.log(
      "    sofixer -s " +
        moduleName +
        ".dump -o " +
        moduleName +
        ".fixed -m 0x" +
        module.base.toString().replace("0x", ""),
    );
    console.log("[+] 3. 用 IDA/Ghidra 打开 " + moduleName + ".fixed 分析");
  } else {
    dumpViaSend(module);
  }
}

function waitAndDump(moduleName) {
  var module = Process.findModuleByName(moduleName);

  if (module === null) {
    console.log("[!] 模块尚未加载，hook dlopen 等待...");

    var onLoaded = function (path) {
      console.log("[*] 检测到模块加载: " + path);
      console.log(
        "[*] 等待 " + CONFIG.waitDecryptDelay / 1000 + " 秒让壳解密...",
      );
      setTimeout(function () {
        doDump(moduleName);
      }, CONFIG.waitDecryptDelay);
    };

    var hooked = false;

    // 要 hook 的 dlopen 系列函数
    var dlopenFuncs = ["android_dlopen_ext", "dlopen", "__loader_dlopen"];
    dlopenFuncs.forEach(function (funcName) {
      try {
        var addr = Module.findExportByName(null, funcName);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter: function (args) {
              try {
                this.path = args[0].readCString();
              } catch (e) {
                this.path = null;
              }
            },
            onLeave: function (retval) {
              if (this.path && this.path.indexOf(moduleName) !== -1) {
                onLoaded(this.path);
              }
            },
          });
          console.log("[*] Hooked: " + funcName);
          hooked = true;
        }
      } catch (e) {
        console.log("[!] Hook " + funcName + " 失败: " + e);
      }
    });

    if (!hooked) {
      console.log("[!] 无法 hook 任何 dlopen 函数，使用轮询等待...");
      var poll = setInterval(function () {
        var m = Process.findModuleByName(moduleName);
        if (m) {
          clearInterval(poll);
          onLoaded(m.path);
        }
      }, 2000);
    }
  } else {
    console.log(
      "[*] 模块已在内存中，等待 " +
        CONFIG.waitDecryptDelay / 1000 +
        " 秒确保解密完成...",
    );
    setTimeout(function () {
      doDump(moduleName);
    }, CONFIG.waitDecryptDelay);
  }
}

// ======================== 列出所有 SO 模块 ========================

function listAllModules() {
  console.log("\n[*] 当前进程已加载的 SO 模块:");
  console.log("──────────────────────────────────────");
  var modules = Process.enumerateModules();
  modules.forEach(function (m, idx) {
    if (m.name.endsWith(".so")) {
      console.log(
        "  [" +
          idx +
          "] " +
          m.name +
          "  base=" +
          m.base +
          "  size=0x" +
          m.size.toString(16) +
          "  (" +
          (m.size / 1024 / 1024).toFixed(2) +
          " MB)",
      );
    }
  });
  console.log("──────────────────────────────────────");
  console.log(
    "[*] 共 " +
      modules.filter(function (m) {
        return m.name.endsWith(".so");
      }).length +
      " 个 SO 模块",
  );
}

// ======================== 入口 ========================
console.log("==========================================");
console.log("  通用 SO Dump (加固/加壳场景)");
console.log("  目标模块: " + CONFIG.moduleName);
console.log("==========================================");

// 如果目标是占位符或 "list"，则列出所有模块
if (CONFIG.moduleName === "__TARGET_SO__" || CONFIG.moduleName === "list") {
  listAllModules();
  console.log("\n[!] 请通过 --so 参数指定要 dump 的模块名");
  console.log("    例: python dump_and_fix.py --so libFEProj.so");
} else {
  listAllModules();
  waitAndDump(CONFIG.moduleName);
}
