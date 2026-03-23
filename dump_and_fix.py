#!/usr/bin/env python3
# =============================================================
#  dump_and_fix.py — 自动化编排：Frida dump + SoFixer 修复
#
#  完整流程:
#    ① Frida attach 目标进程
#    ② 等待 SO 加载并解密完成
#    ③ 从内存 dump 出 SO
#    ④ SoFixer 修复 ELF 头
#    ⑤ 输出可供 IDA/Ghidra 分析的文件
#
#  用法:
#    python dump_and_fix.py --so libFEProj.so
#    python dump_and_fix.py --so libtersafe.so --pkg com.tencent.lolm
#    python dump_and_fix.py --list --pkg com.tencent.lolm
#    python dump_and_fix.py --pkg com.tencent.lolm --serial 37171FDJH001TH --so libFEProj.so
# =============================================================

import argparse
import os
import re
import struct
import subprocess
import sys
import time

try:
    import frida
except ImportError:
    print("[!] 请先安装 frida: pip install frida frida-tools")
    sys.exit(1)


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ======================== 配置 ========================

DEFAULT_PKG = "com.tencent.lolm"
DEFAULT_SO = "libFEProj.so"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ======================== ADB 工具 ========================

def adb_cmd(args, serial=None):
    """执行 adb 命令并返回输出"""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout.strip(), result.stderr.strip()


def adb_pull(remote_path, local_path, serial=None):
    """从设备拉取文件"""
    print(f"[*] 拉取文件: {remote_path} -> {local_path}")
    # 先复制到 sdcard（绕过权限问题）
    sdcard_path = f"/sdcard/{os.path.basename(remote_path)}"
    adb_cmd(["shell", "su", "-c", f"cp {remote_path} {sdcard_path}"], serial)
    time.sleep(1)

    stdout, stderr = adb_cmd(["pull", sdcard_path, local_path], serial)
    if "error" in stderr.lower():
        print(f"[!] 拉取失败: {stderr}")
        return False

    # 清理临时文件
    adb_cmd(["shell", "rm", sdcard_path], serial)
    print(f"[+] 拉取成功: {local_path}")
    return True


# ======================== Frida Dump ========================

class DumpReceiver:
    """接收 Frida send() 传输的 dump 数据"""

    def __init__(self, output_path):
        self.output_path = output_path
        self.fd = None
        self.base_addr = None
        self.total_size = 0
        self.received = 0
        self.done = False

    def on_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type", "")

            if msg_type == "dump_start":
                self.base_addr = payload["base"]
                self.total_size = payload["size"]
                self.fd = open(self.output_path, "wb")
                print(f"[*] 开始接收 dump 数据, 总大小: {self.total_size / 1024 / 1024:.2f} MB")

            elif msg_type == "dump_block":
                if self.fd and data:
                    self.fd.write(data)
                    self.received += len(data)
                    pct = self.received / self.total_size * 100 if self.total_size else 0
                    print(f"\r[*] 进度: {pct:.1f}% ({self.received}/{self.total_size})", end="")

            elif msg_type == "dump_complete":
                if self.fd:
                    self.fd.close()
                print(f"\n[+] dump 数据接收完成: {self.output_path}")
                self.done = True

        elif message["type"] == "error":
            print(f"[!] Frida 错误: {message['stack']}")


def frida_dump(pkg_name, so_name, serial=None, use_send=False):
    """
    通过 Frida attach 进程并 dump 指定 SO
    返回: (dump文件路径, 基地址hex字符串)
    """
    print(f"[*] 连接设备...")

    # 优先使用 USB 设备连接
    device = frida.get_usb_device(timeout=10)
    print(f"[*] 设备: {device.name} (id: {device.id})")

    # 先列出所有进程，查找目标
    print(f"[*] 枚举进程中...")
    processes = device.enumerate_processes()
    target_proc = None

    # 优先精确匹配进程名（主进程名 == 包名）
    for proc in processes:
        if proc.name == pkg_name:
            target_proc = proc
            break

    # 如果按名称没找到，尝试通过 enumerate_applications 匹配
    if not target_proc:
        try:
            apps = device.enumerate_applications(scope="full")
            for app in apps:
                if app.identifier == pkg_name and app.pid > 0:
                    target_proc = type('Proc', (), {'pid': app.pid, 'name': app.identifier})()
                    print(f"[*] 通过应用列表找到: PID={app.pid}")
                    break
        except Exception:
            pass

    # 最后模糊搜索（排除子进程如 :plugin, :xg_vip_service）
    if not target_proc:
        # 先找完全匹配的（不含冒号的主进程）
        candidates = [p for p in processes if p.name == pkg_name]
        if not candidates:
            candidates = [p for p in processes if p.name.startswith(pkg_name) and ":" not in p.name]
        if not candidates:
            candidates = [p for p in processes if pkg_name in p.name]
        if candidates:
            print(f"[*] 找到候选进程:")
            for p in candidates:
                print(f"    PID={p.pid}  名称={p.name}")
            target_proc = candidates[0]
            print(f"[*] 使用: {target_proc.name} (PID={target_proc.pid})")

    # attach 到目标进程
    if target_proc:
        print(f"[*] Attach 到进程: {target_proc.name} (PID={target_proc.pid})")
        try:
            session = device.attach(target_proc.pid)
        except Exception as e:
            print(f"[!] Attach 失败: {e}")
            sys.exit(1)
    else:
        # 最后尝试直接用包名 attach
        print(f"[*] Attach 到进程: {pkg_name}")
        try:
            session = device.attach(pkg_name)
        except frida.ProcessNotFoundError:
            print(f"[!] 进程未找到: {pkg_name}")
            print(f"[*] 当前运行的进程:")
            for p in sorted(processes, key=lambda x: x.name):
                print(f"    PID={p.pid}  {p.name}")
            sys.exit(1)

    # 读取 JS 脚本
    js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dumpil2cppso.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    def js_quote(value):
        return value.replace("\\", "\\\\").replace('"', '\\"')

    # 注入目标 SO 名称，仅替换 CONFIG 中的 moduleName 配置
    js_code = re.sub(
        r'moduleName:\s*"[^"]*"',
        f'moduleName: "{js_quote(so_name)}"',
        js_code,
        count=1,
    )
    print(f"[*] 目标 SO: {so_name}")

    # 注入包名，仅替换 CONFIG 中的 packageName 配置
    js_code = re.sub(
        r'packageName:\s*"[^"]*"',
        f'packageName: "{js_quote(pkg_name)}"',
        js_code,
        count=1,
    )

    # 如果使用 send 模式，修改配置
    if use_send:
        js_code = js_code.replace('saveTo: "file"', 'saveTo: "send"')

    dump_file = os.path.join(OUTPUT_DIR, f"{so_name}.dump")
    base_addr = None

    if use_send:
        # 通过 send() 接收数据
        receiver = DumpReceiver(dump_file)
        script = session.create_script(js_code)
        script.on("message", receiver.on_message)
        script.load()

        print("[*] 等待 dump 完成（脚本内含等待解密延迟）...")
        while not receiver.done:
            time.sleep(1)

        base_addr = receiver.base_addr
        script.unload()
    else:
        # 文件模式: JS 写入设备文件，再 adb pull 拉回
        base_addr_holder = {}

        def on_msg(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if payload.get("type") == "dump_start":
                    base_addr_holder["addr"] = payload["base"]
            elif message["type"] == "error":
                print(f"[!] Frida 错误: {message['stack']}")
            else:
                # 普通 console.log 输出
                pass

        script = session.create_script(js_code)
        script.on("message", on_msg)
        script.load()

        # 等待 dump 完成（脚本内有延迟等待解密）
        print("[*] 等待 dump 完成（脚本内含等待解密延迟）...")
        print("[*] 监听 Frida 日志输出，请观察终端...")
        time.sleep(25)  # 等待 JS 脚本执行完成（10s 解密等待 + dump 时间）

        # 从设备拉取 dump 文件
        remote_path = f"/data/data/{pkg_name}/{so_name}.dump"
        if not adb_pull(remote_path, dump_file, serial):
            print("[!] 文件拉取失败，尝试 send 模式重新 dump")
            script.unload()
            return frida_dump(pkg_name, so_name, serial, use_send=True)

        # 获取基地址（从日志解析）
        # 尝试通过额外脚本调用获取
        try:
            addr_script = session.create_script(f"""
                var m = Process.findModuleByName("{so_name}");
                if (m) send({{base: m.base.toString()}});
            """)
            def on_addr(msg, data):
                if msg["type"] == "send":
                    base_addr_holder["addr"] = msg["payload"]["base"]
            addr_script.on("message", on_addr)
            addr_script.load()
            time.sleep(1)
            addr_script.unload()
        except Exception:
            pass

        base_addr = base_addr_holder.get("addr")
        script.unload()

    session.detach()

    if not os.path.exists(dump_file):
        print("[!] dump 文件不存在!")
        sys.exit(1)

    size_mb = os.path.getsize(dump_file) / 1024 / 1024
    print(f"[+] Dump 文件: {dump_file} ({size_mb:.2f} MB)")
    print(f"[+] 基地址: {base_addr}")

    return dump_file, base_addr


# ======================== SoFixer 修复 ========================

def find_sofixer():
    """查找 SoFixer 可执行文件"""
    possible_names = ["SoFixer", "sofixer", "SoFixer-Windows-64", "SoFixer.exe", "sofixer.exe", "sofixer-windows-64.exe"]
    possible_dirs = [
        OUTPUT_DIR,
        os.path.join(OUTPUT_DIR, "tools"),
        os.getcwd(),
    ]

    # 先在 PATH 中搜索
    for name in possible_names:
        try:
            result = subprocess.run(
                ["where" if os.name == "nt" else "which", name],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception:
            pass

    # 在本地目录搜索
    for d in possible_dirs:
        for name in possible_names:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                return path

    return None


def align_up(value, alignment):
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def fallback_fix_elf(dump_file, output_file):
    """在 SoFixer 崩溃时执行最小 ELF 修复，重点修复 phdr 并补齐基础 shdr。"""
    with open(dump_file, "rb") as f:
        data = bytearray(f.read())

    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        print("[!] fallback 修复失败: 输入不是 ELF 文件")
        return None

    ei_class = data[4]
    ei_data = data[5]
    if ei_class != 2 or ei_data != 1:
        print("[!] fallback 修复仅支持 ELF64 小端文件")
        return None

    ehdr_struct = struct.Struct("<16sHHIQQQIHHHHHH")
    phdr_struct = struct.Struct("<IIQQQQQQ")
    shdr_struct = struct.Struct("<IIQQQQIIQQ")
    dyn_struct = struct.Struct("<QQ")

    ehdr = list(ehdr_struct.unpack_from(data, 0))
    e_phoff = ehdr[5]
    e_phentsize = ehdr[9]
    e_phnum = ehdr[10]

    if e_phoff <= 0 or e_phnum <= 0 or e_phentsize != phdr_struct.size:
        print("[!] fallback 修复失败: program header 无效")
        return None

    dynamic_offset = None
    dynamic_size = 0
    min_load = None
    max_load = 0
    note_segment = None
    eh_frame_segment = None

    for index in range(e_phnum):
        phoff = e_phoff + index * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = phdr_struct.unpack_from(data, phoff)
        fixed_offset = p_vaddr if p_vaddr < len(data) else p_offset
        if fixed_offset >= len(data):
            fixed_offset = p_offset
        fixed_filesz = p_memsz
        if fixed_offset + fixed_filesz > len(data):
            fixed_filesz = max(0, len(data) - fixed_offset)

        phdr_struct.pack_into(
            data,
            phoff,
            p_type,
            p_flags,
            fixed_offset,
            p_vaddr,
            p_vaddr,
            fixed_filesz,
            p_memsz,
            p_align,
        )

        if p_type == 1:
            load_start = p_vaddr & ~0xFFF
            load_end = align_up(p_vaddr + p_memsz, 0x1000)
            min_load = load_start if min_load is None else min(min_load, load_start)
            max_load = max(max_load, load_end)
        elif p_type == 4:
            note_segment = (fixed_offset, fixed_filesz)
        elif p_type == 0x6474E550:
            eh_frame_segment = (fixed_offset, fixed_filesz)

        if p_type == 2:
            dynamic_offset = fixed_offset
            dynamic_size = fixed_filesz

    if dynamic_offset is None or dynamic_size <= 0:
        print("[!] fallback 修复失败: dynamic segment 不存在")
        return None

    if min_load is None:
        min_load = 0

    dynamic = {}
    dynamic_entries = []
    max_dynamic_end = min(dynamic_offset + dynamic_size, len(data))
    for off in range(dynamic_offset, max_dynamic_end, dyn_struct.size):
        d_tag, d_val = dyn_struct.unpack_from(data, off)
        dynamic_entries.append((d_tag, d_val))
        if d_tag == 0:
            break
        if d_tag not in dynamic:
            dynamic[d_tag] = d_val

    dynamic_count = len(dynamic_entries)

    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_JMPREL = 23
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28

    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_REL = 9
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15
    SHT_ARM_EXIDX = 0x70000001

    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_LINK_ORDER = 0x80

    sections = [{
        "name": "",
        "type": SHT_NULL,
        "flags": 0,
        "addr": 0,
        "offset": 0,
        "size": 0,
        "link_name": None,
        "info": 0,
        "addralign": 0,
        "entsize": 0,
    }]

    def add_section(name, sec_type, flags, addr, size, link_name=None, info=0, addralign=1, entsize=0):
        if addr is None or size is None or size <= 0:
            return
        if addr < 0 or addr + size > len(data):
            return
        sections.append({
            "name": name,
            "type": sec_type,
            "flags": flags,
            "addr": addr,
            "offset": addr,
            "size": size,
            "link_name": link_name,
            "info": info,
            "addralign": addralign,
            "entsize": entsize,
        })

    hash_size = 0
    hash_nchain = 0
    if DT_HASH in dynamic and dynamic[DT_HASH] + 8 <= len(data):
        nbucket, nchain = struct.unpack_from("<II", data, dynamic[DT_HASH])
        hash_nchain = nchain
        hash_size = (nbucket + nchain + 2) * 8

    plt_type = dynamic.get(DT_PLTREL)
    plt_rel_addr = dynamic.get(DT_JMPREL)
    plt_rel_size = dynamic.get(DT_PLTRELSZ)
    rela_ent_size = dynamic.get(DT_RELAENT, 0x18)
    rel_ent_size = dynamic.get(DT_RELENT, 0x10)
    plt_ent_size = rela_ent_size if plt_type == DT_RELA else rel_ent_size
    plt_rel_count = 0
    if plt_rel_size and plt_ent_size:
        plt_rel_count = plt_rel_size // plt_ent_size

    rel_addr = dynamic.get(DT_REL)
    rel_size = dynamic.get(DT_RELSZ)
    rela_addr = dynamic.get(DT_RELA)
    rela_size = dynamic.get(DT_RELASZ)

    arm_exidx_addr = None
    arm_exidx_size = 0
    for entry in dynamic_entries:
        if entry[0] == 0x70000001:
            arm_exidx_addr = entry[1]
        elif entry[0] == 0x70000002:
            arm_exidx_size = entry[1]

    add_section(
        ".dynsym",
        SHT_DYNSYM,
        SHF_ALLOC,
        dynamic.get(DT_SYMTAB),
        hash_nchain * dynamic.get(DT_SYMENT, 0x18) if hash_nchain else dynamic.get(DT_SYMENT, 0x18),
        link_name=".dynstr",
        addralign=8,
        entsize=dynamic.get(DT_SYMENT, 0x18),
    )

    add_section(
        ".dynstr",
        SHT_STRTAB,
        SHF_ALLOC,
        dynamic.get(DT_STRTAB),
        dynamic.get(DT_STRSZ),
        addralign=1,
    )

    add_section(
        ".hash",
        SHT_HASH,
        SHF_ALLOC,
        dynamic.get(DT_HASH),
        hash_size,
        link_name=".dynsym",
        addralign=4,
        entsize=4,
    )

    if note_segment:
        add_section(
            ".note.gnu.build-id",
            SHT_NOTE,
            SHF_ALLOC,
            note_segment[0],
            note_segment[1],
            addralign=4,
        )

    if eh_frame_segment:
        add_section(
            ".eh_frame_hdr",
            SHT_PROGBITS,
            SHF_ALLOC,
            eh_frame_segment[0],
            eh_frame_segment[1],
            addralign=4,
        )

    add_section(
        ".rel.dyn",
        SHT_REL,
        SHF_ALLOC,
        rel_addr,
        rel_size,
        link_name=".dynsym",
        addralign=8,
        entsize=rel_ent_size,
    )

    add_section(
        ".rela.dyn",
        SHT_RELA,
        SHF_ALLOC,
        rela_addr,
        rela_size,
        link_name=".dynsym",
        addralign=8,
        entsize=rela_ent_size,
    )

    plt_name = ".rela.plt" if plt_type == DT_RELA else ".rel.plt"
    plt_sec_type = SHT_RELA if plt_type == DT_RELA else SHT_REL
    add_section(
        plt_name,
        plt_sec_type,
        SHF_ALLOC,
        plt_rel_addr,
        plt_rel_size,
        link_name=".dynsym",
        addralign=8,
        entsize=plt_ent_size,
    )

    if plt_rel_addr is not None and plt_rel_size:
        plt_addr = plt_rel_addr + plt_rel_size
        plt_size = min(20 + 12 * plt_rel_count, max(0, max_load - plt_addr))
        add_section(
            ".plt",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            plt_addr,
            plt_size,
            addralign=4,
        )

        text_addr = align_up(plt_addr + plt_size, 8)
        add_section(
            ".text&ARM.extab",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            text_addr,
            1,
            addralign=8,
        )

    add_section(
        ".ARM.exidx",
        SHT_ARM_EXIDX,
        SHF_ALLOC | SHF_LINK_ORDER,
        arm_exidx_addr,
        arm_exidx_size,
        link_name=".text&ARM.extab",
        addralign=4,
        entsize=0x8,
    )

    add_section(
        ".init_array",
        SHT_INIT_ARRAY,
        SHF_ALLOC | SHF_WRITE,
        dynamic.get(DT_INIT_ARRAY),
        dynamic.get(DT_INIT_ARRAYSZ),
        addralign=8,
    )

    add_section(
        ".fini_array",
        SHT_FINI_ARRAY,
        SHF_ALLOC | SHF_WRITE,
        dynamic.get(DT_FINI_ARRAY),
        dynamic.get(DT_FINI_ARRAYSZ),
        addralign=8,
    )

    add_section(
        ".dynamic",
        SHT_DYNAMIC,
        SHF_ALLOC | SHF_WRITE,
        dynamic_offset,
        dynamic_count * dyn_struct.size,
        link_name=".dynstr",
        addralign=8,
        entsize=0x10,
    )

    dynamic_end = dynamic_offset + dynamic_count * dyn_struct.size
    if dynamic_end < max_load:
        add_section(
            ".data",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_WRITE,
            dynamic_end,
            max_load - dynamic_end,
            addralign=4,
        )

    work_sections = sections[:1] + sorted(sections[1:], key=lambda entry: entry["addr"])

    name_to_index = {entry["name"]: idx for idx, entry in enumerate(work_sections) if entry["name"]}

    for entry in work_sections:
        if entry["name"] == ".hash":
            entry["link_name"] = ".dynsym"
        elif entry["name"] in {".rel.dyn", ".rela.dyn", ".rel.plt", ".rela.plt"}:
            entry["link_name"] = ".dynsym"
        elif entry["name"] == ".dynamic":
            entry["link_name"] = ".dynstr"
        elif entry["name"] == ".dynsym":
            entry["link_name"] = ".dynstr"
        elif entry["name"] == ".ARM.exidx":
            entry["link_name"] = ".text&ARM.extab"

    for index, entry in enumerate(work_sections):
        if entry["name"] == ".dynsym" and index + 1 < len(work_sections):
            entry["size"] = max(0, work_sections[index + 1]["addr"] - entry["addr"])
        if entry["name"] == ".text&ARM.extab" and index + 1 < len(work_sections):
            entry["size"] = max(0, work_sections[index + 1]["addr"] - entry["addr"])

    for index in range(2, len(work_sections)):
        prev_entry = work_sections[index - 1]
        entry = work_sections[index]
        gap = entry["offset"] - prev_entry["offset"]
        if gap < prev_entry["size"]:
            prev_entry["size"] = max(0, gap)

    work_sections = [entry for entry in work_sections if entry["name"] == "" or entry["size"] > 0]
    name_to_index = {entry["name"]: idx for idx, entry in enumerate(work_sections) if entry["name"]}

    shstrtab = bytearray(b"\x00")
    for entry in work_sections[1:]:
        entry["name_offset"] = len(shstrtab)
        shstrtab.extend(entry["name"].encode("ascii") + b"\x00")

    shstrtab_name_offset = len(shstrtab)
    shstrtab.extend(b".shstrtab\x00")

    shstrtab_offset = align_up(max(len(data), max_load), 0x10)
    if shstrtab_offset > len(data):
        data.extend(b"\x00" * (shstrtab_offset - len(data)))
    data.extend(shstrtab)

    shdr_offset = align_up(len(data), 8)
    if shdr_offset > len(data):
        data.extend(b"\x00" * (shdr_offset - len(data)))

    shstrtab_index = len(work_sections)
    final_sections = work_sections + [{
        "name": ".shstrtab",
        "name_offset": shstrtab_name_offset,
        "type": SHT_STRTAB,
        "flags": 0,
        "addr": shstrtab_offset,
        "offset": shstrtab_offset,
        "size": len(shstrtab),
        "link_name": None,
        "info": 0,
        "addralign": 1,
        "entsize": 0,
    }]

    for entry in final_sections:
        if entry["name"] == "":
            entry["name_offset"] = 0

    for entry in final_sections:
        link = name_to_index.get(entry.get("link_name"), 0)
        data.extend(shdr_struct.pack(
            entry["name_offset"],
            entry["type"],
            entry["flags"],
            entry["addr"],
            entry["offset"],
            entry["size"],
            link,
            entry["info"],
            entry["addralign"],
            entry["entsize"],
        ))

    ehdr[6] = shdr_offset
    ehdr[11] = shdr_struct.size
    ehdr[12] = len(final_sections)
    ehdr[13] = shstrtab_index
    ehdr_struct.pack_into(data, 0, *ehdr)

    with open(output_file, "wb") as f:
        f.write(data)

    print(f"[+] fallback 修复完成: {output_file}")
    return output_file


def run_sofixer(dump_file, base_addr, output_file=None):
    """
    使用 SoFixer 修复 dump 出的 ELF 文件
    SoFixer: https://github.com/F8LEFT/SoFixer
    """
    sofixer = find_sofixer()

    if not sofixer:
        print("\n[!] 未找到 SoFixer，请手动修复:")
        print(f"    下载: https://github.com/F8LEFT/SoFixer")
        print(f"    用法: SoFixer -s {dump_file} -o {dump_file.replace('.dump', '.fixed')} -m {base_addr}")
        print(f"\n[*] 也可直接用 IDA 打开 dump 文件（部分功能可用）")
        return None

    if not output_file:
        output_file = dump_file.replace(".dump", ".fixed")

    # 检测架构（读取 ELF header 的 EI_CLASS）
    with open(dump_file, "rb") as f:
        elf_header = f.read(5)

    if len(elf_header) < 5 or elf_header[:4] != b"\x7fELF":
        print("[!] dump 文件不是有效的 ELF 文件!")
        return None

    is_64 = (elf_header[4] == 2)
    arch_flag = "-d" if is_64 else ""  # SoFixer -d 表示64位

    cmd = [sofixer, "-s", dump_file, "-o", output_file, "-m", str(base_addr)]
    if arch_flag:
        cmd.append(arch_flag)

    print(f"\n[*] 运行 SoFixer: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("[!] SoFixer 执行超时，尝试使用 fallback 修复")
        return fallback_fix_elf(dump_file, output_file)

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        print(f"[!] SoFixer 返回非零退出码: {result.returncode}")
        return fallback_fix_elf(dump_file, output_file)

    if os.path.exists(output_file):
        size_mb = os.path.getsize(output_file) / 1024 / 1024
        print(f"[+] 修复完成: {output_file} ({size_mb:.2f} MB)")
        return output_file
    else:
        print("[!] SoFixer 修复失败，尝试使用 fallback 修复")
        return fallback_fix_elf(dump_file, output_file)


# ======================== 主流程 ========================

def main():
    parser = argparse.ArgumentParser(description="Frida dump + SoFixer 自动化工具（支持任意 SO）")
    parser.add_argument("--pkg", default=DEFAULT_PKG, help=f"目标包名 (默认: {DEFAULT_PKG})")
    parser.add_argument("--so", default=DEFAULT_SO, help=f"要 dump 的 SO 名称 (默认: {DEFAULT_SO})")
    parser.add_argument("--serial", "-s", default=None, help="ADB 设备序列号")
    parser.add_argument("--use-send", action="store_true", help="使用 send 模式传输（无需 root cp）")
    parser.add_argument("--skip-dump", default=None, help="跳过 dump，直接修复指定文件")
    parser.add_argument("--base", default=None, help="手动指定基地址 (如 0x7a12340000)")
    parser.add_argument("--list", action="store_true", help="列出目标进程所有已加载的 SO 模块")
    args = parser.parse_args()

    print("=" * 50)
    print("  通用 SO Dump & Fix 自动化工具")
    print("=" * 50)

    # 如果是列出模块模式
    if args.list:
        so_name = "list"
        print(f"\n[*] 列出 {args.pkg} 进程中所有已加载的 SO 模块...")
        frida_dump(args.pkg, so_name, args.serial)
        return

    # 步骤 1-3: Frida dump
    if args.skip_dump:
        dump_file = args.skip_dump
        base_addr = args.base
        if not base_addr:
            print("[!] 跳过 dump 时必须通过 --base 指定基地址")
            sys.exit(1)
        print(f"[*] 跳过 dump，使用已有文件: {dump_file}")
    else:
        print(f"\n[步骤 1-3] Frida attach + 等待解密 + dump")
        print(f"[*] 目标: {args.pkg}")
        print(f"[*] SO:   {args.so}")
        dump_file, base_addr = frida_dump(args.pkg, args.so, args.serial, args.use_send)

    # 步骤 4: SoFixer 修复
    print(f"\n[步骤 4] SoFixer 修复 ELF")
    fixed_file = run_sofixer(dump_file, base_addr)

    # 步骤 5: 提示分析
    print(f"\n[步骤 5] 分析")
    target = fixed_file if fixed_file else dump_file
    print(f"[+] 请使用 IDA Pro 或 Ghidra 打开: {target}")
    if not fixed_file:
        print(f"[*] 提示: 在 IDA 中加载时选择 'Manual Load'，设置基地址为 {base_addr}")

    print("\n[+] 全部完成!")


if __name__ == "__main__":
    main()
