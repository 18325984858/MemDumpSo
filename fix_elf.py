import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dump_and_fix import fallback_fix_elf
result = fallback_fix_elf(r'c:\Users\user\Desktop\MemDumpSo\libUE4.so.dump', r'c:\Users\user\Desktop\MemDumpSo\libUE4.so.fixed')
print('Result:', result)
