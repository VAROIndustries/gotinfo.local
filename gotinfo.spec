# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], ['psutil', 'psutil._pswindows', 'netetw']
for pkg in ('textual', 'rich'):  # textual imports widgets dynamically
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h

a = Analysis(['gotinfo.py'], binaries=binaries, datas=datas, hiddenimports=hiddenimports, excludes=['tkinter'])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='gotinfo', console=True, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, upx=False, name='gotinfo')
