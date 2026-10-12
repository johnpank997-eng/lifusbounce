
from pathlib import Path
import argparse
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--before-header', type=Path)
args = parser.parse_args()
build = root / 'build/performance'
build.mkdir(parents=True, exist_ok=True)
release = root / 'out/obj/release'
objects = [release / 'sdk_skeleton.obj']
objects += [release / ('third_party_imgui_imgui' + suffix + '.obj')
            for suffix in ('', '_draw', '_tables', '_widgets')]
if any(not p.exists() for p in objects):
    raise SystemExit('build release first')
(build / 'link.rsp').write_text('\n'.join('"' + str(p) + '"' for p in objects)
                              + '\nuser32.lib\ngdi32.lib\nimm32.lib\n')
define = ''
if args.before_header:
    header = args.before_header.resolve()
    if not header.is_file():
        raise SystemExit('missing reference header')
    reference = header.read_text(encoding='utf-8').replace(
        'namespace base::draw {', 'namespace base::legacy_draw {').replace(
        'base::sdk::skeleton::Project(', 'base::performance::LegacyProject(')
    for old,new in [('nodes','Nodes'),('matrix','Matrix'),('circle_geometry','CircleGeometry'),('bone','Bone')]:
        reference = reference.replace('base::sdk::skeleton::'+old, 'base::sdk::skeleton::'+new)
    reference = reference.replace('base::sdk::skeleton::project(', 'base::performance::LegacyProject(')
    if 'namespace base::legacy_draw {' not in reference:
        raise SystemExit('unexpected reference header')
    define = '/DPERFORMANCE_BEFORE '
vcvars = r'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'
(build / 'check.cmd').write_text(f'''@echo off
call "{vcvars}" >nul
cl /nologo /std:c++20 /EHsc /MT /O2 /W4 /DNOMINMAX /DWIN32_LEAN_AND_MEAN {define}/Isrc /Ithird_party/imgui /c tools/performance_checks.cpp /Fo"{build / 'checks.obj'}"
if errorlevel 1 exit /b 1
link /nologo /OUT:"{build / 'checks.exe'}" "{build / 'checks.obj'}" @"{build / 'link.rsp'}"
if errorlevel 1 exit /b 1
"{build / 'checks.exe'}"
''')
if args.before_header:
    (build / 'draw-before.hpp').write_text(reference, encoding='utf-8')
result = subprocess.run(['cmd.exe', '/c', str(build / 'check.cmd')], cwd=root,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
print(result.stdout, end='')
log = 'benchmark.txt' if args.before_header else 'regression.txt'
(build / log).write_text(result.stdout, encoding='utf-8')
result.check_returncode()
