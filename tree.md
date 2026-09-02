

## Project File Tree

```markdown
├── 📂 build
│  ├── 📂 CMakeFiles
│  │  ├── 📂 4.4.2
│  │  │  ├── 📂 CompilerIdC
│  │  │  │  ├── 📂 tmp
│  │  │  │  ├── 📄 a.exe
│  │  │  │  └── 📄 CMakeCCompilerId.c
│  │  │  ├── 📄 CMakeCCompiler.cmake
│  │  │  ├── 📄 CMakeDetermineCompilerABI_C.bin
│  │  │  ├── 📄 CMakeRCCompiler.cmake
│  │  │  └── 📄 CMakeSystem.cmake
│  │  ├── 📂 jockey_demo.dir
│  │  │  ├── 📂 demo
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  ├── 📄 linkLibs.rsp
│  │  │  ├── 📄 objects1.rsp
│  │  │  └── 📄 progress.make
│  │  ├── 📂 jockey_shared.dir
│  │  │  ├── 📂 src
│  │  │  │  ├── 📂 pal
│  │  │  │  └── 📂 syscalls
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  ├── 📄 linkLibs.rsp
│  │  │  ├── 📄 objects1.rsp
│  │  │  └── 📄 progress.make
│  │  ├── 📂 jockey.dir
│  │  │  ├── 📂 src
│  │  │  │  ├── 📂 pal
│  │  │  │  ├── 📂 syscalls
│  │  │  │  ├── 📄 api_unhooking.c.obj
│  │  │  │  ├── 📄 api_unhooking.c.obj.d
│  │  │  │  ├── 📄 byovd_loader.c.obj
│  │  │  │  ├── 📄 byovd_loader.c.obj.d
│  │  │  │  ├── 📄 inject.c.obj
│  │  │  │  ├── 📄 inject.c.obj.d
│  │  │  │  ├── 📄 other_injections.c.obj
│  │  │  │  ├── 📄 other_injections.c.obj.d
│  │  │  │  ├── 📄 process_hollowing.c.obj
│  │  │  │  ├── 📄 process_hollowing.c.obj.d
│  │  │  │  ├── 📄 reflective_dll.c.obj
│  │  │  │  └── 📄 reflective_dll.c.obj.d
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean_target.cmake
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  └── 📄 progress.make
│  │  ├── 📂 pkgRedirects
│  │  ├── 📂 Progress
│  │  │  ├── 📄 1
│  │  │  ├── 📄 2
│  │  │  ├── 📄 3
│  │  │  ├── 📄 4
│  │  │  ├── 📄 5
│  │  │  ├── 📄 6
│  │  │  ├── 📄 7
│  │  │  └── 📄 count.txt
│  │  ├── 📄 cmake.check_cache
│  │  ├── ⚙️ CMakeConfigureLog.yaml
│  │  ├── 📄 CMakeDirectoryInformation.cmake
│  │  ├── ⚙️ InstallScripts.json
│  │  ├── 📄 Makefile.cmake
│  │  ├── 📄 Makefile2
│  │  ├── 📄 progress.marks
│  │  └── 📄 TargetDirectories.txt
│  ├── 📂 win
│  │  ├── 📂 CMakeFiles
│  │  │  ├── 📂 4.4.2
│  │  │  │  ├── 📂 CompilerIdC
│  │  │  │  │  ├── 📂 tmp
│  │  │  │  │  ├── 📄 a.exe
│  │  │  │  │  └── 📄 CMakeCCompilerId.c
│  │  │  │  ├── 📄 CMakeCCompiler.cmake
│  │  │  │  ├── 📄 CMakeDetermineCompilerABI_C.bin
│  │  │  │  ├── 📄 CMakeRCCompiler.cmake
│  │  │  │  └── 📄 CMakeSystem.cmake
│  │  │  ├── 📂 CMakeScratch
│  │  │  ├── 📂 jockey_demo.dir
│  │  │  │  ├── 📂 demo
│  │  │  │  │  ├── 📄 main.c.obj
│  │  │  │  │  └── 📄 main.c.obj.d
│  │  │  │  ├── 📄 build.make
│  │  │  │  ├── 📄 cmake_clean.cmake
│  │  │  │  ├── 📄 compiler_depend.make
│  │  │  │  ├── 📄 compiler_depend.ts
│  │  │  │  ├── 📄 depend.make
│  │  │  │  ├── 📄 DependInfo.cmake
│  │  │  │  ├── 📄 flags.make
│  │  │  │  ├── 📄 includes_C.rsp
│  │  │  │  ├── 📄 link.txt
│  │  │  │  ├── 📄 linkLibs.rsp
│  │  │  │  ├── 📄 objects.a
│  │  │  │  ├── 📄 objects1.rsp
│  │  │  │  └── 📄 progress.make
│  │  │  ├── 📂 jockey_shared.dir
│  │  │  │  ├── 📂 src
│  │  │  │  │  ├── 📂 pal
│  │  │  │  │  │  ├── 📄 pal_win.c.obj
│  │  │  │  │  │  └── 📄 pal_win.c.obj.d
│  │  │  │  │  ├── 📂 syscalls
│  │  │  │  │  │  ├── 📄 syscalls_win.c.obj
│  │  │  │  │  │  └── 📄 syscalls_win.c.obj.d
│  │  │  │  │  ├── 📄 api_unhooking.c.obj
│  │  │  │  │  ├── 📄 api_unhooking.c.obj.d
│  │  │  │  │  ├── 📄 byovd_loader.c.obj
│  │  │  │  │  ├── 📄 byovd_loader.c.obj.d
│  │  │  │  │  ├── 📄 inject.c.obj
│  │  │  │  │  ├── 📄 inject.c.obj.d
│  │  │  │  │  ├── 📄 other_injections.c.obj
│  │  │  │  │  ├── 📄 other_injections.c.obj.d
│  │  │  │  │  ├── 📄 process_hollowing.c.obj
│  │  │  │  │  ├── 📄 process_hollowing.c.obj.d
│  │  │  │  │  ├── 📄 reflective_dll.c.obj
│  │  │  │  │  └── 📄 reflective_dll.c.obj.d
│  │  │  │  ├── 📄 build.make
│  │  │  │  ├── 📄 cmake_clean.cmake
│  │  │  │  ├── 📄 compiler_depend.make
│  │  │  │  ├── 📄 compiler_depend.ts
│  │  │  │  ├── 📄 depend.make
│  │  │  │  ├── 📄 DependInfo.cmake
│  │  │  │  ├── 📄 flags.make
│  │  │  │  ├── 📄 includes_C.rsp
│  │  │  │  ├── 📄 link.txt
│  │  │  │  ├── 📄 linkLibs.rsp
│  │  │  │  ├── 📄 objects.a
│  │  │  │  ├── 📄 objects1.rsp
│  │  │  │  └── 📄 progress.make
│  │  │  ├── 📂 jockey.dir
│  │  │  │  ├── 📂 src
│  │  │  │  │  ├── 📂 pal
│  │  │  │  │  │  ├── 📄 pal_win.c.obj
│  │  │  │  │  │  └── 📄 pal_win.c.obj.d
│  │  │  │  │  ├── 📂 syscalls
│  │  │  │  │  │  ├── 📄 syscalls_win.c.obj
│  │  │  │  │  │  └── 📄 syscalls_win.c.obj.d
│  │  │  │  │  ├── 📄 api_unhooking.c.obj
│  │  │  │  │  ├── 📄 api_unhooking.c.obj.d
│  │  │  │  │  ├── 📄 byovd_loader.c.obj
│  │  │  │  │  ├── 📄 byovd_loader.c.obj.d
│  │  │  │  │  ├── 📄 inject.c.obj
│  │  │  │  │  ├── 📄 inject.c.obj.d
│  │  │  │  │  ├── 📄 other_injections.c.obj
│  │  │  │  │  ├── 📄 other_injections.c.obj.d
│  │  │  │  │  ├── 📄 process_hollowing.c.obj
│  │  │  │  │  ├── 📄 process_hollowing.c.obj.d
│  │  │  │  │  ├── 📄 reflective_dll.c.obj
│  │  │  │  │  └── 📄 reflective_dll.c.obj.d
│  │  │  │  ├── 📄 build.make
│  │  │  │  ├── 📄 cmake_clean_target.cmake
│  │  │  │  ├── 📄 cmake_clean.cmake
│  │  │  │  ├── 📄 compiler_depend.make
│  │  │  │  ├── 📄 compiler_depend.ts
│  │  │  │  ├── 📄 depend.make
│  │  │  │  ├── 📄 DependInfo.cmake
│  │  │  │  ├── 📄 flags.make
│  │  │  │  ├── 📄 includes_C.rsp
│  │  │  │  ├── 📄 link.txt
│  │  │  │  └── 📄 progress.make
│  │  │  ├── 📂 pkgRedirects
│  │  │  ├── 📄 cmake.check_cache
│  │  │  ├── ⚙️ CMakeConfigureLog.yaml
│  │  │  ├── 📄 CMakeDirectoryInformation.cmake
│  │  │  ├── ⚙️ InstallScripts.json
│  │  │  ├── 📄 Makefile.cmake
│  │  │  ├── 📄 Makefile2
│  │  │  ├── 📄 progress.marks
│  │  │  └── 📄 TargetDirectories.txt
│  │  ├── 📄 cmake_install.cmake
│  │  ├── 📄 CMakeCache.txt
│  │  ├── 📄 jockey_demo.exe
│  │  ├── 📄 libjockey.a
│  │  ├── 📄 libjockey.dll
│  │  ├── 📄 libjockey.dll.a
│  │  └── 📄 Makefile
│  ├── 📄 build.bat
│  ├── 🔧 build.sh
│  ├── 🔧 clean.sh
│  ├── 📄 cmake_install.cmake
│  ├── 📄 CMakeCache.txt
│  └── 📄 Makefile
├── 📂 build_config
│  ├── 📂 CMakeFiles
│  │  ├── 📂 4.4.2
│  │  │  ├── 📂 CompilerIdC
│  │  │  │  ├── 📂 tmp
│  │  │  │  ├── 📄 a.exe
│  │  │  │  └── 📄 CMakeCCompilerId.c
│  │  │  ├── 📄 CMakeCCompiler.cmake
│  │  │  ├── 📄 CMakeDetermineCompilerABI_C.bin
│  │  │  ├── 📄 CMakeRCCompiler.cmake
│  │  │  └── 📄 CMakeSystem.cmake
│  │  ├── 📂 jockey_demo.dir
│  │  │  ├── 📂 demo
│  │  │  │  ├── 📄 main.c.obj
│  │  │  │  └── 📄 main.c.obj.d
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.internal
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  ├── 📄 linkLibs.rsp
│  │  │  ├── 📄 objects.a
│  │  │  ├── 📄 objects1.rsp
│  │  │  └── 📄 progress.make
│  │  ├── 📂 jockey_shared.dir
│  │  │  ├── 📂 src
│  │  │  │  ├── 📂 pal
│  │  │  │  │  ├── 📄 pal_win.c.obj
│  │  │  │  │  └── 📄 pal_win.c.obj.d
│  │  │  │  ├── 📂 syscalls
│  │  │  │  │  ├── 📄 syscalls_win.c.obj
│  │  │  │  │  └── 📄 syscalls_win.c.obj.d
│  │  │  │  ├── 📄 api_unhooking.c.obj
│  │  │  │  ├── 📄 api_unhooking.c.obj.d
│  │  │  │  ├── 📄 byovd_loader.c.obj
│  │  │  │  ├── 📄 byovd_loader.c.obj.d
│  │  │  │  ├── 📄 inject.c.obj
│  │  │  │  ├── 📄 inject.c.obj.d
│  │  │  │  ├── 📄 other_injections.c.obj
│  │  │  │  ├── 📄 other_injections.c.obj.d
│  │  │  │  ├── 📄 process_hollowing.c.obj
│  │  │  │  ├── 📄 process_hollowing.c.obj.d
│  │  │  │  ├── 📄 reflective_dll.c.obj
│  │  │  │  └── 📄 reflective_dll.c.obj.d
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.internal
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  ├── 📄 linkLibs.rsp
│  │  │  ├── 📄 objects.a
│  │  │  ├── 📄 objects1.rsp
│  │  │  └── 📄 progress.make
│  │  ├── 📂 jockey.dir
│  │  │  ├── 📂 src
│  │  │  │  ├── 📂 pal
│  │  │  │  │  ├── 📄 pal_win.c.obj
│  │  │  │  │  └── 📄 pal_win.c.obj.d
│  │  │  │  ├── 📂 syscalls
│  │  │  │  │  ├── 📄 syscalls_win.c.obj
│  │  │  │  │  └── 📄 syscalls_win.c.obj.d
│  │  │  │  ├── 📄 api_unhooking.c.obj
│  │  │  │  ├── 📄 api_unhooking.c.obj.d
│  │  │  │  ├── 📄 byovd_loader.c.obj
│  │  │  │  ├── 📄 byovd_loader.c.obj.d
│  │  │  │  ├── 📄 inject.c.obj
│  │  │  │  ├── 📄 inject.c.obj.d
│  │  │  │  ├── 📄 other_injections.c.obj
│  │  │  │  ├── 📄 other_injections.c.obj.d
│  │  │  │  ├── 📄 process_hollowing.c.obj
│  │  │  │  ├── 📄 process_hollowing.c.obj.d
│  │  │  │  ├── 📄 reflective_dll.c.obj
│  │  │  │  └── 📄 reflective_dll.c.obj.d
│  │  │  ├── 📄 build.make
│  │  │  ├── 📄 cmake_clean_target.cmake
│  │  │  ├── 📄 cmake_clean.cmake
│  │  │  ├── 📄 compiler_depend.internal
│  │  │  ├── 📄 compiler_depend.make
│  │  │  ├── 📄 compiler_depend.ts
│  │  │  ├── 📄 depend.make
│  │  │  ├── 📄 DependInfo.cmake
│  │  │  ├── 📄 flags.make
│  │  │  ├── 📄 includes_C.rsp
│  │  │  ├── 📄 link.txt
│  │  │  └── 📄 progress.make
│  │  ├── 📂 pkgRedirects
│  │  ├── 📄 cmake.check_cache
│  │  ├── ⚙️ CMakeConfigureLog.yaml
│  │  ├── 📄 CMakeDirectoryInformation.cmake
│  │  ├── ⚙️ InstallScripts.json
│  │  ├── 📄 Makefile.cmake
│  │  ├── 📄 Makefile2
│  │  ├── 📄 progress.marks
│  │  └── 📄 TargetDirectories.txt
│  ├── 📄 cmake_install.cmake
│  ├── 📄 CMakeCache.txt
│  ├── 📄 jockey_demo.exe
│  ├── 📄 libjockey.a
│  ├── 📄 libjockey.dll
│  ├── 📄 libjockey.dll.a
│  └── 📄 Makefile
├── 📂 demo
│  └── 📄 main.c
├── 📂 include
│  ├── 📂 linux
│  │  ├── 📄 pal_linux.c
│  │  └── 📄 syscalls_linux.c
│  ├── 📂 windows
│  │  ├── 📄 pal_win.c
│  │  └── 📄 syscalls_win.c
│  ├── 📄 api_unhooking.h
│  ├── 📄 byovd.h
│  ├── 📄 injection.h
│  ├── 📄 pal.h
│  ├── 📄 payload.exe
│  └── 📄 syscalls.h
├── 📂 src
│  ├── 📂 pal
│  │  ├── 📄 pal_linux.c
│  │  └── 📄 pal_win.c
│  ├── 📂 syscalls
│  │  ├── 📄 syscalls_linux.c
│  │  └── 📄 syscalls_win.c
│  ├── 📄 api_unhooking.c
│  ├── 📄 byovd_loader.c
│  ├── 📄 inject.c
│  ├── 📄 other_injections.c
│  ├── 📄 process_hollowing.c
│  └── 📄 reflective_dll.c
├── 📝 build_build.log
├── 📝 build_config.log
├── 📄 buildlog.txt
└── 📄 CMakeLists.txt

```