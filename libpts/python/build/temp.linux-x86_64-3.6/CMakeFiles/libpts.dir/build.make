# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/zhangxun/code/tensorflow_federated/third_party/libpts/python

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6

# Include any dependencies generated for this target.
include CMakeFiles/libpts.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/libpts.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/libpts.dir/flags.make

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o: CMakeFiles/libpts.dir/flags.make
CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o: ../../homomorph/dataIO.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o -c /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/dataIO.cpp

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libpts.dir/homomorph/dataIO.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/dataIO.cpp > CMakeFiles/libpts.dir/homomorph/dataIO.cpp.i

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libpts.dir/homomorph/dataIO.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/dataIO.cpp -o CMakeFiles/libpts.dir/homomorph/dataIO.cpp.s

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.requires:

.PHONY : CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.requires

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.provides: CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.requires
	$(MAKE) -f CMakeFiles/libpts.dir/build.make CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.provides.build
.PHONY : CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.provides

CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.provides.build: CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o


CMakeFiles/libpts.dir/homomorph/paillier.cpp.o: CMakeFiles/libpts.dir/flags.make
CMakeFiles/libpts.dir/homomorph/paillier.cpp.o: ../../homomorph/paillier.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/libpts.dir/homomorph/paillier.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libpts.dir/homomorph/paillier.cpp.o -c /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/paillier.cpp

CMakeFiles/libpts.dir/homomorph/paillier.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libpts.dir/homomorph/paillier.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/paillier.cpp > CMakeFiles/libpts.dir/homomorph/paillier.cpp.i

CMakeFiles/libpts.dir/homomorph/paillier.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libpts.dir/homomorph/paillier.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/paillier.cpp -o CMakeFiles/libpts.dir/homomorph/paillier.cpp.s

CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.requires:

.PHONY : CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.requires

CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.provides: CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.requires
	$(MAKE) -f CMakeFiles/libpts.dir/build.make CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.provides.build
.PHONY : CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.provides

CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.provides.build: CMakeFiles/libpts.dir/homomorph/paillier.cpp.o


CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o: CMakeFiles/libpts.dir/flags.make
CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o: ../../homomorph/cpu/pai_thread.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o -c /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/pai_thread.cpp

CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/pai_thread.cpp > CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.i

CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/pai_thread.cpp -o CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.s

CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.requires:

.PHONY : CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.requires

CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.provides: CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.requires
	$(MAKE) -f CMakeFiles/libpts.dir/build.make CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.provides.build
.PHONY : CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.provides

CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.provides.build: CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o


CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o: CMakeFiles/libpts.dir/flags.make
CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o: ../../homomorph/cpu/paillier_thread.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o -c /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/paillier_thread.cpp

CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/paillier_thread.cpp > CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.i

CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/homomorph/cpu/paillier_thread.cpp -o CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.s

CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.requires:

.PHONY : CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.requires

CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.provides: CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.requires
	$(MAKE) -f CMakeFiles/libpts.dir/build.make CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.provides.build
.PHONY : CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.provides

CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.provides.build: CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o


# Object files for target libpts
libpts_OBJECTS = \
"CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o" \
"CMakeFiles/libpts.dir/homomorph/paillier.cpp.o" \
"CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o" \
"CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o"

# External object files for target libpts
libpts_EXTERNAL_OBJECTS =

../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/homomorph/paillier.cpp.o
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/build.make
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: /usr/local/lib/libgmp.so
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: /usr/lib/x86_64-linux-gnu/libgmpxx.so
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: /usr/lib/x86_64-linux-gnu/libssl.so
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: /usr/lib/x86_64-linux-gnu/libcrypto.so
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: /usr/local/lib/libhcs.so
../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so: CMakeFiles/libpts.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX shared module ../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libpts.dir/link.txt --verbose=$(VERBOSE)
	/usr/bin/strip /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so

# Rule to build all files generated by this target.
CMakeFiles/libpts.dir/build: ../lib.linux-x86_64-3.6/libpts.cpython-36m-x86_64-linux-gnu.so

.PHONY : CMakeFiles/libpts.dir/build

CMakeFiles/libpts.dir/requires: CMakeFiles/libpts.dir/homomorph/dataIO.cpp.o.requires
CMakeFiles/libpts.dir/requires: CMakeFiles/libpts.dir/homomorph/paillier.cpp.o.requires
CMakeFiles/libpts.dir/requires: CMakeFiles/libpts.dir/homomorph/cpu/pai_thread.cpp.o.requires
CMakeFiles/libpts.dir/requires: CMakeFiles/libpts.dir/homomorph/cpu/paillier_thread.cpp.o.requires

.PHONY : CMakeFiles/libpts.dir/requires

CMakeFiles/libpts.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/libpts.dir/cmake_clean.cmake
.PHONY : CMakeFiles/libpts.dir/clean

CMakeFiles/libpts.dir/depend:
	cd /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhangxun/code/tensorflow_federated/third_party/libpts/python /home/zhangxun/code/tensorflow_federated/third_party/libpts/python /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6 /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6 /home/zhangxun/code/tensorflow_federated/third_party/libpts/python/build/temp.linux-x86_64-3.6/CMakeFiles/libpts.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/libpts.dir/depend

