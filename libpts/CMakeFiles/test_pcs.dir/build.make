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
CMAKE_SOURCE_DIR = /home/zhangxun/code/tensorflow_federated/third_party/libpts

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zhangxun/code/tensorflow_federated/third_party/libpts

# Include any dependencies generated for this target.
include CMakeFiles/test_pcs.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test_pcs.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_pcs.dir/flags.make

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o: CMakeFiles/test_pcs.dir/flags.make
CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o: test/test_pcs.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o -c /home/zhangxun/code/tensorflow_federated/third_party/libpts/test/test_pcs.cpp

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_pcs.dir/test/test_pcs.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhangxun/code/tensorflow_federated/third_party/libpts/test/test_pcs.cpp > CMakeFiles/test_pcs.dir/test/test_pcs.cpp.i

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_pcs.dir/test/test_pcs.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhangxun/code/tensorflow_federated/third_party/libpts/test/test_pcs.cpp -o CMakeFiles/test_pcs.dir/test/test_pcs.cpp.s

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.requires:

.PHONY : CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.requires

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.provides: CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.requires
	$(MAKE) -f CMakeFiles/test_pcs.dir/build.make CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.provides.build
.PHONY : CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.provides

CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.provides.build: CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o


# Object files for target test_pcs
test_pcs_OBJECTS = \
"CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o"

# External object files for target test_pcs
test_pcs_EXTERNAL_OBJECTS =

bin/test_pcs: CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o
bin/test_pcs: CMakeFiles/test_pcs.dir/build.make
bin/test_pcs: lib/libhcs.so
bin/test_pcs: /usr/local/lib/libgmp.so
bin/test_pcs: /usr/lib/x86_64-linux-gnu/libgmpxx.so
bin/test_pcs: CMakeFiles/test_pcs.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zhangxun/code/tensorflow_federated/third_party/libpts/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/test_pcs"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_pcs.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_pcs.dir/build: bin/test_pcs

.PHONY : CMakeFiles/test_pcs.dir/build

CMakeFiles/test_pcs.dir/requires: CMakeFiles/test_pcs.dir/test/test_pcs.cpp.o.requires

.PHONY : CMakeFiles/test_pcs.dir/requires

CMakeFiles/test_pcs.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_pcs.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_pcs.dir/clean

CMakeFiles/test_pcs.dir/depend:
	cd /home/zhangxun/code/tensorflow_federated/third_party/libpts && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhangxun/code/tensorflow_federated/third_party/libpts /home/zhangxun/code/tensorflow_federated/third_party/libpts /home/zhangxun/code/tensorflow_federated/third_party/libpts /home/zhangxun/code/tensorflow_federated/third_party/libpts /home/zhangxun/code/tensorflow_federated/third_party/libpts/CMakeFiles/test_pcs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_pcs.dir/depend

