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
CMAKE_SOURCE_DIR = /home/steve/Documents/my_sockets

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/steve/Documents/my_sockets/build

# Include any dependencies generated for this target.
include CMakeFiles/my_sockets_tdd.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/my_sockets_tdd.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/my_sockets_tdd.dir/flags.make

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o: CMakeFiles/my_sockets_tdd.dir/flags.make
CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o: ../msg_server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/steve/Documents/my_sockets/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o"
	/usr/bin/clang++-10  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o -c /home/steve/Documents/my_sockets/msg_server.cpp

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.i"
	/usr/bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/steve/Documents/my_sockets/msg_server.cpp > CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.i

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.s"
	/usr/bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/steve/Documents/my_sockets/msg_server.cpp -o CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.s

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.requires:

.PHONY : CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.requires

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.provides: CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.requires
	$(MAKE) -f CMakeFiles/my_sockets_tdd.dir/build.make CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.provides.build
.PHONY : CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.provides

CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.provides.build: CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o


# Object files for target my_sockets_tdd
my_sockets_tdd_OBJECTS = \
"CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o"

# External object files for target my_sockets_tdd
my_sockets_tdd_EXTERNAL_OBJECTS =

my_sockets_tdd: CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o
my_sockets_tdd: CMakeFiles/my_sockets_tdd.dir/build.make
my_sockets_tdd: CMakeFiles/my_sockets_tdd.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/steve/Documents/my_sockets/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable my_sockets_tdd"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/my_sockets_tdd.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/my_sockets_tdd.dir/build: my_sockets_tdd

.PHONY : CMakeFiles/my_sockets_tdd.dir/build

CMakeFiles/my_sockets_tdd.dir/requires: CMakeFiles/my_sockets_tdd.dir/msg_server.cpp.o.requires

.PHONY : CMakeFiles/my_sockets_tdd.dir/requires

CMakeFiles/my_sockets_tdd.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/my_sockets_tdd.dir/cmake_clean.cmake
.PHONY : CMakeFiles/my_sockets_tdd.dir/clean

CMakeFiles/my_sockets_tdd.dir/depend:
	cd /home/steve/Documents/my_sockets/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/steve/Documents/my_sockets /home/steve/Documents/my_sockets /home/steve/Documents/my_sockets/build /home/steve/Documents/my_sockets/build /home/steve/Documents/my_sockets/build/CMakeFiles/my_sockets_tdd.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/my_sockets_tdd.dir/depend

