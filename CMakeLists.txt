cmake_minimum_required(VERSION 2.8.11)
project(note_server_demo)

# Allow disabling server logging with: cmake -DLOG_SILENT=ON ..
OPTION(LOG_SILENT "Disables server logs when client connect/disconnect" OFF)
IF(LOG_SILENT)
	add_definitions(-DLOG_SILENT)
ENDIF(LOG_SILENT)

# Build everything position independent
add_definitions(-fPIC)

# Note server target
add_executable(simple_note_server simple_note_server.c)
