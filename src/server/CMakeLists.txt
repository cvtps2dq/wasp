add_executable(wasp_server main.cpp session_manager.cpp)
target_link_libraries(wasp_server PRIVATE libwasp ${LWS_LIBRARY} OpenSSL::Crypto pthread)