add_executable(sting main.cpp)
target_link_libraries(sting PRIVATE libwasp ${LWS_LIBRARY} OpenSSL::Crypto pthread)