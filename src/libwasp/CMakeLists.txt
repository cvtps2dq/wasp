add_library(libwasp STATIC
        wasp_session.cpp
        worker_pool.cpp
        tun_device.cpp
        wasp_protocol.cpp
)

target_include_directories(libwasp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(libwasp PRIVATE ${LWS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(libwasp PRIVATE OpenSSL::Crypto ${LWS_LIBRARY})