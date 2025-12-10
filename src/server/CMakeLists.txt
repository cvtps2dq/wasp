# Fetch sqlite_orm logic
include(FetchContent)
FetchContent_Declare(
        sqlite_orm
        GIT_REPOSITORY https://github.com/fnc12/sqlite_orm.git
        GIT_TAG        v1.8.2
)

# Bypass upstream CMakeLists.txt to avoid CMake < 3.5 errors
FetchContent_GetProperties(sqlite_orm)
if(NOT sqlite_orm_POPULATED)
    FetchContent_Populate(sqlite_orm)

    # Define the header-only library manually
    add_library(sqlite_orm INTERFACE)
    target_include_directories(sqlite_orm INTERFACE ${sqlite_orm_SOURCE_DIR}/include)

    # Create the alias so your code finds sqlite_orm::sqlite_orm
    add_library(sqlite_orm::sqlite_orm ALIAS sqlite_orm)
endif()

add_executable(wasp_server main.cpp session_manager.cpp)

# Link SQLite3 and the ORM
find_package(SQLite3 REQUIRED)

target_link_libraries(wasp_server PRIVATE
        libwasp
        ${LWS_LIBRARY}
        OpenSSL::Crypto
        pthread
        sqlite_orm::sqlite_orm
        SQLite::SQLite3
)