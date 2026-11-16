#cmake 문법으로 프로그램 어떻게 만들지 작성하는 빌드 설명서
cmake_minimum_required(VERSION 3.22) 
#  cmake 최소 버전 명시(최소 3.22이싱으로 cmake를 설치해야함)

project(seal_practice LANGUAGES CXX) 
#  프로젝트 이름과 언어 명시

set(CMAKE_CXX_STANDARD 17) 
#  만드는 대상에 C++17 표준 사용
set(CMAKE_CXX_STANDARD_REQUIRED ON) 
#  C++17 표준 사용 필수, 요청한 표준을 사용할 수 없을때 낮은 표준으로 자동 변경하지 않도록 설정
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) 
# compile_commands.json 파일 생성(각 소스 파일 컴파일에 필요한 명령어와 옵션 기록, 빌드 명령어를 json 형식으로 저장, clangd에서 사용해 읽을 수 있음, 어느 소스 파일이 어떤 옵션으로 컴파일되는지 확인 가능)

find_package(SEAL REQUIRED) 
# SEAL 라이브러리 찾기, SEALConfig.cmake 파일을 통해 SEAL 라이브러리 경로를 찾음, REQUIRED 옵션은 SEAL 라이브러리를 찾지 못하면 에러 발생

add_executable(hello hello.cpp) 
# hello.cpp 파일을 컴파일하여 hello 실행 파일 생성

target_link_libraries(hello PRIVATE SEAL::seal_shared) 
# hello 실행 파일에 SEAL 라이브러리 링크, PRIVATE 옵션은 hello 실행 파일만 SEAL 라이브러리를 사용하도록 설정, 다른 대상이 hello를 링크해도 SEAL 라이브러리를 링크하지 않음  


add_executable(region_statistics region_statistics.cpp) 
target_link_libraries(region_statistics PRIVATE SEAL::seal_shared) 

add_executable(multi_condition multi_condition.cpp)
target_link_libraries(multi_condition PRIVATE SEAL::seal_shared)

add_executable(simd_conditional_stats simd_conditional_stats.cpp)
target_link_libraries(simd_conditional_stats PRIVATE SEAL::seal_shared)

add_executable(benchmark benchmark.cpp)
target_link_libraries(benchmark PRIVATE SEAL::seal_shared)

add_executable(extended_stats extended_stats.cpp)
target_link_libraries(extended_stats PRIVATE SEAL::seal_shared)

add_executable(benchmark_large benchmark_large.cpp)
target_link_libraries(benchmark_large PRIVATE SEAL::seal_shared)