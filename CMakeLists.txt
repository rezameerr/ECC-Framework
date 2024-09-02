cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(ECC_Framework VERSION 0.1.0 LANGUAGES C CXX)

include_directories(${PROJECT_SOURCE_DIR}/lib)

set(INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include")

set(
    HEADER_FILES 
    ${INCLUDE_PATH}/Utils/Common.h
    ${INCLUDE_PATH}/Cryptography/HashFunctions.h
    ${INCLUDE_PATH}/Math/ExtensionField.h
    ${INCLUDE_PATH}/Math/ECPoint.h
    ${INCLUDE_PATH}/Math/EllipticCurve.h
    ${INCLUDE_PATH}/Math/EllipticCurveFq.h
    ${INCLUDE_PATH}/ECC/ECCDomainParameters.h
    ${INCLUDE_PATH}/ECC/ECC.h
    ${INCLUDE_PATH}/ECC/ECCKey.h
    ${INCLUDE_PATH}/ECC/ECDHE.h
    ${INCLUDE_PATH}/ECC/StandardCurves.h
    ${INCLUDE_PATH}/ECC/ECCPrivateKey.h
    ${INCLUDE_PATH}/ECC/ECCPublicKey.h
    ${INCLUDE_PATH}/ECC/ECDSA.h
    ${INCLUDE_PATH}/Cryptography/Twofish.h
    ${INCLUDE_PATH}/ECC/ECElGamal.h
    ${INCLUDE_PATH}/ECC/ECIES.h
    ${INCLUDE_PATH}/ECC/ECIESCryptographySuits.h
    ${INCLUDE_PATH}/Cryptography/TwofishWrapper.h
    ${PROJECT_SOURCE_DIR}/src/Cryptography/argon2/include/argon2.h
    ${PROJECT_SOURCE_DIR}/src/Cryptography/argon2/src/blake2/blake2-impl.h
    ${PROJECT_SOURCE_DIR}/src/Cryptography/argon2/src/blake2/blake2.h
    ${INCLUDE_PATH}/Cryptography/HMAC.h
    )

set(
    SOURCES 
    main.cpp 
    src/Utils/Common.cpp
    src/Cryptography/HashFunctions.cpp
    src/Math/ExtensionField.cpp
    src/Math/ECPoint.cpp
    src/Math/EllipticCurve.cpp
    src/Math/EllipticCurveFq.cpp
    src/ECC/ECCDomainParameters.cpp
    src/ECC/ECC.cpp
    src/ECC/ECCKey.cpp
    src/ECC/ECDHE.cpp
    src/ECC/StandardCurves.cpp
    src/ECC/ECCPrivateKey.cpp
    src/ECC/ECCPublicKey.cpp
    src/ECC/ECDSA.cpp
    src/Cryptography/Twofish.c
    src/ECC/ECElGamal.cpp
    src/ECC/ECIES.cpp
    src/ECC/ECIESCryptographySuits.cpp
    src/Cryptography/TwofishWrapper.cpp
    src/Cryptography/argon2/src/blake2/blake2b.c
    src/Cryptography/argon2/src/argon2.c
    src/Cryptography/argon2/src/core.c
    src/Cryptography/argon2/src/encoding.c
    src/Cryptography/argon2/src/opt.c
    src/Cryptography/argon2/src/thread.c
    src/Cryptography/HMAC.cpp
    )

add_executable(ECC_Framework ${SOURCES} ${HEADER_FILES})

target_link_libraries(ECC_Framework /usr/local/lib/libgivaro.a /usr/local/lib/libgmpxx.a  /usr/local/lib/libgmp.a /usr/local/lib64/libssl.a /usr/local/lib64/libcrypto.a)

