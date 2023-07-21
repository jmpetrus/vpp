# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if(NOT OPENSSL_FOUND)
  return()
endif()

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.h
  COMMAND "make"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/epp
  COMMENT "Build EnclaveESP"
)

set(Urts_Library_Name "sgx_urts")
set(Uae_Service_Name "sgx_uae_service")
include_directories(/opt/intel/sgxsdk/include /opt/intel/sgxsdk/lib64 epp/Include ${OPENSSL_INCLUDE_DIR})
add_vpp_plugin(crypto_sgx
  SOURCES
  main.c
  Enclave_u.c

  INSTALL_HEADERS
  Enclave_u.h

  LINK_LIBRARIES
  ${OPENSSL_LIBRARIES}
  ${Urts_Library_Name}
  ${Uae_Service_Name}
)
