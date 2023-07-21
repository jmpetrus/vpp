# Copyright (c) 2019 KAIST.
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

##############################################################################
# vpp an external app that uses the SGX SDK
##############################################################################
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.h
  COMMAND "make"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/eke
  COMMENT "Build EnclaveIKE"
)

set(Urts_Library_Name "sgx_urts")
include_directories(/opt/intel/sgxsdk/include /opt/intel/sgxsdk/lib64 eke/Include)

add_vpp_plugin(ske
  SOURCES
  ske.c
  ske_api.c
  ske_cli.c
  ske_crypto.c
  ske_format.c
  ske_payload.c
  Enclave_u.c

  API_FILES
  ske.api

  API_TEST_SOURCES
  ske_test.c

  INSTALL_HEADERS
  ske.h
  ske_priv.h
  Enclave_u.h

  LINK_LIBRARIES
  ${Urts_Library_Name} 
)


