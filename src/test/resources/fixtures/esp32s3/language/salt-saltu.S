/* SPDX-License-Identifier: Apache-2.0 */
/* Independent operand combinations for ESP32-S3 SALT/SALTU decoding. */
    .section .text
    .global embedra_salt_saltu_fixture
embedra_salt_saltu_fixture:
    salt a2, a3, a4
    saltu a5, a6, a7
    salt a8, a8, a5
    saltu a8, a8, a9
    ret.n
