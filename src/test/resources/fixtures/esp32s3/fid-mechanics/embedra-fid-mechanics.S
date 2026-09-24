/*
 * SPDX-FileCopyrightText: 2026 Embedra contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Original Embedra test code for the T026A Function ID mechanics. The two
 * functions contain no ESP-IDF or runtime library code. Each body is a long
 * straight-line ALU sequence so its Function ID score comfortably exceeds
 * Ghidra's default instruction-count threshold. Distinct mnemonics keep the
 * full hashes different; the operand mix keeps specific hashes distinct.
 */

	.text
	.globl	embedra_fid_alpha
	.type	embedra_fid_alpha,@function
embedra_fid_alpha:
	add.n	a2, a2, a3
	add.n	a4, a4, a5
	add.n	a6, a6, a7
	add.n	a8, a8, a9
	add.n	a10, a10, a11
	add.n	a12, a12, a13
	add.n	a14, a14, a2
	add.n	a3, a3, a4
	add.n	a5, a5, a6
	add.n	a7, a7, a8
	add.n	a9, a9, a10
	add.n	a11, a11, a12
	add.n	a13, a13, a14
	add.n	a2, a2, a5
	add.n	a6, a6, a9
	add.n	a10, a10, a13
	add.n	a14, a14, a3
	add.n	a4, a4, a7
	add.n	a8, a8, a11
	add.n	a12, a12, a2
	add.n	a5, a5, a14
	add.n	a9, a9, a4
	add.n	a13, a13, a8
	add.n	a3, a3, a12
	add.n	a7, a7, a10
	add.n	a11, a11, a6
	add.n	a2, a2, a13
	add.n	a5, a5, a3
	add.n	a9, a9, a14
	add.n	a4, a4, a11
	ret.n
	.size	embedra_fid_alpha, .-embedra_fid_alpha

	.globl	embedra_fid_beta
	.type	embedra_fid_beta,@function
embedra_fid_beta:
	addi.n	a3, a2, 1
	addi.n	a4, a3, 2
	addi.n	a5, a4, 3
	addi.n	a6, a5, 4
	addi.n	a7, a6, 5
	addi.n	a8, a7, 6
	addi.n	a9, a8, 7
	addi.n	a10, a9, 8
	addi.n	a11, a10, 9
	addi.n	a12, a11, 10
	addi.n	a13, a12, 11
	addi.n	a14, a13, 12
	addi.n	a2, a14, 13
	addi.n	a3, a2, 14
	addi.n	a4, a3, 15
	addi.n	a5, a4, 1
	addi.n	a6, a5, 2
	addi.n	a7, a6, 3
	addi.n	a8, a7, 4
	addi.n	a9, a8, 5
	addi.n	a10, a9, 6
	addi.n	a11, a10, 7
	addi.n	a12, a11, 8
	addi.n	a13, a12, 9
	addi.n	a14, a13, 10
	addi.n	a2, a14, 11
	addi.n	a3, a2, 12
	addi.n	a4, a3, 13
	addi.n	a5, a4, 14
	addi.n	a6, a5, 15
	ret.n
	.size	embedra_fid_beta, .-embedra_fid_beta
	.ident	"Embedra ESP32-S3 Function ID mechanics fixture"
