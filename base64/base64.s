#--------------------------------------------------------------------------------
# A 64-bit function for base64 encode on Linux
#
# Please do *not* use it on 32-bit platform or non-Linux platform.
# 
# Use it in C language as following:
#	void base64_encode(char *output, const char *input, int input_len);
#
# Please allocation memory for output
# 
# Compile:
#	as -o base64.o base64.s -gstabs 
#--------------------------------------------------------------------------------
.section .data
table64:
	.ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" 
str:
	.asciz "abcdefgh"
.section .bss
	.lcomm result, 20
.section .text
.type base64_encode, @function
.globl base64_encode
base64_encode:
	pushq %rbp
	movq %rsp, %rbp

	#movq 8(%rbp), %rdi
	#movq 16(%rbp), %rsi
	#movl 24(%rbp), %ecx

	#leaq str, %rsi
	#leaq result, %rdi
	#xorq %rcx, %rcx
	#movl $8, %ecx
	movl %edx, %ecx

	xor %rax, %rax
	#xor %rcx, %rcx
	cld
loop_b:
	#movl str(, %ecx, 3), %ebx
	#movb %ax, %bx

	lodsb
	cmpb $2, %dl
	je equal2
	cmpb $4, %dl
	je equal4
	movb %al, %ah
	andb $0xFC, %al
	sarb $2, %al
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	movl $2, %edx
	decl %ecx
	jz last
	jne loop_b
equal2:
	movb %al, %bl
	andw $0x3F0, %ax
	sarw $4, %ax
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	movb %bl, %ah
	movl $4, %edx
	decl %ecx
	jz last
	jne loop_b
equal4:
	movw %ax, %bx
	andw $0xFC0, %ax
	sarw $6, %ax
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	movw %bx, %ax
	andb $0x3F, %al
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	xorl %edx, %edx
	loop loop_b

last:
	cmpl $2, %edx
	je equal2_2
	cmpl $4, %edx
	je equal4_2
	jmp end
equal2_2:
	xorb %al, %al
	andw $0x3F0, %ax
	sarw $4, %ax
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	movb $'=', %al
	stosb
	stosb
	jmp end
equal4_2:
	xorb %al, %al
	andw $0xFC0, %ax
	sarw $6, %ax
	xorl %edx, %edx
	movb %al, %dl
	movb table64(, %edx, 1), %al
	stosb
	movb $'=', %al
	stosb
end:

	movq %rbp, %rsp
	popq %rbp
	ret
