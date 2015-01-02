; ---------------------------------------------------------------------------

_OSVERSIONINFOA	struc ;	(sizeof=0x94, standard type)
dwOSVersionInfoSize dd ?
dwMajorVersion	dd ?
dwMinorVersion	dd ?
dwBuildNumber	dd ?
dwPlatformId	dd ?
szCSDVersion	db 128 dup(?)
_OSVERSIONINFOA	ends

; ---------------------------------------------------------------------------

_STARTUPINFOA	struc ;	(sizeof=0x44, standard type)
cb		dd ?
lpReserved	dd ?			; offset
lpDesktop	dd ?			; offset
lpTitle		dd ?			; offset
dwX		dd ?
dwY		dd ?
dwXSize		dd ?
dwYSize		dd ?
dwXCountChars	dd ?
dwYCountChars	dd ?
dwFillAttribute	dd ?
dwFlags		dd ?
wShowWindow	dw ?
cbReserved2	dw ?
lpReserved2	dd ?			; offset
hStdInput	dd ?			; offset
hStdOutput	dd ?			; offset
hStdError	dd ?			; offset
_STARTUPINFOA	ends

; ---------------------------------------------------------------------------

_cpinfo		struc ;	(sizeof=0x14, standard type)
MaxCharSize	dd ?
DefaultChar	db 2 dup(?)
LeadByte	db 12 dup(?)
_padding	db 2 dup(?)
_cpinfo		ends

; ---------------------------------------------------------------------------

FILE		struc ;	(sizeof=0x18, standard type)
curp		dd ?			; offset
buffer		dd ?			; offset
level		dd ?
bsize		dd ?
istemp		dw ?
flags		dw ?
hold		dw ?
fd		db ?
token		db ?
FILE		ends

; ---------------------------------------------------------------------------

_RTL_CRITICAL_SECTION struc ; (sizeof=0x18, standard type)
DebugInfo	dd ?			; offset
LockCount	dd ?
RecursionCount	dd ?
OwningThread	dd ?			; offset
LockSemaphore	dd ?			; offset
SpinCount	dd ?
_RTL_CRITICAL_SECTION ends

; ---------------------------------------------------------------------------

_SECURITY_ATTRIBUTES struc ; (sizeof=0xC, standard type)
nLength		dd ?
lpSecurityDescriptor dd	?		; offset
bInheritHandle	dd ?
_SECURITY_ATTRIBUTES ends

; ---------------------------------------------------------------------------

_tpidc		struc ;	(sizeof=0x30, variable size)
tpDtt		dd ?			; base 16
tpMask		dw ?			; base 16
tpName		dw ?			; base 16
bParent		dd ?			; offset
tpcFlags	dd ?			; base 16
Size		dw ?			; base 16
ExpDim		dw ?			; base 16
mfnDel		dd ?			; offset
mfnMask		dw ?			; base 16
mfnMaskArr	dw ?			; base 16
mfnDelArr	dd ?			; offset
DtorCount	dd ?			; base 10
DtorAltCount	dd ?			; base 10
DtorAddr	dd ?			; offset
DtorMask	dw ?			; base 16
DtorMemberOff	dw ?			; base 16
Name		db 0 dup(?)		; string(C)
_tpidc		ends

; ---------------------------------------------------------------------------

_tpidp		struc ;	(sizeof=0xC, variable size)
tpDtt		dd ?			; base 16
tpMask		dw ?			; base 16
tpName		dw ?			; base 16
BaseType	dd ?			; offset
Name		db 0 dup(?)		; string(C)
_tpidp		ends

; ---------------------------------------------------------------------------

_excHdr		struc ;	(sizeof=0x8)
_unk		dd ?			; base 16
spoff		dd ?			; base 10
_excHdr		ends

; ---------------------------------------------------------------------------

_excInfo	struc ;	(sizeof=0xC)
RttiPtr		dd ?			; offset
Flags		dd ?			; base 16
spoff		dd ?			; base 10
_excInfo	ends

; ---------------------------------------------------------------------------

_excData	struc ;	(sizeof=0xC)
Flags		dd ?			; base 16
_unk		dd ?			; base 16
InfoPtr		dd ?			; offset
_excData	ends

; ---------------------------------------------------------------------------

_excInfo2	struc ;	(sizeof=0x20)
spoff		dd ?			; base 10
_unk		dd ?			; base 16
finEntry	dd ?			; offset
RttiInfo	dd ?			; offset
zArg		dd 4 dup(?)
_excInfo2	ends

; ---------------------------------------------------------------------------

_excData2	struc ;	(sizeof=0xC)
Flags		dd ?			; base 16
InitPtr		dd ?			; offset
Flags2		dd ?			; base 16
_excData2	ends

; ---------------------------------------------------------------------------

struct_0	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_0	ends

; ---------------------------------------------------------------------------

struct_1	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_1	ends

; ---------------------------------------------------------------------------

struct_2	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_2	ends

; ---------------------------------------------------------------------------

struct_3	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_3	ends

; ---------------------------------------------------------------------------

struct_4	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_4	ends

; ---------------------------------------------------------------------------

struct_5	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_5	ends

; ---------------------------------------------------------------------------

struct_6	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_6	ends

; ---------------------------------------------------------------------------

struct_7	struc ;	(sizeof=0xA)
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
		db ? ; undefined
anonymous_0	dd ?
anonymous_1	dw ?
struct_7	ends


;
; +-------------------------------------------------------------------------+
; |	This file is generated by The Interactive Disassembler (IDA)	    |
; |	Copyright (c) 2007 by DataRescue sa/nv,	<ida@datarescue.com>	    |
; |		       Licensed	to: Development	license			    |
; +-------------------------------------------------------------------------+
;
; Input	MD5   :	F1A8BA2D18B207D18975095276AC165A

; File Name   :	Z:\idasrc\current\bin\stm.exe
; Format      :	Portable executable for	80386 (PE)
; Imagebase   :	400000
; Section 1. (virtual address 00001000)
; Virtual size			: 0000C000 (  49152.)
; Section size in file		: 0000BC00 (  48128.)
; Offset to raw	data for section: 00000600
; Flags	60000020: Text Executable Readable
; Alignment	: default
; OS type	  :  MS	Windows
; Application type:  Executable	32bit


unicode		macro page,string,zero
		irpc c,<string>
		db '&c', page
		endm
		ifnb <zero>
		dw zero
		endif
endm

		.686p
		.mmx
		.model flat

; ===========================================================================

; Segment type:	Pure code
; Segment permissions: Read/Execute
_text		segment	para public 'CODE' use32
		assume cs:_text
		;org 401000h
		assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
byte_401000	db 2 dup(0)		; DATA XREF: .data:off_40D034o
		dd offset sub_402410
		dw 2000h
		dd offset sub_40241C
		db 0, 1
		dd offset __init_lock
		dw 2000h
		dd offset sub_403464
		db 0, 20h
		dd offset unknown_libname_3 ; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		dw 2000h
		dd offset sub_404097
		db 2 dup(0)
		dd offset loc_40473C
		align 4
		dd offset loc_4049CC
		db 0, 5
		dd offset __init_streams
		dw 400h
		dd offset __init_handles
		db 0, 0Ah
		dd offset __cvt_init
		dw 0A00h
		dd offset loc_408BBC
		db 0, 0Ah
		dd offset __cvt_initw
		dw 0A00h
		dd offset __scan_initw
		db 0, 1
		dd offset __initMBCSTable
		dw 100h
		dd offset unknown_libname_18 ; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		db 0, 3
		dd offset __setargv
		dw 200h
		dd offset unknown_libname_19 ; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		db 0, 3
		dd offset loc_40A488
		dw 600h
		dd offset loc_40A9BC
		db 0, 1
		dd offset __init_tls
		dw 100h
		dd offset loc_40AD6C
		db 2 dup(0)
		dd offset loc_40AEF0
		align 4
		dd offset loc_40AF08
byte_401090	db 0, 20h		; DATA XREF: .data:0040D038o
					; .data:0040D03Co
		dd offset sub_40245C
		align 4
		dd offset loc_402718
		db 0, 20h
		dd offset sub_4034D8
		dw 2000h
		dd offset sub_403728
		db 0, 1
		dd offset sub_403D3B
		dw 2000h
		dd offset sub_4040C2
		db 2 dup(0)
		dd offset loc_4049E4
		align 4
		dd offset __exit_streams
		db 0, 3
		dd offset __exitargv
		dw 200h
		dd offset loc_40A2D8
		db 0, 3
		dd offset loc_40A308
		dw 200h
		dd offset sub_40AD80
unk_4010D8	db    0			; DATA XREF: .data:0040D040o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
; [00000059 BYTES: COLLAPSED FUNCTION start. PRESS KEYPAD "+" TO EXPAND]
; Exported entry   1. __GetExceptDLLinfo
; [00000005 BYTES: COLLAPSED FUNCTION __GetExceptDLLinfo. PRESS	KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

__isDLL:
		xor	eax, eax
		mov	al, byte_40D07D
		retn
; ---------------------------------------------------------------------------

__getHInstance:
		mov	eax, dword_40D093
		retn

; =============== S U B	R O U T	I N E =======================================

; Attributes: noreturn

sub_40114C	proc near		; CODE XREF: .text:00401170p
					; .text:00401191p ...
		pusha
		mov	ebx, 0BCB05000h
		push	ebx
		push	0BADh
		retn
sub_40114C	endp

; ---------------------------------------------------------------------------

loc_401159:				; CODE XREF: .text:004011C6j
		mov	ecx, 0A4h
		or	ecx, ecx
		jz	short locret_4011AF
		cmp	TlsIndex, 0
		jnb	short loc_401175
		mov	eax, 0FEh
		call	sub_40114C
; ---------------------------------------------------------------------------

loc_401175:				; CODE XREF: .text:00401169j
		mov	ecx, 0A4h
		push	ecx
		push	8
		call	GetProcessHeap
		push	eax
		call	HeapAlloc
		or	eax, eax
		jnz	short loc_401196
		mov	eax, 0FDh
		call	sub_40114C
; ---------------------------------------------------------------------------

loc_401196:				; CODE XREF: .text:0040118Aj
		push	eax
		push	eax
		push	TlsIndex
		call	___CRTL_TLS_SetValue
		push	TlsIndex
		call	___CRTL_TLS_InitThread
		pop	edi

locret_4011AF:				; CODE XREF: .text:00401160j
		retn
; ---------------------------------------------------------------------------
		mov	ecx, 0A4h
		or	ecx, ecx
		jz	short locret_4011D2
		call	___CRTL_TLS_Alloc
		mov	TlsIndex, eax
		cmp	eax, 0
		jnb	short loc_401159
		mov	eax, 0FCh
		call	sub_40114C
; ---------------------------------------------------------------------------

locret_4011D2:				; CODE XREF: .text:004011B7j
		retn

; =============== S U B	R O U T	I N E =======================================


sub_4011D3	proc near		; CODE XREF: .text:0040120Fp
		cmp	TlsIndex, 0
		jb	short locret_401204
		push	TlsIndex	; dwTlsIndex
		call	___CRTL_TLS_GetValue
		or	eax, eax
		jz	short locret_401204
		push	eax		; lpMem
		push	8		; dwFlags
		call	GetProcessHeap
		push	eax		; hHeap
		call	HeapFree
		push	TlsIndex
		call	___CRTL_TLS_ExitThread

locret_401204:				; CODE XREF: sub_4011D3+7j
					; sub_4011D3+16j
		retn
sub_4011D3	endp

; ---------------------------------------------------------------------------
		retn
; ---------------------------------------------------------------------------
		cmp	TlsIndex, 0
		jb	short locret_40121F
		call	sub_4011D3
		push	TlsIndex
		call	___CRTL_TLS_Free

locret_40121F:				; CODE XREF: .text:0040120Dj
		retn
; [0000000F BYTES: COLLAPSED FUNCTION Sysinit::__linkproc__ GetTls(void). PRESS	KEYPAD "+" TO EXPAND]
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_401230(char *format, char arglist)
sub_401230	proc near		; CODE XREF: sub_401A04+29p
					; sub_401A04+11Ap ...

format		= dword	ptr  8
arglist		= byte ptr  0Ch

		push	ebp
		mov	ebp, esp
		lea	eax, [ebp+arglist]
		push	eax		; arglist
		push	[ebp+format]	; format
		push	dword_410A9C	; stream
		call	_vfprintf
		add	esp, 0Ch
		pop	ebp
		retn
sub_401230	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_40124C(char *format, char arglist)
sub_40124C	proc near		; CODE XREF: sub_401A04+42p
					; sub_401F5C+27p

format		= dword	ptr  8
arglist		= byte ptr  0Ch

		push	ebp
		mov	ebp, esp
		lea	eax, [ebp+arglist]
		push	eax		; arglist
		push	[ebp+format]	; format
		push	dword_410AA0	; stream
		call	_vfprintf
		add	esp, 0Ch
		pop	ebp
		retn
sub_40124C	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================


sub_401268	proc near		; CODE XREF: sub_401268+5j
					; sub_401274+Ep
		mov	dl, [eax]
		inc	eax
		test	dl, dl
		jnz	short sub_401268
		dec	eax
		retn
sub_401268	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_401274	proc near		; CODE XREF: _main+1A9p

var_4		= dword	ptr -4

		push	ebp
		mov	ebp, esp
		push	ecx
		push	ebx
		push	esi
		push	edi
		mov	[ebp+var_4], edx
		mov	esi, eax
		mov	eax, esi
		call	sub_401268
		mov	ebx, eax
		mov	edi, ebx
		cmp	esi, ebx
		ja	short loc_4012CF

loc_40128F:				; CODE XREF: sub_401274+59j
		movsx	eax, byte ptr [ebx]
		cmp	eax, 5Ch
		jz	short loc_4012CF
		movsx	edx, byte ptr [ebx]
		cmp	edx, 2Eh
		jnz	short loc_4012CA
		mov	eax, [ebp+var_4]
		inc	ebx
		mov	edi, eax
		xor	eax, eax
		push	esi
		or	ecx, 0FFFFFFFFh
		repne scasb
		not	ecx
		sub	edi, ecx
		mov	esi, ebx
		xchg	esi, edi
		mov	edx, ecx
		mov	eax, edi
		shr	ecx, 2
		rep movsd
		mov	ecx, edx
		and	ecx, 3
		rep movsb
		pop	esi
		mov	eax, esi
		jmp	short loc_4012FD
; ---------------------------------------------------------------------------

loc_4012CA:				; CODE XREF: sub_401274+29j
		dec	ebx
		cmp	esi, ebx
		jbe	short loc_40128F

loc_4012CF:				; CODE XREF: sub_401274+19j
					; sub_401274+21j
		mov	byte ptr [edi],	2Eh
		inc	edi
		mov	edx, [ebp+var_4]
		push	esi
		push	edi
		mov	esi, edi
		xor	eax, eax
		mov	edi, edx
		or	ecx, 0FFFFFFFFh
		repne scasb
		not	ecx
		sub	edi, ecx
		mov	edx, ecx
		xchg	esi, edi
		shr	ecx, 2
		mov	eax, edi
		rep movsd
		mov	ecx, edx
		and	ecx, 3
		rep movsb
		pop	edi
		pop	esi
		mov	eax, esi

loc_4012FD:				; CODE XREF: sub_401274+54j
		pop	edi
		pop	esi
		pop	ebx
		pop	ecx
		pop	ebp
		retn
sub_401274	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================


; int __fastcall sub_401304(size_t size)
sub_401304	proc near		; CODE XREF: sub_402010+5p
		push	ebx
		push	eax		; size
		call	_malloc
		pop	ecx
		mov	ebx, eax
		test	ebx, ebx
		jnz	short loc_40132C
		push	offset aNoMemory ; "\n\n\aNo memory !!!\n"
		push	offset stru_40EBC4 ; stream
		call	_fprintf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_40132C:				; CODE XREF: sub_401304+Cj
		mov	eax, ebx
		pop	ebx
		retn
sub_401304	endp


; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

; int __cdecl main(int argc, const char	**argv,	const char *envp)
_main		proc near		; DATA XREF: .data:0040D04Co

argc		= dword	ptr  8
argv		= dword	ptr  0Ch
envp		= dword	ptr  10h

		push	ebp
		mov	ebp, esp
		push	ebx
		push	esi
		push	edi
		mov	ebx, [ebp+argv]
		mov	esi, [ebp+argc]
		push	dword_40D0A8
		push	arglist
		push	offset format	; "Symbol Table	Maker v%d.%02d.	Copyright "...
		call	_printf
		add	esp, 0Ch
		cmp	esi, 3
		jle	loc_40142F

loc_40135E:				; CODE XREF: _main+F9j
		mov	eax, [ebx+4]
		movsx	edx, byte ptr [eax]
		cmp	edx, 2Dh
		jnz	loc_40142F
		mov	ecx, [ebx+4]
		movsx	eax, byte ptr [ecx+1]
		cmp	eax, 61h
		jg	short loc_40138F
		jz	short loc_4013D5
		sub	eax, 3Fh
		jz	short loc_4013EE
		sub	eax, 9
		jz	short loc_4013EE
		dec	eax
		jz	short loc_4013AD
		sub	eax, 7
		jz	short loc_4013BB
		jmp	short loc_401403
; ---------------------------------------------------------------------------

loc_40138F:				; CODE XREF: _main+47j
		sub	eax, 68h
		jz	short loc_4013EE
		dec	eax
		jz	short loc_4013A3
		sub	eax, 4
		jz	short loc_4013C7
		sub	eax, 6
		jz	short loc_4013E2
		jmp	short loc_401403
; ---------------------------------------------------------------------------

loc_4013A3:				; CODE XREF: _main+65j
		mov	dword_40D0CC, 1

loc_4013AD:				; CODE XREF: _main+56j
		mov	edx, [ebx+4]
		add	edx, 2
		mov	dword_40D0C8, edx
		jmp	short loc_401422
; ---------------------------------------------------------------------------

loc_4013BB:				; CODE XREF: _main+5Bj
		mov	off_40D0BC, offset aHpp	; "hpp"
		jmp	short loc_401422
; ---------------------------------------------------------------------------

loc_4013C7:				; CODE XREF: _main+6Aj
		mov	ecx, [ebx+4]
		add	ecx, 2
		mov	off_40D0C0, ecx
		jmp	short loc_401422
; ---------------------------------------------------------------------------

loc_4013D5:				; CODE XREF: _main+49j
		mov	eax, [ebx+4]
		add	eax, 2
		mov	off_40D0C4, eax
		jmp	short loc_401422
; ---------------------------------------------------------------------------

loc_4013E2:				; CODE XREF: _main+6Fj
		mov	dword_40D0D0, 1
		jmp	short loc_401422
; ---------------------------------------------------------------------------

loc_4013EE:				; CODE XREF: _main+4Ej	_main+53j ...
		push	offset aUsageStmIinclI ; "Usage: stm [-Iincl] [-iincl] [-P] [-aac"...
		call	_printf
		pop	ecx
		mov	eax, 1
		jmp	loc_40161A
; ---------------------------------------------------------------------------

loc_401403:				; CODE XREF: _main+5Dj	_main+71j
		mov	edx, [ebx+4]
		movsx	ecx, byte ptr [edx+1]
		push	ecx
		push	offset aBadSwitchC ; "Bad switch '%c'\n"
		call	_printf
		add	esp, 8
		mov	eax, 1
		jmp	loc_40161A
; ---------------------------------------------------------------------------

loc_401422:				; CODE XREF: _main+89j	_main+95j ...
		dec	esi
		add	ebx, 4
		cmp	esi, 3
		jg	loc_40135E

loc_40142F:				; CODE XREF: _main+28j	_main+37j
		cmp	esi, 3
		jnz	short loc_4013EE
		push	offset mode	; "r"
		push	dword ptr [ebx+4] ; path
		call	_fopen
		add	esp, 8
		mov	stream,	eax
		mov	edx, stream
		test	edx, edx
		jnz	short loc_40146B
		push	dword ptr [ebx+4]
		push	offset aCanTOpenInputF ; "Can't open input file %s\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_40146B:				; CODE XREF: _main+121j
		push	offset aW	; "w"
		push	dword ptr [ebx+8] ; path
		call	_fopen
		add	esp, 8
		mov	dword_410A9C, eax
		mov	ecx, dword_410A9C
		test	ecx, ecx
		jnz	short loc_4014A2
		push	dword ptr [ebx+8]
		push	offset aCanTOpenOutput ; "Can't open output file %s\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_4014A2:				; CODE XREF: _main+158j
		mov	eax, [ebx+8]
		mov	esi, offset unk_410AA4
		mov	edi, eax
		xor	eax, eax
		or	ecx, 0FFFFFFFFh
		repne scasb
		not	ecx
		sub	edi, ecx
		mov	edx, ecx
		xchg	esi, edi
		shr	ecx, 2
		mov	eax, edi
		rep movsd
		mov	ecx, edx
		mov	eax, offset unk_410AA4
		and	ecx, 3
		rep movsb
		push	offset aW	; "w"
		mov	edx, off_40D0BC
		call	sub_401274
		push	eax		; path
		call	_fopen
		add	esp, 8
		mov	dword_410AA0, eax
		mov	ecx, dword_410AA0
		test	ecx, ecx
		jnz	short loc_401510
		push	offset unk_410AA4
		push	offset aCanTOpenHeader ; "Can't open header file %s\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401510:				; CODE XREF: _main+1C4j
		push	0		; int
		mov	edx, offset aAny ; "any"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	1		; int
		mov	edx, offset aNext ; "next"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	2		; int
		mov	edx, offset aThis ; "this"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	3		; int
		mov	edx, offset aStart ; "start"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	0FFFFFFFFh	; int
		mov	edx, offset aError ; "error"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	5		; int
		mov	edx, offset aEnd ; "end"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		push	4		; int
		mov	edx, offset a0	; "0"
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 3		; int
		call	sub_402034
		call	sub_4016EC
		call	sub_401800
		push	stream		; stream
		call	_rewind
		pop	ecx
		xor	eax, eax
		mov	dword_40D0AC, eax

loc_4015C7:				; CODE XREF: _main+2A5j _main+2B1j ...
		call	sub_401620
		mov	edx, offset aEot ; "EOT"

loc_4015D1:				; CODE XREF: _main+2BBj
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_4015C7
		test	cl, cl
		jz	short loc_4015ED
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_4015C7
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_4015D1

loc_4015ED:				; CODE XREF: _main+2A9j
		jnz	short loc_4015C7
		call	sub_401A04
		push	stream		; stream
		call	_fclose
		pop	ecx
		push	dword_410A9C	; stream
		call	_fclose
		pop	ecx
		push	dword_410AA0	; stream
		call	_fclose
		pop	ecx
		xor	eax, eax

loc_40161A:				; CODE XREF: _main+CEj	_main+EDj
		pop	edi
		pop	esi
		pop	ebx
		pop	ebp
		retn
_main		endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================


sub_401620	proc near		; CODE XREF: _main:loc_4015C7p
					; sub_4016EC+14p ...
		push	ebx
		jmp	short loc_401656
; ---------------------------------------------------------------------------

loc_401623:				; CODE XREF: sub_401620+40j
		push	stream		; stream
		push	100h		; n
		push	offset byte_40D0E8 ; s
		call	_fgets
		add	esp, 0Ch
		test	eax, eax
		jnz	short loc_401646
		mov	eax, offset aL_eof ; "**l_eof**"
		pop	ebx
		retn
; ---------------------------------------------------------------------------

loc_401646:				; CODE XREF: sub_401620+1Dj
		inc	dword_40D0AC
		mov	s1, offset byte_40D0E8

loc_401656:				; CODE XREF: sub_401620+1j
					; sub_401620+67j ...
		mov	edx, s1
		mov	cl, [edx]
		test	cl, cl
		jz	short loc_401623
		jmp	short loc_40166A
; ---------------------------------------------------------------------------

loc_401664:				; CODE XREF: sub_401620+5Bj
		inc	s1

loc_40166A:				; CODE XREF: sub_401620+42j
		mov	eax, s1
		movsx	edx, byte ptr [eax]
		push	edx		; c
		call	_isspace
		pop	ecx
		test	eax, eax
		jnz	short loc_401664
		mov	ecx, s1
		mov	al, [ecx]
		test	al, al
		jz	short loc_401656
		mov	ebx, s1
		jmp	short loc_401697
; ---------------------------------------------------------------------------

loc_401691:				; CODE XREF: sub_401620+88j
		inc	s1

loc_401697:				; CODE XREF: sub_401620+6Fj
		mov	eax, s1
		movsx	edx, byte ptr [eax]
		push	edx		; c
		call	_isspace
		pop	ecx
		test	eax, eax
		jz	short loc_401691
		mov	ecx, s1
		mov	al, [ecx]
		test	al, al
		jz	short loc_4016C5
		mov	edx, s1
		mov	byte ptr [edx],	0
		inc	s1

loc_4016C5:				; CODE XREF: sub_401620+94j
		push	2		; maxlen
		push	offset s2	; "//"
		push	ebx		; s1
		call	_strncmp
		add	esp, 0Ch
		test	eax, eax
		jnz	short loc_4016E7
		mov	ecx, s1
		mov	byte ptr [ecx],	0
		jmp	loc_401656
; ---------------------------------------------------------------------------

loc_4016E7:				; CODE XREF: sub_401620+B7j
		mov	eax, ebx
		pop	ebx
		retn
sub_401620	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================


sub_4016EC	proc near		; CODE XREF: _main+27Ap
		push	ebx
		push	esi
		push	edi
		jmp	loc_4017B3
; ---------------------------------------------------------------------------

loc_4016F4:				; CODE XREF: sub_4016EC+D7j
					; sub_4016EC+E7j ...
		cmp	esi, offset aL_eof ; "**l_eof**"
		jz	loc_4017B3
		call	sub_401620
		movsx	edx, byte ptr [eax]
		cmp	edx, 27h
		jnz	short loc_40173D
		inc	eax
		movsx	ebx, byte ptr [eax]
		inc	eax
		movsx	edx, byte ptr [eax]
		cmp	edx, 27h
		jz	short loc_401722
		shl	ebx, 8
		movsx	ecx, byte ptr [eax]
		add	ebx, ecx

loc_401722:				; CODE XREF: sub_4016EC+2Cj
		inc	eax
		movsx	edx, byte ptr [eax]
		cmp	edx, 3Dh
		jnz	short loc_401730
		add	ebx, 3Dh
		jmp	short loc_401746
; ---------------------------------------------------------------------------

loc_401730:				; CODE XREF: sub_4016EC+3Dj
		movsx	eax, byte ptr [eax]
		cmp	eax, 2Eh
		jnz	short loc_401746
		add	ebx, 2Eh
		jmp	short loc_401746
; ---------------------------------------------------------------------------

loc_40173D:				; CODE XREF: sub_4016EC+1Fj
		push	eax		; s
		call	_atoi_0
		pop	ecx
		mov	ebx, eax

loc_401746:				; CODE XREF: sub_4016EC+42j
					; sub_4016EC+4Aj ...
		mov	eax, offset unk_40D0D4
		mov	ecx, ebx
		mov	edx, 1
		call	sub_402140
		mov	edi, eax
		test	eax, eax
		jz	short loc_40177C
		push	dword ptr [edi+8]
		push	esi
		push	dword_40D0AC
		push	offset aTermCodeErrorA ; "Term Code Error at line %d: %s and %s\n"
		call	_printf
		add	esp, 10h
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_40177C:				; CODE XREF: sub_4016EC+6Fj
		push	ebx		; int
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 1		; int
		mov	edx, esi	; s
		call	sub_402034
		mov	eax, dword_410AF4
		test	eax, eax
		jz	short loc_4017B3
		push	esi
		push	dword_40D0AC
		push	offset aTermRedeclarat ; "Term Redeclaration Error at line %d (%s"...
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_4017B3:				; CODE XREF: sub_4016EC+3j
					; sub_4016EC+Ej ...
		call	sub_401620
		mov	esi, eax
		mov	edx, offset aEot ; "EOT"

loc_4017BF:				; CODE XREF: sub_4016EC+F5j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	loc_4016F4
		test	cl, cl
		jz	short loc_4017E3
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	loc_4016F4
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_4017BF

loc_4017E3:				; CODE XREF: sub_4016EC+DFj
		jnz	loc_4016F4
		pop	edi
		pop	esi
		pop	ebx
		retn
sub_4016EC	endp

; ---------------------------------------------------------------------------
		align 10h
; [0000000E BYTES: COLLAPSED FUNCTION _atoi_0. PRESS KEYPAD "+"	TO EXPAND]
		align 10h

; =============== S U B	R O U T	I N E =======================================


sub_401800	proc near		; CODE XREF: _main+27Fp
		push	ebx
		push	esi
		push	edi

loc_401803:				; CODE XREF: sub_401800+E8j
		call	sub_401620
		mov	ebx, eax
		cmp	ebx, offset aL_eof ; "**l_eof**"
		jz	loc_4019FF
		mov	eax, ebx
		mov	edx, offset aSymbol ; "symbol"

loc_40181D:				; CODE XREF: sub_401800+37j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_401839
		test	cl, cl
		jz	short loc_401856
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_401839
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_40181D

loc_401839:				; CODE XREF: sub_401800+21j
					; sub_401800+2Dj
		jz	short loc_401856
		push	dword_40D0AC
		push	offset aSymbolErrorAtL ; "Symbol Error at line %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401856:				; CODE XREF: sub_401800+25j
					; sub_401800:loc_401839j
		call	sub_401620
		mov	ebx, eax
		push	dword_40D1EC	; int
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 2		; int
		mov	edx, ebx	; s
		call	sub_402034
		mov	edx, dword_40D1EC
		mov	dword_40D5F0[edx*4], eax
		inc	dword_40D1EC
		mov	eax, dword_410AF4
		test	eax, eax
		jz	short loc_4018AC
		push	ebx
		push	dword_40D0AC
		push	offset aMetaRedeclarat ; "Meta Redeclaration Error at line %d (%s"...
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_4018AC:				; CODE XREF: sub_401800+8Ej
		or	edi, 0FFFFFFFFh

loc_4018AF:				; CODE XREF: sub_401800+1A8j
					; sub_401800+1FAj
		inc	edi
		call	sub_401620
		mov	ebx, eax
		mov	edx, offset aEos ; "EOS"
		mov	eax, ebx

loc_4018BE:				; CODE XREF: sub_401800+D8j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_4018ED
		test	cl, cl
		jz	short loc_4018DA
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_4018ED
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_4018BE

loc_4018DA:				; CODE XREF: sub_401800+C6j
		jnz	short loc_4018ED
		mov	eax, dword_40D1EC
		mov	dword_40D1EC[eax*4], edi
		jmp	loc_401803
; ---------------------------------------------------------------------------

loc_4018ED:				; CODE XREF: sub_401800+C2j
					; sub_401800+CEj ...
		call	sub_401620
		mov	esi, eax
		jmp	short loc_40193B
; ---------------------------------------------------------------------------

loc_4018F6:				; CODE XREF: sub_401800+14Aj
					; sub_401800:loc_40195Ej
		push	edi		; int
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 5		; int
		mov	edx, ebx	; s
		call	sub_402034
		mov	eax, dword_410AF4
		test	eax, eax
		jz	short loc_40192D
		push	ebx
		push	dword_40D0AC
		push	offset aLabelRedeclara ; "Label	Redeclaration Error at line %d (%"...
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_40192D:				; CODE XREF: sub_401800+10Fj
		call	sub_401620
		mov	ebx, eax
		call	sub_401620
		mov	esi, eax

loc_40193B:				; CODE XREF: sub_401800+F4j
		mov	eax, esi
		mov	edx, offset asc_40DFDA ; ":"

loc_401942:				; CODE XREF: sub_401800+15Cj
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_40195E
		test	cl, cl
		jz	short loc_4018F6
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_40195E
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_401942

loc_40195E:				; CODE XREF: sub_401800+146j
					; sub_401800+152j
		jz	short loc_4018F6
		mov	eax, offset unk_40D0D4
		mov	edx, ebx
		call	sub_4020E0
		mov	esi, eax
		test	esi, esi
		jnz	short loc_40198E
		push	ebx
		push	dword_40D0AC
		push	offset aUndefinedTermA ; "Undefined term at line %d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_40198E:				; CODE XREF: sub_401800+170j
		call	sub_401620
		call	sub_401620
		mov	ebx, eax
		mov	eax, offset unk_40D0D4
		mov	edx, ebx
		call	sub_4020E0
		test	eax, eax
		jnz	loc_4018AF
		mov	ecx, [esi+0Ch]
		inc	ecx
		jnz	short loc_4019D0
		push	ebx
		push	dword_40D0AC
		push	offset aIllegalUseOfAc ; "Illegal use of action	at line	%d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_4019D0:				; CODE XREF: sub_401800+1B2j
		push	dword_40D9F0	; int
		mov	eax, offset unk_40D0D4 ; int
		mov	ecx, 4		; int
		mov	edx, ebx	; s
		call	sub_402034
		mov	edx, dword_40D9F0
		mov	dword_40D9F4[edx*4], eax
		inc	dword_40D9F0
		jmp	loc_4018AF
; ---------------------------------------------------------------------------

loc_4019FF:				; CODE XREF: sub_401800+10j
		pop	edi
		pop	esi
		pop	ebx
		retn
sub_401800	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_401A04	proc near		; CODE XREF: _main+2BFp

var_24		= dword	ptr -24h
var_20		= dword	ptr -20h
var_1C		= dword	ptr -1Ch
var_18		= dword	ptr -18h
var_14		= dword	ptr -14h
var_10		= dword	ptr -10h
var_C		= dword	ptr -0Ch
var_8		= dword	ptr -8
arglist		= byte ptr -4

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		xor	eax, eax
		xor	edx, edx
		xor	ecx, ecx
		push	ebx
		push	esi
		push	edi
		mov	[ebp+var_18], eax
		mov	[ebp+var_1C], edx
		mov	[ebp+var_20], ecx
		push	dword_40D0A8
		push	arglist		; arglist
		push	offset aThisFileIsGene ; "\n/*\tThis file is generated by Symbol Ta"...
		call	sub_401230
		add	esp, 0Ch
		push	dword_40D0A8
		push	arglist		; arglist
		push	offset aThisFileIsGe_0 ; "/*\n\tThis file is generated by Symbol Ta"...
		call	sub_40124C
		add	esp, 0Ch
		call	sub_401F5C

loc_401A53:				; CODE XREF: sub_401A04+18Aj
		call	sub_401620
		mov	ebx, eax
		cmp	ebx, offset aL_eof ; "**l_eof**"
		jnz	short loc_401A6C
		call	sub_401EE4
		jmp	loc_401EDC
; ---------------------------------------------------------------------------

loc_401A6C:				; CODE XREF: sub_401A04+5Cj
		mov	eax, ebx
		mov	edx, offset aSymbol ; "symbol"

loc_401A73:				; CODE XREF: sub_401A04+89j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_401A8F
		test	cl, cl
		jz	short loc_401AAC
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_401A8F
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_401A73

loc_401A8F:				; CODE XREF: sub_401A04+73j
					; sub_401A04+7Fj
		jz	short loc_401AAC
		push	dword_40D0AC
		push	offset aSymbolErrorAtL ; "Symbol Error at line %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401AAC:				; CODE XREF: sub_401A04+77j
					; sub_401A04:loc_401A8Fj
		call	sub_401620
		mov	ebx, eax
		mov	eax, offset unk_40D0D4
		mov	edx, ebx
		call	sub_4020E0
		mov	esi, eax
		test	esi, esi
		jnz	short loc_401AE1
		push	ebx
		push	dword_40D0AC
		push	offset aMetaNotFoundAt ; "Meta not found at line %d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401AE1:				; CODE XREF: sub_401A04+BFj
		mov	eax, [ebp+var_20]
		mov	edx, dword_40D1F0[eax*4]
		test	edx, edx
		jnz	short loc_401B07
		push	dword ptr [esi+8]
		push	offset aSymbolSIsEmpty ; "Symbol %s is empty !\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401B07:				; CODE XREF: sub_401A04+E9j
		mov	ecx, [ebp+var_20]
		push	dword_40D1F0[ecx*4]
		push	dword ptr [esi+8]
		push	offset aPsymbol_t ; "psymbol_t"
		push	offset aStaticConstSSD ; "static const %s %s[%d] =\n{\n"
		call	sub_401230
		add	esp, 10h
		inc	[ebp+var_20]
		mov	dword ptr [ebp+arglist], 0FFFFFFFFh

loc_401B30:				; CODE XREF: sub_401A04+4D3j
		inc	dword ptr [ebp+arglist]
		call	sub_401620
		mov	edi, eax
		mov	edx, offset aEos ; "EOS"
		mov	eax, edi

loc_401B41:				; CODE XREF: sub_401A04+157j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_401B93
		test	cl, cl
		jz	short loc_401B5D
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_401B93
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_401B41

loc_401B5D:				; CODE XREF: sub_401A04+145j
		jnz	short loc_401B93
		mov	eax, [ebp+var_1C]
		test	eax, eax
		jnz	short loc_401B83
		mov	edx, dword_40D0AC
		dec	edx
		push	edx
		push	offset aBadLastChoiceA ; "Bad last choice at line %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401B83:				; CODE XREF: sub_401A04+160j
		push	offset asc_40E1EF ; "\n};\n\n"
		call	sub_401230
		pop	ecx
		jmp	loc_401A53
; ---------------------------------------------------------------------------

loc_401B93:				; CODE XREF: sub_401A04+141j
					; sub_401A04+14Dj ...
		call	sub_401620
		mov	ebx, eax
		jmp	short loc_401BAA
; ---------------------------------------------------------------------------

loc_401B9C:				; CODE XREF: sub_401A04+1B5j
					; sub_401A04:loc_401BCDj
		call	sub_401620
		mov	edi, eax
		call	sub_401620
		mov	ebx, eax

loc_401BAA:				; CODE XREF: sub_401A04+196j
		mov	eax, ebx
		mov	edx, offset asc_40DFDA ; ":"

loc_401BB1:				; CODE XREF: sub_401A04+1C7j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_401BCD
		test	cl, cl
		jz	short loc_401B9C
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_401BCD
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_401BB1

loc_401BCD:				; CODE XREF: sub_401A04+1B1j
					; sub_401A04+1BDj
		jz	short loc_401B9C
		mov	eax, offset unk_40D0D4
		mov	edx, edi
		call	sub_4020E0
		mov	esi, eax
		mov	eax, offset unk_40D0D4
		mov	edx, ebx
		call	sub_4020E0
		mov	[ebp+var_8], eax
		call	sub_401620
		mov	edx, eax
		mov	eax, offset unk_40D0D4
		call	sub_4020E0
		mov	[ebp+var_C], eax
		test	esi, esi
		jnz	short loc_401C20
		push	edi
		push	dword_40D0AC
		push	offset aUndefinedTermA ; "Undefined term at line %d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401C20:				; CODE XREF: sub_401A04+1FEj
		mov	ecx, [esi+0Ch]
		mov	[ebp+var_10], ecx
		mov	eax, [esi+10h]
		cmp	eax, 3
		jnz	short loc_401C3D
		mov	edx, [esi+0Ch]
		test	edx, edx
		jz	short loc_401C67
		mov	ecx, [esi+0Ch]
		inc	ecx
		jnz	short loc_401C4B
		jmp	short loc_401C67
; ---------------------------------------------------------------------------

loc_401C3D:				; CODE XREF: sub_401A04+228j
		mov	eax, [esi+10h]
		dec	eax
		jnz	short loc_401C4B
		mov	edx, [esi+0Ch]
		mov	[ebp+var_10], edx
		jmp	short loc_401C67
; ---------------------------------------------------------------------------

loc_401C4B:				; CODE XREF: sub_401A04+235j
					; sub_401A04+23Dj
		push	edi
		push	dword_40D0AC
		push	offset aTermMismatchAt ; "Term mismatch	at line	%d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401C67:				; CODE XREF: sub_401A04+22Fj
					; sub_401A04+237j ...
		mov	ecx, [esi+0Ch]
		inc	ecx
		jz	short loc_401CDF
		mov	eax, [ebp+var_8]
		test	eax, eax
		jnz	short loc_401C90
		push	ebx
		push	dword_40D0AC
		push	offset aUndefinedMetaA ; "Undefined meta at line %d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401C90:				; CODE XREF: sub_401A04+26Ej
		mov	edx, [ebp+var_8]
		mov	ecx, [edx+0Ch]
		mov	[ebp+var_18], ecx
		mov	eax, [ebp+var_8]
		mov	edx, [eax+10h]
		cmp	edx, 3
		jnz	short loc_401CB8
		mov	ecx, [ebp+var_8]
		mov	eax, [ecx+0Ch]
		cmp	eax, 4
		jnz	short loc_401CB8
		mov	[ebp+var_18], 0FFFFFFFFh
		jmp	short loc_401CDF
; ---------------------------------------------------------------------------

loc_401CB8:				; CODE XREF: sub_401A04+29Ej
					; sub_401A04+2A9j
		mov	edx, [ebp+var_8]
		mov	ecx, [edx+10h]
		cmp	ecx, 2
		jz	short loc_401CDF
		push	ebx
		push	dword_40D0AC
		push	offset aMetaMismatchAt ; "Meta mismatch	at line	%d (%s)\n"
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401CDF:				; CODE XREF: sub_401A04+267j
					; sub_401A04+2B2j ...
		mov	eax, [ebp+var_C]
		test	eax, eax
		jnz	short loc_401D01
		push	dword_40D0AC
		push	offset aUndefinedNextL ; "Undefined next label at line %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401D01:				; CODE XREF: sub_401A04+2E0j
		mov	edx, [ebp+var_C]
		mov	ecx, [edx+10h]
		cmp	ecx, 3
		jz	short loc_401D35
		mov	eax, [ebp+var_C]
		mov	edx, [eax+10h]
		cmp	edx, 5
		jz	short loc_401D35
		push	[ebp+var_C]
		push	dword_40D0AC
		push	offset aNextLabelIsDef ; "Next label is	defined	as term	or meta	a"...
		call	_printf
		add	esp, 0Ch
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401D35:				; CODE XREF: sub_401A04+306j
					; sub_401A04+311j
		mov	ecx, [ebp+var_C]
		mov	eax, [ecx+10h]
		cmp	eax, 5
		jnz	short loc_401D4B
		mov	edx, [ebp+var_C]
		mov	ecx, [edx+0Ch]
		mov	[ebp+var_14], ecx
		jmp	short loc_401D9E
; ---------------------------------------------------------------------------

loc_401D4B:				; CODE XREF: sub_401A04+33Aj
		mov	eax, [ebp+var_C]
		mov	edx, [eax+0Ch]
		dec	edx
		jz	short loc_401D6B
		dec	edx
		jz	short loc_401D7B
		dec	edx
		jz	short loc_401D74
		dec	edx
		sub	edx, 2
		jb	short loc_401D62
		jmp	short loc_401D83
; ---------------------------------------------------------------------------

loc_401D62:				; CODE XREF: sub_401A04+35Aj
		mov	[ebp+var_14], 0FFFFFFFFh
		jmp	short loc_401D9E
; ---------------------------------------------------------------------------

loc_401D6B:				; CODE XREF: sub_401A04+34Ej
		mov	ecx, dword ptr [ebp+arglist]
		inc	ecx
		mov	[ebp+var_14], ecx
		jmp	short loc_401D9E
; ---------------------------------------------------------------------------

loc_401D74:				; CODE XREF: sub_401A04+354j
		xor	eax, eax
		mov	[ebp+var_14], eax
		jmp	short loc_401D9E
; ---------------------------------------------------------------------------

loc_401D7B:				; CODE XREF: sub_401A04+351j
		mov	edx, dword ptr [ebp+arglist]
		mov	[ebp+var_14], edx
		jmp	short loc_401D9E
; ---------------------------------------------------------------------------

loc_401D83:				; CODE XREF: sub_401A04+35Cj
		mov	ecx, [ebp+var_C]
		push	dword ptr [ecx+0Ch]
		push	offset aUnknownSystemL ; "Unknown system label type %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401D9E:				; CODE XREF: sub_401A04+345j
					; sub_401A04+365j ...
		call	sub_401620
		mov	edx, eax
		mov	eax, offset unk_40D0D4
		call	sub_4020E0
		mov	edi, eax
		mov	eax, [edi+0Ch]
		mov	[ebp+var_24], eax
		mov	edx, [edi+10h]
		cmp	edx, 4
		jz	short loc_401DF1
		mov	ecx, [edi+0Ch]
		cmp	ecx, 4
		jnz	short loc_401DCF
		mov	eax, [edi+10h]
		cmp	eax, 3
		jz	short loc_401DEA

loc_401DCF:				; CODE XREF: sub_401A04+3C1j
		push	dword_40D0AC
		push	offset aTypeMismatchOf ; "Type mismatch	of Action at line %d\n"
		call	_printf
		add	esp, 8
		push	1		; status
		call	_exit
; ---------------------------------------------------------------------------
		pop	ecx

loc_401DEA:				; CODE XREF: sub_401A04+3C9j
		mov	[ebp+var_24], 0FFFFFFFFh

loc_401DF1:				; CODE XREF: sub_401A04+3B9j
		mov	edx, [esi+0Ch]
		inc	edx
		jz	short loc_401E0C
		mov	ecx, [esi+0Ch]
		test	ecx, ecx
		jnz	short loc_401E08
		mov	eax, [ebp+var_14]
		mov	edx, dword ptr [ebp+arglist]
		cmp	eax, edx
		jle	short loc_401E0C

loc_401E08:				; CODE XREF: sub_401A04+3F8j
		xor	ecx, ecx
		jmp	short loc_401E11
; ---------------------------------------------------------------------------

loc_401E0C:				; CODE XREF: sub_401A04+3F1j
					; sub_401A04+402j
		mov	ecx, 1

loc_401E11:				; CODE XREF: sub_401A04+406j
		mov	[ebp+var_1C], ecx
		mov	eax, dword ptr [ebp+arglist]
		test	eax, eax
		jz	short loc_401E26
		push	offset asc_40E2ED ; ",\n"
		call	sub_401230
		pop	ecx

loc_401E26:				; CODE XREF: sub_401A04+415j
		push	[ebp+var_10]
		mov	edx, [ebp+var_10]
		test	edx, edx
		jg	short loc_401E37
		mov	edx, 3
		jmp	short loc_401E3C
; ---------------------------------------------------------------------------

loc_401E37:				; CODE XREF: sub_401A04+42Aj
		mov	edx, 1

loc_401E3C:				; CODE XREF: sub_401A04+431j
		mov	eax, offset unk_40D0D4
		mov	ecx, [ebp+var_10]
		call	sub_402140
		push	dword ptr [eax+8]
		push	dword ptr [ebp+arglist]	; arglist
		push	offset a2d8sD	; "/* %2d %-8s*/ { %d,\t"
		call	sub_401230
		add	esp, 10h
		mov	eax, [esi+0Ch]
		inc	eax
		jz	short loc_401E74
		push	[ebp+var_18]	; arglist
		push	offset aD	; "%d"
		call	sub_401230
		add	esp, 8
		jmp	short loc_401E82
; ---------------------------------------------------------------------------

loc_401E74:				; CODE XREF: sub_401A04+45Cj
		push	ebx		; arglist
		push	offset aS	; "%s"
		call	sub_401230
		add	esp, 8

loc_401E82:				; CODE XREF: sub_401A04+46Ej
		mov	edx, [edi+8]
		test	edx, edx
		jz	short loc_401E8E
		mov	ecx, [edi+8]
		jmp	short loc_401E93
; ---------------------------------------------------------------------------

loc_401E8E:				; CODE XREF: sub_401A04+483j
		mov	ecx, offset unk_40DDF5

loc_401E93:				; CODE XREF: sub_401A04+488j
		push	ecx
		mov	eax, [esi+0Ch]
		inc	eax
		jnz	short loc_401EA1
		mov	edx, offset aError ; "error"
		jmp	short loc_401EA7
; ---------------------------------------------------------------------------

loc_401EA1:				; CODE XREF: sub_401A04+494j
		mov	eax, [ebp+var_8]
		mov	edx, [eax+8]

loc_401EA7:				; CODE XREF: sub_401A04+49Bj
		push	edx
		mov	ecx, [ebp+var_24]
		inc	ecx
		jnz	short loc_401EB5
		mov	eax, 0FFh
		jmp	short loc_401EB8
; ---------------------------------------------------------------------------

loc_401EB5:				; CODE XREF: sub_401A04+4A8j
		mov	eax, [ebp+var_24]

loc_401EB8:				; CODE XREF: sub_401A04+4AFj
		push	eax
		mov	edx, [ebp+var_14]
		inc	edx
		jnz	short loc_401EC6
		mov	ecx, 0FFh
		jmp	short loc_401EC9
; ---------------------------------------------------------------------------

loc_401EC6:				; CODE XREF: sub_401A04+4B9j
		mov	ecx, [ebp+var_14]

loc_401EC9:				; CODE XREF: sub_401A04+4C0j
		push	ecx		; arglist
		push	offset aDDSS	; ",\t%d,\t%d,\t} /* %s,%s */"
		call	sub_401230
		add	esp, 14h
		jmp	loc_401B30
; ---------------------------------------------------------------------------

loc_401EDC:				; CODE XREF: sub_401A04+63j
		pop	edi
		pop	esi
		pop	ebx
		mov	esp, ebp
		pop	ebp
		retn
sub_401A04	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================


sub_401EE4	proc near		; CODE XREF: sub_401A04+5Ep
		push	ebx
		push	dword_40D1EC
		push	off_40D0C0
		push	offset aPsymbol_t ; "psymbol_t"
		mov	eax, dword_40D0D0
		test	eax, eax
		jz	short loc_401F06
		mov	edx, offset aStatic ; "static "
		jmp	short loc_401F0B
; ---------------------------------------------------------------------------

loc_401F06:				; CODE XREF: sub_401EE4+19j
		mov	edx, offset unk_40DDF5

loc_401F0B:				; CODE XREF: sub_401EE4+20j
		push	edx		; arglist
		push	offset aSconstSConstSD ; "%sconst %s *const %s[	%d ] = {\n"
		call	sub_401230
		add	esp, 14h
		xor	ebx, ebx
		jmp	short loc_401F45
; ---------------------------------------------------------------------------

loc_401F1D:				; CODE XREF: sub_401EE4+69j
		test	ebx, ebx
		jz	short loc_401F2C
		push	offset asc_40E2ED ; ",\n"
		call	sub_401230
		pop	ecx

loc_401F2C:				; CODE XREF: sub_401EE4+3Bj
		mov	eax, dword_40D5F0[ebx*4]
		push	dword ptr [eax+8]
		push	ebx		; arglist
		push	offset a2dS	; "/* %2d */ %s"
		call	sub_401230
		add	esp, 0Ch
		inc	ebx

loc_401F45:				; CODE XREF: sub_401EE4+37j
		mov	edx, dword_40D1EC
		cmp	ebx, edx
		jl	short loc_401F1D
		push	offset asc_40E358 ; "\n};\n"
		call	sub_401230
		pop	ecx
		pop	ebx
		retn
sub_401EE4	endp


; =============== S U B	R O U T	I N E =======================================


sub_401F5C	proc near		; CODE XREF: sub_401A04+4Ap
		push	ebx
		mov	eax, dword_40D9F0
		test	eax, eax
		jz	loc_40200C
		xor	ebx, ebx
		jmp	short loc_401F8C
; ---------------------------------------------------------------------------

loc_401F6E:				; CODE XREF: sub_401F5C+38j
		mov	eax, dword_40D9F4[ebx*4]
		push	dword ptr [eax+8]
		push	offset aError_t	; "error_t"
		push	ebx		; arglist
		push	offset a2dSIdaapiSVoid ; "/* %2d */ %s idaapi %s(void);\n"
		call	sub_40124C
		add	esp, 10h
		inc	ebx

loc_401F8C:				; CODE XREF: sub_401F5C+10j
		mov	edx, dword_40D9F0
		cmp	ebx, edx
		jl	short loc_401F6E
		push	dword_40D9F0
		push	off_40D0C4
		push	offset aAction_t ; "action_t"
		mov	ecx, dword_40D0D0
		test	ecx, ecx
		jz	short loc_401FB8
		mov	eax, offset aStatic ; "static "
		jmp	short loc_401FBD
; ---------------------------------------------------------------------------

loc_401FB8:				; CODE XREF: sub_401F5C+53j
		mov	eax, offset unk_40DDF5

loc_401FBD:				; CODE XREF: sub_401F5C+5Aj
		push	eax		; arglist
		push	offset aSconstSSD ; "\n%sconst %s %s[%d] =\n{\n"
		call	sub_401230
		add	esp, 14h
		xor	ebx, ebx
		jmp	short loc_401FF7
; ---------------------------------------------------------------------------

loc_401FCF:				; CODE XREF: sub_401F5C+A3j
		test	ebx, ebx
		jz	short loc_401FDE
		push	offset asc_40E2ED ; ",\n"
		call	sub_401230
		pop	ecx

loc_401FDE:				; CODE XREF: sub_401F5C+75j
		mov	eax, dword_40D9F4[ebx*4]
		push	dword ptr [eax+8]
		push	ebx		; arglist
		push	offset a2dParser_tS ; "/* %2d */ &parser_t::%s"
		call	sub_401230
		add	esp, 0Ch
		inc	ebx

loc_401FF7:				; CODE XREF: sub_401F5C+71j
		mov	edx, dword_40D9F0
		cmp	ebx, edx
		jl	short loc_401FCF
		push	offset asc_40E1EF ; "\n};\n\n"
		call	sub_401230
		pop	ecx

loc_40200C:				; CODE XREF: sub_401F5C+8j
		pop	ebx
		retn
sub_401F5C	endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================


sub_402010	proc near		; CODE XREF: sub_402034:loc_40208Ep
					; sub_402034:loc_4020A5p
		mov	eax, 14h	; size
		call	sub_401304
		xor	edx, edx
		xor	ecx, ecx
		mov	[eax], edx
		mov	[eax+4], ecx
		xor	edx, edx
		xor	ecx, ecx
		mov	[eax+8], edx
		xor	edx, edx
		mov	[eax+0Ch], ecx
		mov	[eax+10h], edx
		retn
sub_402010	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

; int __fastcall sub_402034(int, char *s, int, int)
sub_402034	proc near		; CODE XREF: _main+1F1p _main+207p ...

var_4		= dword	ptr -4
arg_0		= dword	ptr  8

		push	ebp
		mov	ebp, esp
		push	ecx
		push	ebx
		push	esi
		push	edi
		mov	[ebp+var_4], ecx
		mov	edi, edx
		mov	ebx, eax
		mov	dword_410AF4, 1

loc_40204C:				; CODE XREF: sub_402034+58j
					; sub_402034+6Fj
		mov	eax, edi
		mov	edx, [ebx+8]

loc_402051:				; CODE XREF: sub_402034+37j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_40206D
		test	cl, cl
		jz	short loc_40206D
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_40206D
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_402051

loc_40206D:				; CODE XREF: sub_402034+21j
					; sub_402034+25j ...
		setnz	dl
		sbb	eax, eax
		or	al, dl
		mov	esi, eax
		test	eax, eax
		jnz	short loc_40207E
		mov	eax, ebx
		jmp	short loc_4020D6
; ---------------------------------------------------------------------------

loc_40207E:				; CODE XREF: sub_402034+44j
		test	esi, esi
		jle	short loc_40209B
		mov	edx, [ebx+4]
		test	edx, edx
		jz	short loc_40208E
		mov	ebx, [ebx+4]
		jmp	short loc_40204C
; ---------------------------------------------------------------------------

loc_40208E:				; CODE XREF: sub_402034+53j
		call	sub_402010
		mov	[ebx+4], eax
		mov	ebx, [ebx+4]
		jmp	short loc_4020AE
; ---------------------------------------------------------------------------

loc_40209B:				; CODE XREF: sub_402034+4Cj
		mov	ecx, [ebx]
		test	ecx, ecx
		jz	short loc_4020A5
		mov	ebx, [ebx]
		jmp	short loc_40204C
; ---------------------------------------------------------------------------

loc_4020A5:				; CODE XREF: sub_402034+6Bj
		call	sub_402010
		mov	[ebx], eax
		mov	ebx, [ebx]

loc_4020AE:				; CODE XREF: sub_402034+65j
		xor	eax, eax
		mov	edx, [ebp+arg_0]
		mov	dword_410AF4, eax
		mov	[ebx+0Ch], edx
		mov	ecx, [ebp+var_4]
		xor	eax, eax
		mov	[ebx+10h], ecx
		mov	[ebx+4], eax
		xor	edx, edx
		mov	[ebx], edx
		push	edi		; s
		call	_strdup
		pop	ecx
		mov	[ebx+8], eax
		mov	eax, ebx

loc_4020D6:				; CODE XREF: sub_402034+48j
		pop	edi
		pop	esi
		pop	ebx
		pop	ecx
		pop	ebp
		retn	4
sub_402034	endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================


sub_4020E0	proc near		; CODE XREF: sub_401800+167p
					; sub_401800+1A1p ...
		push	ebx
		push	esi
		push	edi
		mov	edi, edx
		mov	ebx, eax

loc_4020E7:				; CODE XREF: sub_4020E0+47j
					; sub_4020E0+55j
		mov	eax, edi
		mov	edx, [ebx+8]

loc_4020EC:				; CODE XREF: sub_4020E0+26j
		mov	cl, [eax]
		cmp	cl, [edx]
		jnz	short loc_402108
		test	cl, cl
		jz	short loc_402108
		mov	cl, [eax+1]
		cmp	cl, [edx+1]
		jnz	short loc_402108
		add	eax, 2
		add	edx, 2
		test	cl, cl
		jnz	short loc_4020EC

loc_402108:				; CODE XREF: sub_4020E0+10j
					; sub_4020E0+14j ...
		setnz	dl
		sbb	eax, eax
		or	al, dl
		mov	esi, eax
		test	eax, eax
		jnz	short loc_402119
		mov	eax, ebx
		jmp	short loc_402139
; ---------------------------------------------------------------------------

loc_402119:				; CODE XREF: sub_4020E0+33j
		test	esi, esi
		jle	short loc_40212D
		mov	edx, [ebx+4]
		test	edx, edx
		jz	short loc_402129
		mov	ebx, [ebx+4]
		jmp	short loc_4020E7
; ---------------------------------------------------------------------------

loc_402129:				; CODE XREF: sub_4020E0+42j
		xor	eax, eax
		jmp	short loc_402139
; ---------------------------------------------------------------------------

loc_40212D:				; CODE XREF: sub_4020E0+3Bj
		mov	edx, [ebx]
		test	edx, edx
		jz	short loc_402137
		mov	ebx, [ebx]
		jmp	short loc_4020E7
; ---------------------------------------------------------------------------

loc_402137:				; CODE XREF: sub_4020E0+51j
		xor	eax, eax

loc_402139:				; CODE XREF: sub_4020E0+37j
					; sub_4020E0+4Bj
		pop	edi
		pop	esi
		pop	ebx
		retn
sub_4020E0	endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_402140	proc near		; CODE XREF: sub_4016EC+66p
					; sub_401A04+440p ...

var_4		= dword	ptr -4

		push	ebp
		mov	ebp, esp
		push	ecx
		push	ebx
		mov	ebx, eax
		push	esi
		push	edi
		mov	[ebp+var_4], ecx
		mov	eax, [ebx+10h]
		mov	edi, edx
		cmp	edi, eax
		jnz	short loc_402163
		mov	edx, [ebp+var_4]
		mov	ecx, [ebx+0Ch]
		cmp	edx, ecx
		jnz	short loc_402163
		mov	eax, ebx
		jmp	short loc_40219F
; ---------------------------------------------------------------------------

loc_402163:				; CODE XREF: sub_402140+13j
					; sub_402140+1Dj
		mov	edx, [ebx]
		test	edx, edx
		jz	short loc_40217F
		mov	ecx, [ebp+var_4]
		mov	edx, edi
		mov	eax, [ebx]
		call	sub_402140
		mov	esi, eax
		test	eax, eax
		jz	short loc_40217F
		mov	eax, esi
		jmp	short loc_40219F
; ---------------------------------------------------------------------------

loc_40217F:				; CODE XREF: sub_402140+27j
					; sub_402140+39j
		mov	edx, [ebx+4]
		test	edx, edx
		jz	short loc_40219D
		mov	ecx, [ebp+var_4]
		mov	edx, edi
		mov	eax, [ebx+4]
		call	sub_402140
		mov	esi, eax
		test	eax, eax
		jz	short loc_40219D
		mov	eax, esi
		jmp	short loc_40219F
; ---------------------------------------------------------------------------

loc_40219D:				; CODE XREF: sub_402140+44j
					; sub_402140+57j
		xor	eax, eax

loc_40219F:				; CODE XREF: sub_402140+21j
					; sub_402140+3Dj ...
		pop	edi
		pop	esi
		pop	ebx
		pop	ecx
		pop	ebp
		retn
sub_402140	endp

; ---------------------------------------------------------------------------
		align 4
; [0000002B BYTES: COLLAPSED FUNCTION _calloc. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION __rtl_close. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION __close. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION std::set_new_handler(void	(*)(void)). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000090 BYTES: COLLAPSED FUNCTION operator new(uint). PRESS	KEYPAD "+" TO EXPAND]
; `__tpdsc__'[std::bad_alloc]
@$xt$13std@bad_alloc dd	4		     ; tpDtt ; DATA XREF: operator new(uint)+63o
					; .text:`__tpdsc__'[std::bad_alloc *]o ...
		dw 3			; tpMask ; BCC v4.x/5.x	& BCB v1.0/v7.0	BDS2006	win32 runtime
		dw 30h			; tpName
		dd 0			; bParent
		dd 77h			; tpcFlags
		dw 40h			; Size
		dw 50h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 2			; DtorCount
		dd 2			; DtorAltCount
		dd offset unknown_libname_5; DtorAddr
		dw 1			; DtorMask
		dw 54h			; DtorMemberOff
		db 'std::bad_alloc',0   ; Name
		align 4
		dd offset @$xt$13std@exception ; Parent
		dd 0, 3, 0
		dd 0
		dd 0			; end of tpid
; [0000003E BYTES: COLLAPSED FUNCTION std::bad_alloc::bad_alloc(std::bad_alloc &). PRESS KEYPAD	"+" TO EXPAND]
		align 10h
; `__tpdsc__'[std::bad_alloc *]
@$xt$p13std@bad_alloc dd 4		      ;	tpDtt ;	DATA XREF: .data:stru_40E3E4o
					; .data:off_40E454o ...
		dw 90h			; tpMask ; `__tpdsc__'[std::bad_alloc]
		dw 0Ch			; tpName
		dd offset @$xt$13std@bad_alloc;	BaseType
		db 'bad_alloc *',0      ; Name
; `__tpdsc__'[std::exception]
@$xt$13std@exception dd	4		     ; tpDtt ; DATA XREF: .text:004022D8o
					; .text:00403580o ...
		dw 3			; tpMask ; BCC v4.x/5.x	& BCB v1.0/v7.0	BDS2006	win32 runtime
		dw 30h			; tpName
		dd 0			; bParent
		dd 73h			; tpcFlags
		dw 40h			; Size
		dw 44h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 1			; DtorCount
		dd 1			; DtorAltCount
		dd offset unknown_libname_4; DtorAddr
		dw 1			; DtorMask
		dw 48h			; DtorMemberOff
		db 'std::exception',0   ; Name
		align 4
		dd 0
		dd 0
		dd 0			; end of tpid

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_402394	proc near		; DATA XREF: .data:0040E418o
					; .data:0040E624o ...
		push	ebp
		mov	ebp, esp
		mov	eax, off_40E63C
		pop	ebp
		retn
sub_402394	endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_4023A0	proc near		; DATA XREF: .data:0040E42Co
		push	ebp
		mov	ebp, esp
		mov	eax, off_40E644
		pop	ebp
		retn
sub_4023A0	endp

; ---------------------------------------------------------------------------
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION operator new[](uint). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000054 BYTES: COLLAPSED FUNCTION unknown_libname_1. PRESS KEYPAD "+" TO EXPAND]

; =============== S U B	R O U T	I N E =======================================


sub_402410	proc near		; DATA XREF: .text:00401002o
		push	offset unknown_libname_1 ; BCC v4.x/5.x	& BCB v1.0/v7.0	BDS2006	win32 runtime
		call	@std@set_new_handler$qpqv$v ; std::set_new_handler(void	(*)(void))
		pop	ecx
		retn
sub_402410	endp


; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_40241C	proc near		; DATA XREF: .text:00401008o

var_24		= dword	ptr -24h
var_14		= word ptr -14h
var_8		= dword	ptr -8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		mov	eax, offset stru_40E488
		call	@__InitExceptBlockLDTC
		mov	[ebp+var_14], 8
		inc	[ebp+var_8]
		inc	[ebp+var_8]
		mov	edx, offset off_40E414
		mov	dword_410AFC, edx
		mov	ecx, offset off_40E428
		mov	dword_410AFC, ecx
		mov	eax, [ebp+var_24]
		mov	large fs:0, eax
		mov	esp, ebp
		pop	ebp
		retn
sub_40241C	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_40245C	proc near		; DATA XREF: .text:00401092o

var_24		= dword	ptr -24h
var_8		= dword	ptr -8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		mov	eax, offset stru_40E49C
		call	@__InitExceptBlockLDTC
		sub	[ebp+var_8], 2
		push	2		; char
		push	offset dword_410AFC ; handle
		call	unknown_libname_5 ; BCC	v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		add	esp, 8
		mov	edx, [ebp+var_24]
		mov	large fs:0, edx
		mov	esp, ebp
		pop	ebp
		retn
sub_40245C	endp

; ---------------------------------------------------------------------------
		align 10h
; [0000006A BYTES: COLLAPSED FUNCTION @_virt_reserve. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000027 BYTES: COLLAPSED FUNCTION @_virt_alloc. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [0000004B BYTES: COLLAPSED FUNCTION @_virt_commit. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000018 BYTES: COLLAPSED FUNCTION @_virt_decommit. PRESS KEYPAD "+"	TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION @_virt_release. PRESS KEYPAD "+" TO EXPAND]
		align 4
		push	offset aBorlndmm ; "borlndmm"
		call	LoadLibraryA
		cmp	eax, dword_410B14
		jz	short locret_4025C1
		push	offset aHrdir_b_cLoadl ; "hrdir_b.c: LoadLibrary != mmdll borlndm"...
		call	__ErrorExit
; ---------------------------------------------------------------------------
		db  59h	; Y
; ---------------------------------------------------------------------------

locret_4025C1:				; CODE XREF: .text:004025B4j
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000007C BYTES: COLLAPSED FUNCTION ___CRTL_MEM_GetBorMemPtrs. PRESS KEYPAD "+" TO EXPAND]
; [00000003 BYTES: COLLAPSED FUNCTION ___CRTL_MEM_CheckBorMem. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000010 BYTES: COLLAPSED FUNCTION _malloc. PRESS KEYPAD "+"	TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION _free. PRESS KEYPAD "+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION _realloc.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000048 BYTES: COLLAPSED FUNCTION ___CRTL_MEM_Revector. PRESS KEYPAD "+" TO	EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION sub_4026C4. PRESS	KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION sub_4026DC. PRESS	KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION sub_4026F4. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_5. PRESS KEYPAD "+" TO EXPAND]
		align 4

loc_402718:				; DATA XREF: .text:00401098o
		mov	dword_40E540, 1
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000010 BYTES: COLLAPSED FUNCTION __free_heaps. PRESS KEYPAD "+" TO	EXPAND]
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_1. PRESS KEYPAD "+" TO EXPAND]
		align 4

__init_lock:				; DATA XREF: .text:0040100Eo
		push	offset aCreatingHeapLo ; "creating heap	lock"
		push	offset lpCriticalSection
		call	__create_lock
		add	esp, 8
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __lock_heap. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __unlock_heap. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000040 BYTES: COLLAPSED FUNCTION sub_40276C. PRESS	KEYPAD "+" TO EXPAND]
; [000000FF BYTES: COLLAPSED FUNCTION sub_4027AC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000000EB BYTES: COLLAPSED FUNCTION sub_4028AC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000002C2 BYTES: COLLAPSED FUNCTION sub_402998. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000000F1 BYTES: COLLAPSED FUNCTION sub_402C5C. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [0000002B BYTES: COLLAPSED FUNCTION __internal_free. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000111 BYTES: COLLAPSED FUNCTION sub_402D7C. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [0000003B BYTES: COLLAPSED FUNCTION sub_402E90. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000027 BYTES: COLLAPSED FUNCTION __internal_malloc. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [000001FA BYTES: COLLAPSED FUNCTION sub_402EF4. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000018 BYTES: COLLAPSED FUNCTION __phys_avail. PRESS KEYPAD "+" TO	EXPAND]
; [00000060 BYTES: COLLAPSED FUNCTION __internal_free_heaps. PRESS KEYPAD "+" TO EXPAND]
; [0000013C BYTES: COLLAPSED FUNCTION __expand.	PRESS KEYPAD "+" TO EXPAND]
; [000000C9 BYTES: COLLAPSED FUNCTION sub_4032A4. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [000000A0 BYTES: COLLAPSED FUNCTION __internal_realloc. PRESS	KEYPAD "+" TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION __msize. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_2. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_3. PRESS KEYPAD "+" TO EXPAND]
		align 4

unknown_libname_2:			; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		push	offset @$xt$14std@bad_typeid
		push	0
		push	1
		call	@__GetTypeInfo$qpvt1t1 ; __GetTypeInfo(void *,void *,void *)
		add	esp, 0Ch
		push	eax
		push	offset @$xt$12std@bad_cast ; `__tpdsc__'[std::bad_cast]
		push	0
		push	1
		call	@__GetTypeInfo$qpvt1t1 ; __GetTypeInfo(void *,void *,void *)
		add	esp, 0Ch
		push	eax
		call	@std@type_info@$beql$xqrx13std@type_info ; std::type_info::operator==(std::type_info &)
		add	esp, 8
		retn
; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_403464	proc near		; DATA XREF: .text:00401014o

var_24		= dword	ptr -24h
var_14		= word ptr -14h
var_8		= dword	ptr -8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		mov	eax, offset stru_40E5DC
		call	@__InitExceptBlockLDTC
		mov	[ebp+var_14], 8
		push	offset stru_410B1C ; lpCriticalSection
		call	InitializeCriticalSection
		inc	[ebp+var_8]
		inc	[ebp+var_8]
		inc	[ebp+var_8]
		inc	[ebp+var_8]
		mov	dword_410B34, 1
		mov	edx, offset off_40E414
		mov	ecx, offset off_40E634
		mov	dword_410B38, edx
		mov	dword_410B38, ecx
		inc	[ebp+var_8]
		mov	eax, offset off_40E414
		mov	dword_410B3C, eax
		mov	edx, offset off_40E620
		mov	dword_410B3C, edx
		mov	ecx, [ebp+var_24]
		mov	large fs:0, ecx
		mov	esp, ebp
		pop	ebp
		retn
sub_403464	endp

; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_4034D8	proc near		; DATA XREF: .text:0040109Eo

var_24		= dword	ptr -24h
var_8		= dword	ptr -8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		mov	eax, offset stru_40E5F0
		call	@__InitExceptBlockLDTC
		dec	[ebp+var_8]
		dec	[ebp+var_8]
		push	0		; char
		push	offset dword_410B3C ; handle
		call	unknown_libname_4 ; BCC	v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		add	esp, 8
		dec	[ebp+var_8]
		dec	[ebp+var_8]
		push	0		; char
		push	offset dword_410B38 ; handle
		call	unknown_libname_4 ; BCC	v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		add	esp, 8
		dec	[ebp+var_8]
		cmp	dword_410B34, 0
		jz	short loc_403530
		xor	edx, edx
		push	offset stru_410B1C ; lpCriticalSection
		mov	dword_410B34, edx
		call	DeleteCriticalSection

loc_403530:				; CODE XREF: sub_4034D8+44j
		mov	ecx, [ebp+var_24]
		mov	large fs:0, ecx
		mov	esp, ebp
		pop	ebp
		retn
sub_4034D8	endp

; ---------------------------------------------------------------------------
		align 10h
; `__tpdsc__'[std::bad_cast]
@$xt$12std@bad_cast dd 4		    ; tpDtt ; DATA XREF: .text:00403446o
					; .data:0040E5C0o ...
		dw 3			; tpMask ; __rwstd::facet_imp::~facet_imp(void)
		dw 30h			; tpName
		dd 0			; bParent
		dd 77h			; tpcFlags
		dw 40h			; Size
		dw 50h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 2			; DtorCount
		dd 2			; DtorAltCount
		dd offset @__rwstd@facet_imp@$bdtr$qv_0; DtorAddr
		dw 1			; DtorMask
		dw 54h			; DtorMemberOff
		db 'std::bad_cast',0    ; Name
		align 4
		dd offset @$xt$13std@exception ; Parent
		dd 0, 3, 0
		dd 0
		dd 0			; end of tpid
; `__tpdsc__'[std::bad_typeid]
@$xt$14std@bad_typeid dd 4		      ;	tpDtt ;	DATA XREF: .text:unknown_libname_2o
					; __GetTypeInfo(void *,void *,void *)+46o ...
		dw 3			; tpMask ; __rwstd::facet_imp::~facet_imp(void)
		dw 30h			; tpName
		dd 0			; bParent
		dd 77h			; tpcFlags
		dw 40h			; Size
		dw 50h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 2			; DtorCount
		dd 2			; DtorAltCount
		dd offset @__rwstd@facet_imp@$bdtr$qv; DtorAddr
		dw 1			; DtorMask
		dw 54h			; DtorMemberOff
		db 'std::bad_typeid',0  ; Name
		dd offset @$xt$13std@exception ; Parent
		dd 0, 3, 0
		dd 0
		dd 0			; end of tpid
; `__tpdsc__'[_RWSTDMutex]
@$xt$11_RWSTDMutex dd 1Ch		   ; tpDtt ; DATA XREF:	.data:off_40E5B4o
					; .data:off_40E650o
		dw 3			; tpMask ; _RWSTDMutex::~_RWSTDMutex(void)
		dw 30h			; tpName
		dd 0FFFFFFFFh		; bParent
		dd 3			; tpcFlags
		dw 3Ch			; Size
		dw 40h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 1			; DtorCount
		dd 1			; DtorAltCount
		dd offset @_RWSTDMutex@$bdtr$qv; DtorAddr
		dw 1			; DtorMask
		dw 44h			; DtorMemberOff
		db '_RWSTDMutex',0      ; Name
		dd 0
		dd 0
		dd 0			; end of tpid
; [0000002C BYTES: COLLAPSED FUNCTION _RWSTDMutex::~_RWSTDMutex(void). PRESS KEYPAD "+"	TO EXPAND]
; [00000042 BYTES: COLLAPSED FUNCTION __rwstd::facet_imp::~facet_imp(void). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000042 BYTES: COLLAPSED FUNCTION __rwstd::facet_imp::~facet_imp(void). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [0000003B BYTES: COLLAPSED FUNCTION unknown_libname_3. PRESS KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_403728	proc near		; DATA XREF: .text:004010A4o

var_24		= dword	ptr -24h
var_8		= dword	ptr -8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		mov	eax, offset stru_40E674
		call	@__InitExceptBlockLDTC
		dec	[ebp+var_8]
		cmp	dword_410B58, 0
		jz	short loc_403756
		xor	edx, edx
		push	offset stru_410B40 ; lpCriticalSection
		mov	dword_410B58, edx
		call	DeleteCriticalSection

loc_403756:				; CODE XREF: sub_403728+1Aj
		mov	ecx, [ebp+var_24]
		mov	large fs:0, ecx
		mov	esp, ebp
		pop	ebp
		retn
sub_403728	endp

; [00000020 BYTES: COLLAPSED FUNCTION unknown_libname_4. PRESS KEYPAD "+" TO EXPAND]
; [0000005C BYTES: COLLAPSED FUNCTION unknown_libname_5. PRESS KEYPAD "+" TO EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION _memchr. PRESS KEYPAD "+"	TO EXPAND]
		align 10h
; [00000024 BYTES: COLLAPSED FUNCTION _memcpy. PRESS KEYPAD "+"	TO EXPAND]
; [0000004A BYTES: COLLAPSED FUNCTION _memmove.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [0000008A BYTES: COLLAPSED FUNCTION _memset. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000018 BYTES: COLLAPSED FUNCTION __wmemset. PRESS KEYPAD "+" TO EXPAND]
; [0000003C BYTES: COLLAPSED FUNCTION _strcat. PRESS KEYPAD "+"	TO EXPAND]
; [0000005A BYTES: COLLAPSED FUNCTION _strlen. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000006E BYTES: COLLAPSED FUNCTION _strncat.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000027 BYTES: COLLAPSED FUNCTION _strncmp.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000006C BYTES: COLLAPSED FUNCTION _memcmp. PRESS KEYPAD "+"	TO EXPAND]
; [00000032 BYTES: COLLAPSED FUNCTION _strdup. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000037 BYTES: COLLAPSED FUNCTION __stpcpy.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000018 BYTES: COLLAPSED FUNCTION _wcslen. PRESS KEYPAD "+"	TO EXPAND]
; [0000003F BYTES: COLLAPSED FUNCTION _wcscpy. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000039 BYTES: COLLAPSED FUNCTION @__InitExceptBlockLDTC. PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

@__ExitExceptBlock:
		mov	fs:0, eax
		retn
; ---------------------------------------------------------------------------
		db 2Ah
		dd 4343422Ah
		db 78h,	68h, 31h
; ---------------------------------------------------------------------------

__ExceptionHandler:			; DATA XREF: @__InitExceptBlockLDTC+10o
		mov	eax, esp
		push	dword_40E708
		push	ebx
		push	edi
		push	esi
		push	ebp
		push	eax
		push	dword ptr [eax+10h]
		push	dword ptr [eax+0Ch]
		push	dword ptr [eax+8]
		push	dword ptr [eax+4]
		call	____ExceptionHandler
		add	esp, 14h
		pop	ebp
		pop	esi
		pop	edi
		pop	ebx
		add	esp, 4
		retn
; [00000157 BYTES: COLLAPSED FUNCTION unknown_libname_6. PRESS KEYPAD "+" TO EXPAND]

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_403D3B	proc near		; DATA XREF: .text:004010AAo

var_24		= dword	ptr -24h

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFDCh
		push	ebx
		push	esi
		mov	eax, offset stru_40E70C
		call	@__InitExceptBlockLDTC
		xor	esi, esi

loc_403D4F:				; CODE XREF: sub_403D3B+41j
		mov	eax, dword_410B60[esi*4]
		test	eax, eax
		jz	short loc_403D75
		test	eax, eax
		jz	short loc_403D75

loc_403D5E:				; CODE XREF: sub_403D3B+38j
		mov	ebx, [eax+0Ch]
		test	eax, eax
		jz	short loc_403D6F
		push	3
		push	eax
		mov	eax, [eax]
		call	dword ptr [eax]
		add	esp, 8

loc_403D6F:				; CODE XREF: sub_403D3B+28j
		mov	eax, ebx
		test	eax, eax
		jnz	short loc_403D5E

loc_403D75:				; CODE XREF: sub_403D3B+1Dj
					; sub_403D3B+21j
		inc	esi
		cmp	esi, 100h
		jl	short loc_403D4F
		mov	edx, [ebp+var_24]
		mov	large fs:0, edx
		pop	esi
		pop	ebx
		mov	esp, ebp
		pop	ebp
		retn
sub_403D3B	endp

; [00000267 BYTES: COLLAPSED FUNCTION sub_403D8E. PRESS	KEYPAD "+" TO EXPAND]
; [000000A2 BYTES: COLLAPSED FUNCTION sub_403FF5. PRESS	KEYPAD "+" TO EXPAND]

; =============== S U B	R O U T	I N E =======================================


sub_404097	proc near		; DATA XREF: .text:00401020o
		mov	eax, offset off_40E414
		mov	edx, offset off_40E620
		mov	dword_410B5C, eax
		mov	dword_410B5C, edx
		mov	ecx, offset off_40E414
		mov	eax, offset off_40E634
		mov	dword_410F60, ecx
		mov	dword_410F60, eax
		retn
sub_404097	endp


; =============== S U B	R O U T	I N E =======================================


sub_4040C2	proc near		; DATA XREF: .text:004010B0o
		push	0		; char
		push	offset dword_410F60 ; handle
		call	unknown_libname_4 ; BCC	v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		add	esp, 8
		push	0		; char
		push	offset dword_410B5C ; handle
		call	unknown_libname_4 ; BCC	v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		add	esp, 8
		retn
sub_4040C2	endp

; ---------------------------------------------------------------------------
		align 4
; [00000037 BYTES: COLLAPSED FUNCTION __typeIDname(tpid	*). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [000000DB BYTES: COLLAPSED FUNCTION __isSameTypeID(tpid *,tpid *). PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000010F BYTES: COLLAPSED FUNCTION __isCompatTypeID(tpid *,tpid *,int,tpid **). PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000020 BYTES: COLLAPSED FUNCTION unknown_libname_7. PRESS KEYPAD "+" TO EXPAND]
; [00000071 BYTES: COLLAPSED FUNCTION std::type_info::operator==(std::type_info	&). PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000138 BYTES: COLLAPSED FUNCTION __GetTypeInfo(void *,void	*,void *). PRESS KEYPAD	"+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION std::bad_cast::bad_cast(std::bad_cast &).	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000067 BYTES: COLLAPSED FUNCTION unknown_libname_8. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000007A BYTES: COLLAPSED FUNCTION __adjustClassAdr(void *,tpid *,tpid *). PRESS KEYPAD "+" TO EXPAND]
		align 10h
; `__tpdsc__'[std::type_info]
@$xt$13std@type_info dd	8		     ; tpDtt ; DATA XREF: .text:0040465Co
					; .data:0040EA44o
		dw 3			; tpMask ; BCC v4.x/5.x	& BCB v1.0/v7.0	BDS2006	win32 runtime
		dw 30h			; tpName
		dd 0			; bParent
		dd 73h			; tpcFlags
		dw 40h			; Size
		dw 44h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 1			; DtorCount
		dd 1			; DtorAltCount
		dd offset unknown_libname_7; DtorAddr
		dw 1			; DtorMask
		dw 48h			; DtorMemberOff
		db 'std::type_info',0   ; Name
		align 4
		dd 0
		dd 0
		dd 0			; end of tpid
; `__tpdsc__'[type_info_hash]
@$xt$14type_info_hash dd 14h		      ;	tpDtt ;	DATA XREF: .data:0040EA34o
		dw 3			; tpMask ; std::bad_typeid::~bad_typeid(void)
		dw 30h			; tpName
		dd 0			; bParent
		dd 77h			; tpcFlags
		dw 40h			; Size
		dw 50h			; ExpDim
		dd 0			; mfnDel
		dw 0			; mfnMask
		dw 0			; mfnMaskArr
		dd 0			; mfnDelArr
		dd 2			; DtorCount
		dd 2			; DtorAltCount
		dd offset @std@bad_typeid@$bdtr$qv; DtorAddr
		dw 1			; DtorMask
		dw 54h			; DtorMemberOff
		db 'type_info_hash',0   ; Name
		align 4
		dd offset @$xt$13std@type_info ; Parent
		dd 0, 3, 0
		dd 0
		dd 0			; end of tpid
; [00000026 BYTES: COLLAPSED FUNCTION std::bad_typeid::~bad_typeid(void). PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000027 BYTES: COLLAPSED FUNCTION _InitTermAndUnexPtrs(void). PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000003E BYTES: COLLAPSED FUNCTION std::terminate(void). PRESS KEYPAD "+" TO	EXPAND]
; ---------------------------------------------------------------------------
		mov	ecx, [ebp-24h]
		mov	large fs:0, ecx
		pop	edi
		pop	esi
		pop	ebx
		mov	esp, ebp
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000024 BYTES: COLLAPSED FUNCTION std::unexpected(void). PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		retn
; ---------------------------------------------------------------------------
		align 4

loc_40473C:				; DATA XREF: .text:00401026o
		push	offset a___cppdebughoo ; "___CPPdebugHook"
		push	0
		call	GetModuleHandleA
		push	eax
		call	GetProcAddress
		mov	dword_410F68, eax
		cmp	dword_410F68, 0
		jnz	short locret_404766
		mov	dword_410F68, offset ___CPPdebugHook

locret_404766:				; CODE XREF: .text:0040475Aj
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000060 BYTES: COLLAPSED FUNCTION ___call_terminate. PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		mov	edx, [ebp-24h]
		mov	large fs:0, edx
		pop	edi
		pop	esi
		pop	ebx
		mov	esp, ebp
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000034 BYTES: COLLAPSED FUNCTION ___call_unexpected. PRESS	KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000004B BYTES: COLLAPSED FUNCTION __ExceptInit. PRESS KEYPAD "+" TO	EXPAND]
		align 10h
; [00000027 BYTES: COLLAPSED FUNCTION __GetExceptDLLinfoInternal. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_9. PRESS KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_404894	proc near		; DATA XREF: sub_404980+Ao

arg_0		= dword	ptr  8
arg_4		= dword	ptr  0Ch
arg_8		= dword	ptr  10h
arg_C		= dword	ptr  14h

		push	ebp
		mov	ebp, esp
		push	ebx
		push	esi
		push	edi
		mov	edi, [ebp+arg_8]
		mov	esi, [ebp+arg_4]
		mov	ebx, [ebp+arg_0]
		cmp	dword ptr [ebx], 0EEDFAE6h
		jnz	short loc_4048B2
		xor	eax, eax
		jmp	loc_40497A
; ---------------------------------------------------------------------------

loc_4048B2:				; CODE XREF: sub_404894+15j
		mov	eax, [ebx]
		cmp	eax, 0EEFFACEh
		jz	short loc_4048C2
		cmp	eax, 0EEDFACEh
		jnz	short loc_4048D0

loc_4048C2:				; CODE XREF: sub_404894+25j
		mov	eax, esi
		mov	edx, ebx
		call	___doGlobalUnwind
		call	___call_terminate
; ---------------------------------------------------------------------------

loc_4048D0:				; CODE XREF: sub_404894+2Cj
		cmp	dword ptr [ebx], 0C00000FDh
		jnz	short loc_4048EC
		cmp	dword_40EB74, 0
		jz	short loc_4048EC
		push	offset aStackOverflow ;	"Stack Overflow!"
		call	__ErrorExit
; ---------------------------------------------------------------------------
		db  59h	; Y
; ---------------------------------------------------------------------------

loc_4048EC:				; CODE XREF: sub_404894+42j
					; sub_404894+4Bj
		cmp	dword_410F70, 0
		jz	short loc_40490D
		mov	edx, [ebp+arg_C]
		push	edx		; _DWORD
		push	edi		; _DWORD
		push	esi		; _DWORD
		push	ebx		; _DWORD
		call	dword_410F70
		add	esp, 10h
		test	eax, eax
		jnz	short loc_40490D
		xor	eax, eax
		jmp	short loc_40497A
; ---------------------------------------------------------------------------

loc_40490D:				; CODE XREF: sub_404894+5Fj
					; sub_404894+73j
		cmp	dword_410F6C, 0
		jz	short loc_40492E
		mov	edx, [ebp+arg_C]
		push	edx		; _DWORD
		push	edi		; _DWORD
		push	esi		; _DWORD
		push	ebx		; _DWORD
		call	dword_410F6C
		add	esp, 10h
		test	eax, eax
		jnz	short loc_40492E
		xor	eax, eax
		jmp	short loc_40497A
; ---------------------------------------------------------------------------

loc_40492E:				; CODE XREF: sub_404894+80j
					; sub_404894+94j
		cmp	dword_4143B8, 0
		jz	short loc_404968
		mov	edx, dword_4143B8
		mov	eax, [edx]
		cmp	eax, 1
		jz	short loc_404949
		cmp	eax, 2
		jnz	short loc_404968

loc_404949:				; CODE XREF: sub_404894+AEj
		mov	eax, [ebx]
		cmp	eax, 0EEDFACEh
		jb	short loc_404959
		cmp	eax, 0EEFFACEh
		jbe	short loc_404968

loc_404959:				; CODE XREF: sub_404894+BCj
		push	edi
		push	ebx
		push	esi
		push	3		; int
		push	2		; Arguments
		call	___raiseDebuggerException
		add	esp, 14h

loc_404968:				; CODE XREF: sub_404894+A1j
					; sub_404894+B3j ...
		test	byte ptr [ebx+4], 6
		jz	short loc_404975
		mov	eax, 1
		jmp	short loc_40497A
; ---------------------------------------------------------------------------

loc_404975:				; CODE XREF: sub_404894+D8j
		mov	eax, 2

loc_40497A:				; CODE XREF: sub_404894+19j
					; sub_404894+77j ...
		pop	edi
		pop	esi
		pop	ebx
		pop	ebp
		retn
sub_404894	endp

; ---------------------------------------------------------------------------
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_404980	proc near		; CODE XREF: sub_4049F8+Ap

arg_0		= dword	ptr  8

		push	ebp
		mov	ebp, esp
		mov	eax, [ebp+arg_0]
		xor	edx, edx
		mov	[eax], edx
		mov	dword ptr [eax+4], offset sub_404894
		push	eax
		call	__SetExceptionHandler
		pop	ecx
		pop	ebp
		retn
sub_404980	endp

; ---------------------------------------------------------------------------
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION unknown_libname_20. PRESS	KEYPAD "+" TO EXPAND]
		align 4
		push	ebp
		mov	ebp, esp
		mov	eax, dword_410F70
		mov	edx, [ebp+8]
		mov	dword_410F70, edx
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 10h
		mov	dword_410F70, offset unknown_libname_9 ; BCC v4.x/5.x &	BCB v1.0/v7.0 BDS2006 win32 runtime
		retn
; ---------------------------------------------------------------------------
		align 4

loc_4049CC:				; DATA XREF: .text:0040102Co
		mov	dword_410F6C, offset unknown_libname_9 ; BCC v4.x/5.x &	BCB v1.0/v7.0 BDS2006 win32 runtime
		mov	dword_410F70, offset unknown_libname_9 ; BCC v4.x/5.x &	BCB v1.0/v7.0 BDS2006 win32 runtime
		retn
; ---------------------------------------------------------------------------
		align 4

loc_4049E4:				; DATA XREF: .text:004010B6o
		mov	eax, dword_411384
		test	eax, eax
		jz	short locret_4049F4
		push	eax
		call	unknown_libname_20 ; Borland Visual Component Library &	Packages
		pop	ecx

locret_4049F4:				; CODE XREF: .text:004049EBj
		retn
; ---------------------------------------------------------------------------
		align 4

; =============== S U B	R O U T	I N E =======================================


sub_4049F8	proc near		; CODE XREF: __startup+59p
		mov	eax, dword_411384
		test	eax, eax
		jz	short locret_404A08
		push	eax
		call	sub_404980
		pop	ecx

locret_404A08:				; CODE XREF: sub_4049F8+7j
		retn
sub_4049F8	endp

; ---------------------------------------------------------------------------
		align 4
; [00000015 BYTES: COLLAPSED FUNCTION __SetExceptionHandler. PRESS KEYPAD "+" TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION __UnsetExceptionHandler. PRESS KEYPAD "+"	TO EXPAND]
; ---------------------------------------------------------------------------

__UnwindException:
		jmp	RtlUnwind
; ---------------------------------------------------------------------------
		align 4
; [00000006 BYTES: COLLAPSED FUNCTION jump(void). PRESS	KEYPAD "+" TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION ___doGlobalUnwind. PRESS KEYPAD "+" TO EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION invokeHnd(void). PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000003D BYTES: COLLAPSED FUNCTION ___access. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000075 BYTES: COLLAPSED FUNCTION ___close.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000098 BYTES: COLLAPSED FUNCTION ___eof. PRESS KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION ___isatty. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000017 BYTES: COLLAPSED FUNCTION ___isatty_osfhandle. PRESS KEYPAD	"+" TO EXPAND]
		align 10h
; [00000084 BYTES: COLLAPSED FUNCTION ___lseek.	PRESS KEYPAD "+" TO EXPAND]
; [00000204 BYTES: COLLAPSED FUNCTION ___open. PRESS KEYPAD "+"	TO EXPAND]
; [0000006B BYTES: COLLAPSED FUNCTION sub_404E98. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000146 BYTES: COLLAPSED FUNCTION ___read. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000132 BYTES: COLLAPSED FUNCTION ___write.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000011 BYTES: COLLAPSED FUNCTION unknown_libname_10. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000042 BYTES: COLLAPSED FUNCTION __flushall. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000046 BYTES: COLLAPSED FUNCTION __rtl_read. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000019 BYTES: COLLAPSED FUNCTION __read. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000046 BYTES: COLLAPSED FUNCTION __rtl_write. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000019 BYTES: COLLAPSED FUNCTION __write. PRESS KEYPAD "+"	TO EXPAND]
		align 10h
; [00000005 BYTES: COLLAPSED FUNCTION j____access. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000007D BYTES: COLLAPSED FUNCTION __allocbuf. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000009F BYTES: COLLAPSED FUNCTION _fclose. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000008F BYTES: COLLAPSED FUNCTION _fflush. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000013B BYTES: COLLAPSED FUNCTION _fgets. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000064 BYTES: COLLAPSED FUNCTION __flushout. PRESS	KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION __initfmode. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION __initfileinfo. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [000000D9 BYTES: COLLAPSED FUNCTION sub_40561C. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000000A9 BYTES: COLLAPSED FUNCTION ___openfp. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000002A BYTES: COLLAPSED FUNCTION ___getfp.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000033 BYTES: COLLAPSED FUNCTION _fopen. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000038 BYTES: COLLAPSED FUNCTION _fprintf.	PRESS KEYPAD "+" TO EXPAND]
; [000000D9 BYTES: COLLAPSED FUNCTION ___fputn.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000005A BYTES: COLLAPSED FUNCTION sub_405918. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000073 BYTES: COLLAPSED FUNCTION _fseek. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000008C BYTES: COLLAPSED FUNCTION _ftell. PRESS KEYPAD "+" TO EXPAND]
; [0000000D BYTES: COLLAPSED FUNCTION __lock_all_handles. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000023 BYTES: COLLAPSED FUNCTION __cleanup_handle_locks. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __unlock_all_handles. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000094 BYTES: COLLAPSED FUNCTION __lock_handle. PRESS KEYPAD "+" TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION __unlock_handle. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000040 BYTES: COLLAPSED FUNCTION __get_handle. PRESS KEYPAD "+" TO	EXPAND]
; [00000068 BYTES: COLLAPSED FUNCTION __dup_handle. PRESS KEYPAD "+" TO	EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION __free_handle. PRESS KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_405C58	proc near		; DATA XREF: __init_handles:loc_405D27o

var_8		= dword	ptr -8
var_4		= dword	ptr -4
arg_0		= dword	ptr  8

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFF8h
		mov	eax, uNumber
		test	eax, eax
		push	esi
		mov	esi, [ebp+arg_0]
		lea	edx, uNumber[eax*4]
		jz	short loc_405C7F

loc_405C72:				; CODE XREF: sub_405C58+25j
		cmp	dword ptr [edx], 0
		jnz	short loc_405C7F
		dec	eax
		add	edx, 0FFFFFFFCh
		test	eax, eax
		jnz	short loc_405C72

loc_405C7F:				; CODE XREF: sub_405C58+18j
					; sub_405C58+1Dj
		test	esi, esi
		jnz	short loc_405C95
		test	eax, eax
		jnz	short loc_405C8B
		xor	eax, eax
		jmp	short loc_405CED
; ---------------------------------------------------------------------------

loc_405C8B:				; CODE XREF: sub_405C58+2Dj
		lea	edx, [eax+eax*4]
		add	edx, 4
		mov	eax, edx
		jmp	short loc_405CED
; ---------------------------------------------------------------------------

loc_405C95:				; CODE XREF: sub_405C58+29j
		mov	[esi], eax
		xor	ecx, ecx
		mov	[ebp+var_4], ecx
		add	esi, 4
		mov	[ebp+var_8], offset unk_40F048
		cmp	eax, [ebp+var_4]
		jle	short loc_405CD9

loc_405CAB:				; CODE XREF: sub_405C58+7Fj
		mov	cl, 1
		mov	edx, [ebp+var_8]
		mov	edx, [edx]
		test	dh, 8
		jz	short loc_405CBA
		or	cl, 20h

loc_405CBA:				; CODE XREF: sub_405C58+5Dj
		test	dh, 80h
		jnz	short loc_405CC2
		or	cl, 80h

loc_405CC2:				; CODE XREF: sub_405C58+65j
		test	dh, 20h
		jz	short loc_405CCA
		or	cl, 40h

loc_405CCA:				; CODE XREF: sub_405C58+6Dj
		mov	[esi], cl
		inc	esi
		inc	[ebp+var_4]
		add	[ebp+var_8], 4
		cmp	eax, [ebp+var_4]
		jg	short loc_405CAB

loc_405CD9:				; CODE XREF: sub_405C58+51j
		shl	eax, 2
		push	eax		; n
		push	offset hObject	; src
		push	esi		; dest
		call	_memcpy
		add	esp, 0Ch
		xor	eax, eax

loc_405CED:				; CODE XREF: sub_405C58+31j
					; sub_405C58+3Bj
		pop	esi
		pop	ecx
		pop	ecx
		pop	ebp
		retn
sub_405C58	endp

; ---------------------------------------------------------------------------
		align 4
; [0000016B BYTES: COLLAPSED FUNCTION __init_handles. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000009 BYTES: COLLAPSED FUNCTION ___doserrno. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000004C BYTES: COLLAPSED FUNCTION ___IOerror. PRESS	KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

___DOSerror:
		push	ebx
		call	GetLastError
		mov	ebx, eax
		and	ebx, 0FFFFh
		mov	eax, ebx
		and	eax, 0FFFFh
		push	eax
		call	___IOerror
		pop	ecx
		mov	eax, ebx
		pop	ebx
		retn
; [00000012 BYTES: COLLAPSED FUNCTION ___NTerror. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000034 BYTES: COLLAPSED FUNCTION sub_405EEC. PRESS	KEYPAD "+" TO EXPAND]
; [0000006C BYTES: COLLAPSED FUNCTION sub_405F20. PRESS	KEYPAD "+" TO EXPAND]
; [00000016 BYTES: COLLAPSED FUNCTION unknown_libname_11. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000000E6 BYTES: COLLAPSED FUNCTION unknown_libname_12. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000110 BYTES: COLLAPSED FUNCTION _fputc. PRESS KEYPAD "+" TO EXPAND]
; [00000058 BYTES: COLLAPSED FUNCTION ___mkname. PRESS KEYPAD "+" TO EXPAND]
; [00000041 BYTES: COLLAPSED FUNCTION ___tmpnam. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000003F BYTES: COLLAPSED FUNCTION _printf. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000002F BYTES: COLLAPSED FUNCTION _rewind. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000005F BYTES: COLLAPSED FUNCTION _setvbuf.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [000000C5 BYTES: COLLAPSED FUNCTION __init_streams. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000057 BYTES: COLLAPSED FUNCTION __exit_streams. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __lock_all_streams. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __unlock_all_streams. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [000000A4 BYTES: COLLAPSED FUNCTION __lock_stream. PRESS KEYPAD "+" TO EXPAND]
; [00000023 BYTES: COLLAPSED FUNCTION __cleanup_stream_locks. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000054 BYTES: COLLAPSED FUNCTION __unlock_stream. PRESS KEYPAD "+"	TO EXPAND]
; [0000001A BYTES: COLLAPSED FUNCTION unknown_libname_13. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000038 BYTES: COLLAPSED FUNCTION _vfprintf. PRESS KEYPAD "+" TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION sub_4065B8. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000034 BYTES: COLLAPSED FUNCTION sub_406600. PRESS	KEYPAD "+" TO EXPAND]
; [00000034 BYTES: COLLAPSED FUNCTION sub_406634. PRESS	KEYPAD "+" TO EXPAND]
; [0000094E BYTES: COLLAPSED FUNCTION ___vprinter. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000038 BYTES: COLLAPSED FUNCTION __xfclose. PRESS KEYPAD "+" TO EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION __xfflush. PRESS KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_407024	proc near		; CODE XREF: unknown_libname_11+Ep

arg_0		= dword	ptr  8

		push	ebp
		mov	ebp, esp
		push	ebx
		push	esi
		mov	ebx, [ebp+arg_0]
		push	ebx
		call	__lock_stream
		pop	ecx
		push	ebx
		call	unknown_libname_12 ; BCC v4.x/5.x & BCB	v1.0/v7.0 BDS2006 win32	runtime
		pop	ecx
		mov	esi, eax
		push	ebx
		call	__unlock_stream
		pop	ecx
		mov	eax, esi
		pop	esi
		pop	ebx
		pop	ebp
		retn
sub_407024	endp

; ---------------------------------------------------------------------------
		align 4
; [00000051 BYTES: COLLAPSED FUNCTION __getLocaleNumericInfo. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000016 BYTES: COLLAPSED FUNCTION _isalnum.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000012 BYTES: COLLAPSED FUNCTION _isascii.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000016 BYTES: COLLAPSED FUNCTION _isalpha.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION _iscntrl.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION _isdigit.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000016 BYTES: COLLAPSED FUNCTION _isgraph.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION _islower.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000016 BYTES: COLLAPSED FUNCTION _isprint.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000013 BYTES: COLLAPSED FUNCTION _ispunct.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION _isspace.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION _isupper.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000016 BYTES: COLLAPSED FUNCTION _isxdigit. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000017 BYTES: COLLAPSED FUNCTION _iswalnum. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000014 BYTES: COLLAPSED FUNCTION _iswascii. PRESS KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION _iswalpha. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000014 BYTES: COLLAPSED FUNCTION _iswcntrl. PRESS KEYPAD "+" TO EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION _iswdigit. PRESS KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION _iswgraph. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000014 BYTES: COLLAPSED FUNCTION _iswlower. PRESS KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION _iswprint. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000014 BYTES: COLLAPSED FUNCTION _iswpunct. PRESS KEYPAD "+" TO EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION _iswspace. PRESS KEYPAD "+" TO EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION _iswupper. PRESS KEYPAD "+" TO EXPAND]
; [00000017 BYTES: COLLAPSED FUNCTION _iswxdigit. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000043 BYTES: COLLAPSED FUNCTION ___isctype. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000055 BYTES: COLLAPSED FUNCTION ___iswctype. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000007A BYTES: COLLAPSED FUNCTION _mblen. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [000000D1 BYTES: COLLAPSED FUNCTION _mbtowc. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000071 BYTES: COLLAPSED FUNCTION _wctomb. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000129 BYTES: COLLAPSED FUNCTION _mbstowcs. PRESS KEYPAD "+" TO EXPAND]
		align 4
		push	ebp
		mov	ebp, esp
		push	ebx
		mov	ecx, [ebp+0Ch]
		mov	ebx, [ebp+8]
		lea	edx, [ecx+1]
		mov	eax, ebx
		jmp	short loc_407648
; ---------------------------------------------------------------------------

loc_407645:				; CODE XREF: .text:0040764Fj
		add	eax, 2

loc_407648:				; CODE XREF: .text:00407643j
		dec	edx
		jz	short loc_407651
		cmp	word ptr [eax],	0
		jnz	short loc_407645

loc_407651:				; CODE XREF: .text:00407649j
		test	edx, edx
		jz	short loc_407668
		cmp	word ptr [eax],	0
		jnz	short loc_407668
		sub	eax, ebx
		sar	eax, 1
		jns	short loc_407664
		adc	eax, 0

loc_407664:				; CODE XREF: .text:0040765Fj
		inc	eax
		pop	ebx
		pop	ebp
		retn
; ---------------------------------------------------------------------------

loc_407668:				; CODE XREF: .text:00407653j
					; .text:00407659j
		mov	eax, ecx
		pop	ebx
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 10h
; [000001A4 BYTES: COLLAPSED FUNCTION _wcstombs. PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

__llmul:
		push	edx
		push	eax
		mov	eax, [esp+10h]
		mul	dword ptr [esp]
		mov	ecx, eax
		mov	eax, [esp+4]
		mul	dword ptr [esp+0Ch]
		add	ecx, eax
		mov	eax, [esp]
		mul	dword ptr [esp+0Ch]
		add	edx, ecx
		pop	ecx
		pop	ecx
		retn	8
; ---------------------------------------------------------------------------

__lldiv:
		push	ebp
		push	ebx
		push	esi
		push	edi
		xor	edi, edi
		mov	ebx, [esp+14h]
		mov	ecx, [esp+18h]
		or	ecx, ecx
		jnz	short loc_407851
		or	edx, edx
		jz	short loc_4078A9
		or	ebx, ebx
		jz	short loc_4078A9

loc_407851:				; CODE XREF: .text:00407847j
		or	edx, edx
		jns	short loc_40785F
		neg	edx
		neg	eax
		sbb	edx, 0
		or	edi, 1

loc_40785F:				; CODE XREF: .text:00407853j
		or	ecx, ecx
		jns	short loc_40786D
		neg	ecx
		neg	ebx
		sbb	ecx, 0
		xor	edi, 1

loc_40786D:				; CODE XREF: .text:00407861j
		mov	ebp, ecx
		mov	ecx, 40h
		push	edi
		xor	edi, edi
		xor	esi, esi

loc_407879:				; CODE XREF: .text:loc_407890j
		shl	eax, 1
		rcl	edx, 1
		rcl	esi, 1
		rcl	edi, 1
		cmp	edi, ebp
		jb	short loc_407890
		ja	short loc_40788B
		cmp	esi, ebx
		jb	short loc_407890

loc_40788B:				; CODE XREF: .text:00407885j
		sub	esi, ebx
		sbb	edi, ebp
		inc	eax

loc_407890:				; CODE XREF: .text:00407883j
					; .text:00407889j
		loop	loc_407879
		pop	ebx
		test	ebx, 1
		jz	short loc_4078A2
		neg	edx
		neg	eax
		sbb	edx, 0

loc_4078A2:				; CODE XREF: .text:00407899j
					; .text:004078ADj
		pop	edi
		pop	esi
		pop	ebx
		pop	ebp
		retn	8
; ---------------------------------------------------------------------------

loc_4078A9:				; CODE XREF: .text:0040784Bj
					; .text:0040784Fj
		div	ebx
		xor	edx, edx
		jmp	short loc_4078A2
; [00000049 BYTES: COLLAPSED FUNCTION __lludiv.	PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

__llmod:
		push	ebp
		push	ebx
		push	esi
		push	edi
		xor	edi, edi
		mov	ebx, [esp+14h]
		mov	ecx, [esp+18h]
		or	ecx, ecx
		jnz	short loc_407912
		or	edx, edx
		jz	short loc_40796B
		or	ebx, ebx
		jz	short loc_40796B

loc_407912:				; CODE XREF: .text:00407908j
		or	edx, edx
		jns	short loc_407920
		neg	edx
		neg	eax
		sbb	edx, 0
		or	edi, 1

loc_407920:				; CODE XREF: .text:00407914j
		or	ecx, ecx
		jns	short loc_40792B
		neg	ecx
		neg	ebx
		sbb	ecx, 0

loc_40792B:				; CODE XREF: .text:00407922j
		mov	ebp, ecx
		mov	ecx, 40h
		push	edi
		xor	edi, edi
		xor	esi, esi

loc_407937:				; CODE XREF: .text:loc_40794Ej
		shl	eax, 1
		rcl	edx, 1
		rcl	esi, 1
		rcl	edi, 1
		cmp	edi, ebp
		jb	short loc_40794E
		ja	short loc_407949
		cmp	esi, ebx
		jb	short loc_40794E

loc_407949:				; CODE XREF: .text:00407943j
		sub	esi, ebx
		sbb	edi, ebp
		inc	eax

loc_40794E:				; CODE XREF: .text:00407941j
					; .text:00407947j
		loop	loc_407937
		mov	eax, esi
		mov	edx, edi
		pop	ebx
		test	ebx, 1
		jz	short loc_407964
		neg	edx
		neg	eax
		sbb	edx, 0

loc_407964:				; CODE XREF: .text:0040795Bj
					; .text:00407970j
		pop	edi
		pop	esi
		pop	ebx
		pop	ebp
		retn	8
; ---------------------------------------------------------------------------

loc_40796B:				; CODE XREF: .text:0040790Cj
					; .text:00407910j
		div	ebx
		xchg	eax, edx
		xor	edx, edx
		jmp	short loc_407964
; [0000004E BYTES: COLLAPSED FUNCTION __llumod.	PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

__llshl:
		cmp	cl, 20h
		jl	short loc_4079D6
		cmp	cl, 40h
		jl	short loc_4079CF
		xor	edx, edx
		xor	eax, eax
		retn
; ---------------------------------------------------------------------------

loc_4079CF:				; CODE XREF: .text:004079C8j
		mov	edx, eax
		shl	edx, cl
		xor	eax, eax
		retn
; ---------------------------------------------------------------------------

loc_4079D6:				; CODE XREF: .text:004079C3j
		shld	edx, eax, cl
		shl	eax, cl
		retn
; ---------------------------------------------------------------------------

__llshr:
		cmp	cl, 20h
		jl	short loc_4079F2
		cmp	cl, 40h
		jl	short loc_4079EC
		sar	edx, 1Fh
		mov	eax, edx
		retn
; ---------------------------------------------------------------------------

loc_4079EC:				; CODE XREF: .text:004079E4j
		mov	eax, edx
		cdq
		sar	eax, cl
		retn
; ---------------------------------------------------------------------------

loc_4079F2:				; CODE XREF: .text:004079DFj
		shrd	eax, edx, cl
		sar	edx, cl
		retn
; ---------------------------------------------------------------------------

__llushr:
		cmp	cl, 20h
		jl	short loc_407A0E
		cmp	cl, 40h
		jl	short loc_407A07
		xor	edx, edx
		xor	eax, eax
		retn
; ---------------------------------------------------------------------------

loc_407A07:				; CODE XREF: .text:00407A00j
		mov	eax, edx
		xor	edx, edx
		shr	eax, cl
		retn
; ---------------------------------------------------------------------------

loc_407A0E:				; CODE XREF: .text:004079FBj
		shrd	eax, edx, cl
		shr	edx, cl
		retn
; [0000016C BYTES: COLLAPSED FUNCTION __pow10. PRESS KEYPAD "+"	TO EXPAND]
tbyte_407B80	dt 0.0			; DATA XREF: __pow10+12r
		align 4
tbyte_407B8C	dt 1.0			; DATA XREF: __pow10+35r
		align 4
flt_407B98	dd 1.0			; DATA XREF: __pow10+15Cr
; [00000067 BYTES: COLLAPSED FUNCTION _atol. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION _atoi. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000013 BYTES: COLLAPSED FUNCTION __clear87. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000002F BYTES: COLLAPSED FUNCTION __control87. PRESS KEYPAD	"+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: thunk

sub_407C58	proc near		; CODE XREF: ___vprinter+66Ap
		jmp	off_40FD34
sub_407C58	endp


; =============== S U B	R O U T	I N E =======================================


sub_407C5E	proc near		; CODE XREF: ___vprinter+67Fp
		jmp	off_40FD38
; ---------------------------------------------------------------------------
		jmp	off_40FD3C	; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
; ---------------------------------------------------------------------------
		jmp	off_40FD40	; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
; ---------------------------------------------------------------------------

loc_407C70:				; CODE XREF: sub_407C58j sub_407C5Ej
					; DATA XREF: ...
		push	offset aPrintfFloating ; "printf : floating point formats not lin"...
		call	__ErrorExit
sub_407C5E	endp

; ---------------------------------------------------------------------------
		db  59h	; Y
		db 0C3h	; √
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_14. PRESS	KEYPAD "+" TO EXPAND]
		db  59h	; Y
		db 0C3h	; √

; =============== S U B	R O U T	I N E =======================================

; Attributes: noreturn

sub_407C88	proc near		; DATA XREF: .data:off_40FD9Co
					; .data:off_40FDA0o
		push	offset aPrintfFloati_0 ; "printf : floating point formats not lin"...
		call	__ErrorExit
sub_407C88	endp

; ---------------------------------------------------------------------------
		db  59h	; Y
		db 0C3h	; √

; =============== S U B	R O U T	I N E =======================================

; Attributes: noreturn

sub_407C94	proc near		; DATA XREF: .data:off_40FDA4o
					; .data:off_40FDA8o
		push	offset aScanfFloatin_0 ; "scanf	: floating point formats not link"...
		call	__ErrorExit
sub_407C94	endp

; ---------------------------------------------------------------------------
		db  59h	; Y
		db 0C3h	; √
; [00000016 BYTES: COLLAPSED FUNCTION __fpreset. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000002D BYTES: COLLAPSED FUNCTION __fuildq.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000021 BYTES: COLLAPSED FUNCTION __fuistq.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000011 BYTES: COLLAPSED FUNCTION __fxam. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [000000B1 BYTES: COLLAPSED FUNCTION ___int64toa. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000118 BYTES: COLLAPSED FUNCTION ___ldtrunc. PRESS	KEYPAD "+" TO EXPAND]
; [00000071 BYTES: COLLAPSED FUNCTION ___longtoa. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [0000001B BYTES: COLLAPSED FUNCTION ___utoa. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000030 BYTES: COLLAPSED FUNCTION unknown_libname_15. PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION unknown_libname_16. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000025 BYTES: COLLAPSED FUNCTION unknown_libname_17. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000002A BYTES: COLLAPSED FUNCTION __matherr. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [0000002E BYTES: COLLAPSED FUNCTION __matherrl. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000016 BYTES: COLLAPSED FUNCTION __initmatherr. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000025 BYTES: COLLAPSED FUNCTION __qdiv10.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [0000002E BYTES: COLLAPSED FUNCTION __qmul10.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000041 BYTES: COLLAPSED FUNCTION sub_4080C0. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000285 BYTES: COLLAPSED FUNCTION sub_408104. PRESS	KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_40838C	proc near		; DATA XREF: .text:004083AEo

arg_0		= dword	ptr  8
arg_4		= dword	ptr  0Ch

		push	ebp
		mov	ebp, esp
		cmp	[ebp+arg_4], 0
		mov	eax, [ebp+arg_0]
		jz	short loc_40839D
		add	eax, 0Ch
		jmp	short loc_4083A0
; ---------------------------------------------------------------------------

loc_40839D:				; CODE XREF: sub_40838C+Aj
		add	eax, 8

loc_4083A0:				; CODE XREF: sub_40838C+Fj
		pop	ebp
		retn
sub_40838C	endp

; ---------------------------------------------------------------------------
		align 4

__cvt_init:				; DATA XREF: .text:0040103Eo
		mov	off_40FD34, offset sub_408104
		mov	off_40FD38, offset sub_40838C
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000004A BYTES: COLLAPSED FUNCTION sub_4083BC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000002B7 BYTES: COLLAPSED FUNCTION sub_408408. PRESS	KEYPAD "+" TO EXPAND]
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_4086C0	proc near		; DATA XREF: .text:004086E2o

arg_0		= dword	ptr  8
arg_4		= dword	ptr  0Ch

		push	ebp
		mov	ebp, esp
		cmp	[ebp+arg_4], 0
		mov	eax, [ebp+arg_0]
		jz	short loc_4086D1
		add	eax, 0Ch
		jmp	short loc_4086D4
; ---------------------------------------------------------------------------

loc_4086D1:				; CODE XREF: sub_4086C0+Aj
		add	eax, 8

loc_4086D4:				; CODE XREF: sub_4086C0+Fj
		pop	ebp
		retn
sub_4086C0	endp

; ---------------------------------------------------------------------------
		align 4

__cvt_initw:				; DATA XREF: .text:0040104Ao
		mov	off_40FD9C, offset sub_408408
		mov	off_40FDA0, offset sub_4086C0
		retn
; ---------------------------------------------------------------------------
		align 10h
; [00000449 BYTES: COLLAPSED FUNCTION sub_4086F0. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000080 BYTES: COLLAPSED FUNCTION sub_408B3C. PRESS	KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

loc_408BBC:				; DATA XREF: .text:00401044o
		mov	off_40FD3C, offset sub_4086F0
		mov	off_40FD40, offset sub_408B3C
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000446 BYTES: COLLAPSED FUNCTION sub_408BD4. PRESS	KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

sub_40901C	proc near		; DATA XREF: .text:004090A6o

var_8		= dword	ptr -8
arg_0		= dword	ptr  8
arg_4		= dword	ptr  0Ch
arg_8		= dword	ptr  10h

		push	ebp
		mov	ebp, esp
		add	esp, 0FFFFFFF8h
		push	ebx
		push	esi
		mov	eax, [ebp+arg_8]
		mov	esi, [ebp+arg_4]
		mov	ebx, [ebp+arg_0]
		test	al, 4
		jz	short loc_409056
		push	dword_40FE10	; int
		push	dword_40FE0C	; int
		mov	dx, [ebx+8]
		push	edx
		push	dword ptr [ebx+4]
		push	dword ptr [ebx]	; long double
		push	1		; int
		call	___ldtrunc
		add	esp, 18h
		fstp	qword ptr [esi]
		wait
		jmp	short loc_409096
; ---------------------------------------------------------------------------

loc_409056:				; CODE XREF: sub_40901C+13j
		test	al, 8
		jz	short loc_40906E
		mov	ecx, [ebx]
		mov	[esi], ecx
		mov	ecx, [ebx+4]
		mov	[esi+4], ecx
		mov	cx, [ebx+8]
		mov	[esi+8], cx
		jmp	short loc_409096
; ---------------------------------------------------------------------------

loc_40906E:				; CODE XREF: sub_40901C+3Cj
		mov	eax, offset stru_40FEF8
		fld	tbyte ptr [eax]
		fstp	qword ptr [ebp+var_8]
		wait
		push	[ebp+var_8+4]	; int
		push	[ebp+var_8]	; int
		mov	cx, [ebx+8]
		push	ecx
		push	dword ptr [ebx+4]
		push	dword ptr [ebx]	; long double
		push	0		; int
		call	___ldtrunc
		add	esp, 18h
		fstp	dword ptr [esi]
		wait

loc_409096:				; CODE XREF: sub_40901C+38j
					; sub_40901C+50j
		pop	esi
		pop	ebx
		pop	ecx
		pop	ecx
		pop	ebp
		retn
sub_40901C	endp

; ---------------------------------------------------------------------------

__scan_initw:				; DATA XREF: .text:00401050o
		mov	off_40FDA4, offset sub_408BD4
		mov	off_40FDA8, offset sub_40901C
		retn
; ---------------------------------------------------------------------------
		align 4
; [000002D2 BYTES: COLLAPSED FUNCTION ___xcvt. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [000002F1 BYTES: COLLAPSED FUNCTION ___xcvtw.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000121 BYTES: COLLAPSED FUNCTION __setmbcp. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000006 BYTES: COLLAPSED FUNCTION __getmbcp. PRESS KEYPAD "+" TO EXPAND]
		align 4

__initMBCSTable:			; DATA XREF: .text:00401056o
		call	GetACP
		push	eax
		call	__setmbcp
		pop	ecx
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000001A BYTES: COLLAPSED FUNCTION __ismbcspace. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000056 BYTES: COLLAPSED FUNCTION __mbsrchr. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000045 BYTES: COLLAPSED FUNCTION sub_40982C. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [0000005C BYTES: COLLAPSED FUNCTION __assert.	PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000004E BYTES: COLLAPSED FUNCTION sub_4098D4. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000068 BYTES: COLLAPSED FUNCTION __ErrorMessageHelper. PRESS KEYPAD "+" TO	EXPAND]
; [0000001E BYTES: COLLAPSED FUNCTION ___errno.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000012 BYTES: COLLAPSED FUNCTION Corbaobj::TCorbaImplementation::GetTypeInfoCount(int &). PRESS KEYPAD "+"	TO EXPAND]
		align 10h
; [00000044 BYTES: COLLAPSED FUNCTION sub_4099C0. PRESS	KEYPAD "+" TO EXPAND]
; [0000011B BYTES: COLLAPSED FUNCTION __ErrorMessage. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [0000000F BYTES: COLLAPSED FUNCTION ___ErrorMessage. PRESS KEYPAD "+"	TO EXPAND]
		align 10h
; [00000014 BYTES: COLLAPSED FUNCTION __ErrorExit. PRESS KEYPAD	"+" TO EXPAND]
; ---------------------------------------------------------------------------
		pop	ecx
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000089 BYTES: COLLAPSED FUNCTION unknown_libname_18. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000012 BYTES: COLLAPSED FUNCTION __abort. PRESS KEYPAD "+"	TO EXPAND]
; ---------------------------------------------------------------------------
		pop	ecx
		retn
; [0000000D BYTES: COLLAPSED FUNCTION _abort. PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000001 BYTES: COLLAPSED FUNCTION nullsub_4. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000006A BYTES: COLLAPSED FUNCTION sub_409BFC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000015 BYTES: COLLAPSED FUNCTION _exit. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000015 BYTES: COLLAPSED FUNCTION __exit. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION __cexit. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [0000000F BYTES: COLLAPSED FUNCTION __c_exit.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000001A BYTES: COLLAPSED FUNCTION __init_wild_handlers. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000011 BYTES: COLLAPSED FUNCTION __argv_default_expand. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000011 BYTES: COLLAPSED FUNCTION __argv_default_expand_0. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000027 BYTES: COLLAPSED FUNCTION __init_setargv_handlers. PRESS KEYPAD "+"	TO EXPAND]
		align 4
; [00000088 BYTES: COLLAPSED FUNCTION __setargv. PRESS KEYPAD "+" TO EXPAND]
; [00000031 BYTES: COLLAPSED FUNCTION __exitargv. PRESS	KEYPAD "+" TO EXPAND]
		align 10h

; =============== S U B	R O U T	I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_409DE0(char *s, int)
sub_409DE0	proc near		; CODE XREF: __setargv+50p
					; DATA XREF: __setargv+33o

s		= dword	ptr  8
arg_4		= dword	ptr  0Ch

		push	ebp
		mov	ebp, esp
		push	ebx
		push	esi
		push	edi
		mov	esi, [ebp+s]
		mov	eax, dword_411378
		cmp	eax, dword_411344
		jnz	short loc_409E2A
		add	dword_411344, 10h
		mov	edx, dword_411344
		shl	edx, 2
		push	edx		; size
		mov	ecx, dword_411340
		push	ecx		; block
		call	_realloc
		add	esp, 8
		mov	dword_411340, eax
		test	eax, eax
		jnz	short loc_409E2A
		push	offset aNoSpaceForComm ; "No space for command line argument vect"...
		call	__ErrorExit
; ---------------------------------------------------------------------------
		db  59h	; Y
; ---------------------------------------------------------------------------

loc_409E2A:				; CODE XREF: sub_409DE0+14j
					; sub_409DE0+3Dj
		cmp	[ebp+arg_4], 0
		jz	short loc_409E75
		push	esi		; s
		call	_strlen
		pop	ecx
		inc	eax
		push	eax		; size
		call	_malloc
		pop	ecx
		mov	ebx, eax
		test	eax, eax
		jnz	short loc_409E50
		push	offset aNoSpaceForCo_0 ; "No space for command line argument"
		call	__ErrorExit
; ---------------------------------------------------------------------------
		db  59h	; Y
; ---------------------------------------------------------------------------

loc_409E50:				; CODE XREF: sub_409DE0+63j
		xor	eax, eax
		push	esi
		mov	edi, esi
		or	ecx, 0FFFFFFFFh
		repne scasb
		not	ecx
		sub	edi, ecx
		mov	esi, ebx
		xchg	esi, edi
		mov	edx, ecx
		mov	eax, edi
		shr	ecx, 2
		rep movsd
		mov	ecx, edx
		and	ecx, 3
		rep movsb
		pop	esi
		jmp	short loc_409E77
; ---------------------------------------------------------------------------

loc_409E75:				; CODE XREF: sub_409DE0+4Ej
		mov	ebx, esi

loc_409E77:				; CODE XREF: sub_409DE0+93j
		mov	eax, dword_411340
		mov	edx, dword_411378
		mov	[eax+edx*4], ebx
		inc	dword_411378
		pop	edi
		pop	esi
		pop	ebx
		pop	ebp
		retn
sub_409DE0	endp

; [00000158 BYTES: COLLAPSED FUNCTION __handle_setargv.	PRESS KEYPAD "+" TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION __handle_exitargv. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000071 BYTES: COLLAPSED FUNCTION sub_40A004. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000193 BYTES: COLLAPSED FUNCTION __handle_wsetargv. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000019 BYTES: COLLAPSED FUNCTION __handle_wexitargv. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000077 BYTES: COLLAPSED FUNCTION sub_40A228. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000037 BYTES: COLLAPSED FUNCTION unknown_libname_19. PRESS	KEYPAD "+" TO EXPAND]
		align 4

loc_40A2D8:				; DATA XREF: .text:004010C8o
		mov	eax, lpFilename
		push	eax
		call	_free
		pop	ecx
		retn
; ---------------------------------------------------------------------------
		align 4

__lock_env:
		mov	eax, dword_411360
		push	eax
		call	__lock_nt
		pop	ecx
		retn
; ---------------------------------------------------------------------------
		align 4

__unlock_env:
		mov	eax, dword_411360
		push	eax
		call	__unlock_nt
		pop	ecx
		retn
; ---------------------------------------------------------------------------
		align 4

loc_40A308:				; DATA XREF: .text:004010CEo
		mov	eax, dword_411358
		test	eax, eax
		jz	short loc_40A318
		push	eax
		call	_free
		pop	ecx

loc_40A318:				; CODE XREF: .text:0040A30Fj
		mov	eax, dword_411354
		test	eax, eax
		jz	short loc_40A328
		push	eax
		call	_free
		pop	ecx

loc_40A328:				; CODE XREF: .text:0040A31Fj
		xor	edx, edx
		xor	ecx, ecx
		mov	dword_411358, edx
		mov	dword_411354, ecx
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000014A BYTES: COLLAPSED FUNCTION __expandblock. PRESS KEYPAD "+" TO EXPAND]
		align 4

loc_40A488:				; DATA XREF: .text:0040106Eo
		call	__expandblock
		test	eax, eax
		jnz	short loc_40A49D
		push	offset aCouldNotAlloca ; "Could	not allocate memory for	environme"...
		call	__ErrorExit
; ---------------------------------------------------------------------------
		db  59h	; Y
		db 0C3h	; √
; ---------------------------------------------------------------------------

loc_40A49D:				; CODE XREF: .text:0040A48Fj
		mov	eax, dword_411354
		mov	dword_41136C, eax
		push	offset aCreatingEnviro ; "creating environment lock"
		push	offset dword_411360
		call	__create_lock
		add	esp, 8
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000001F BYTES: COLLAPSED FUNCTION sub_40A4BC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000001F5 BYTES: COLLAPSED FUNCTION sub_40A4DC. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000025 BYTES: COLLAPSED FUNCTION HandlerRoutine. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [000000B3 BYTES: COLLAPSED FUNCTION _signal. PRESS KEYPAD "+"	TO EXPAND]
		align 10h
; [00000094 BYTES: COLLAPSED FUNCTION _raise. PRESS KEYPAD "+" TO EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION __terminate. PRESS KEYPAD	"+" TO EXPAND]
; ---------------------------------------------------------------------------
		pop	ebp
		retn
; ---------------------------------------------------------------------------
		align 4
; [00000003 BYTES: COLLAPSED FUNCTION __create_shmem. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000003 BYTES: COLLAPSED FUNCTION sub_40A858. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [000000D2 BYTES: COLLAPSED FUNCTION __init_exit_proc.	PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [0000006B BYTES: COLLAPSED FUNCTION __cleanup. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __lock_exit. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [0000000D BYTES: COLLAPSED FUNCTION __unlock_exit. PRESS KEYPAD "+" TO EXPAND]
		align 4

loc_40A9BC:				; DATA XREF: .text:00401074o
		push	offset aCreatingAtexit ; "creating atexit lock"
		push	offset dword_411390
		call	__create_lock
		add	esp, 8
		retn
; ---------------------------------------------------------------------------
		align 10h
; [0000017B BYTES: COLLAPSED FUNCTION __startup. PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		pop	ecx
; [00000007 BYTES: COLLAPSED CHUNK OF FUNCTION __startup. PRESS	KEYPAD "+" TO EXPAND]
		align 4

; =============== S U B	R O U T	I N E =======================================


sub_40AB54	proc near		; CODE XREF: __startup+13Bp

var_18		= byte ptr -18h
var_14		= word ptr -14h

		add	esp, 0FFFFFFBCh
		push	esp		; lpStartupInfo
		call	GetStartupInfoA
		test	[esp+44h+var_18], 1
		jz	short loc_40AB6B
		movzx	eax, [esp+44h+var_14]
		jmp	short loc_40AB70
; ---------------------------------------------------------------------------

loc_40AB6B:				; CODE XREF: sub_40AB54+Ej
		mov	eax, 0Ah

loc_40AB70:				; CODE XREF: sub_40AB54+15j
		add	esp, 44h
		retn
sub_40AB54	endp

; ---------------------------------------------------------------------------

___GetTlsIndex:				; Sysinit::__linkproc__	GetTls(void)
		call	@Sysinit@@GetTls$qqrv
; [00000007 BYTES: COLLAPSED FUNCTION Controls::TControl::GetFloatingDockSiteClass(void). PRESS	KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------

___GetStkIndex:				; Sysinit::__linkproc__	GetTls(void)
		call	@Sysinit@@GetTls$qqrv
; [00000007 BYTES: COLLAPSED FUNCTION Modelprimitives::TBasicView::GetShade(void). PRESS KEYPAD	"+" TO EXPAND]
; [0000004F BYTES: COLLAPSED FUNCTION __init_tls. PRESS	KEYPAD "+" TO EXPAND]
		align 4
; [00000006 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_Alloc. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000010 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_Free.	PRESS KEYPAD "+" TO EXPAND]
; [00000010 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_GetValue. PRESS KEYPAD "+" TO	EXPAND]
; [00000014 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_SetValue. PRESS KEYPAD "+" TO	EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_InitThread. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [00000007 BYTES: COLLAPSED FUNCTION ___CRTL_TLS_ExitThread. PRESS KEYPAD "+" TO EXPAND]
		align 4

___CRTL_TLS_GetInfo:
		xor	eax, eax
		retn
; ---------------------------------------------------------------------------
		align 4
; [0000003B BYTES: COLLAPSED FUNCTION __thread_buf. PRESS KEYPAD "+" TO	EXPAND]
		align 4
; [00000026 BYTES: COLLAPSED FUNCTION __thread_data. PRESS KEYPAD "+" TO EXPAND]
		align 10h
; [000000A5 BYTES: COLLAPSED FUNCTION __thread_data_new. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000031 BYTES: COLLAPSED FUNCTION __thread_data_del. PRESS KEYPAD "+" TO EXPAND]
		align 4

loc_40AD6C:				; DATA XREF: .text:00401080o
		push	offset aCreatingThread ; "creating thread data lock"
		push	offset dword_4113AC
		call	__create_lock
		add	esp, 8
		retn
; ---------------------------------------------------------------------------
		align 10h
; [000000AF BYTES: COLLAPSED FUNCTION sub_40AD80. PRESS	KEYPAD "+" TO EXPAND]
		align 10h
; [00000064 BYTES: COLLAPSED FUNCTION __create_lock. PRESS KEYPAD "+" TO EXPAND]
; [0000000E BYTES: COLLAPSED FUNCTION __lock_nt. PRESS KEYPAD "+" TO EXPAND]
		align 4
; [0000000E BYTES: COLLAPSED FUNCTION __unlock_nt. PRESS KEYPAD	"+" TO EXPAND]
		align 4
; [00000033 BYTES: COLLAPSED FUNCTION __lock_error. PRESS KEYPAD "+" TO	EXPAND]
		db  59h	; Y
		db  5Fh	; _
		db  5Eh	; ^
		db  8Bh	; ã
		db 0E5h	; Â
		db  5Dh	; ]
		db 0C3h	; √
		align 10h

loc_40AEF0:				; DATA XREF: .text:00401086o
		push	offset CriticalSection
		call	InitializeCriticalSection
		mov	dword_4143B0, 1
		retn
; ---------------------------------------------------------------------------
		align 4

loc_40AF08:				; DATA XREF: .text:0040108Co
		push	offset a___cppdebugh_0 ; "___CPPdebugHook"
		push	0
		call	GetModuleHandleA
		push	eax
		call	GetProcAddress
		mov	dword_4143B8, eax
		cmp	dword_4143B8, 0
		jnz	short locret_40AF32
		mov	dword_4143B8, offset ___CPPdebugHook

locret_40AF32:				; CODE XREF: .text:0040AF26j
		retn
; [00000006 BYTES: COLLAPSED FUNCTION ___JumpToCatch__.	PRESS KEYPAD "+" TO EXPAND]
; ---------------------------------------------------------------------------
		retn
; [0000004A BYTES: COLLAPSED FUNCTION sub_40AF3A. PRESS	KEYPAD "+" TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION sub_40AF84. PRESS	KEYPAD "+" TO EXPAND]
; [000000C6 BYTES: COLLAPSED FUNCTION sub_40AFB1. PRESS	KEYPAD "+" TO EXPAND]
; [0000010E BYTES: COLLAPSED FUNCTION sub_40B077. PRESS	KEYPAD "+" TO EXPAND]
; [00000018 BYTES: COLLAPSED FUNCTION sub_40B185. PRESS	KEYPAD "+" TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION ___raiseDebuggerException. PRESS KEYPAD "+" TO EXPAND]
; [000000D0 BYTES: COLLAPSED FUNCTION sub_40B1BA. PRESS	KEYPAD "+" TO EXPAND]
; [0000007E BYTES: COLLAPSED FUNCTION sub_40B28A. PRESS	KEYPAD "+" TO EXPAND]
; [00000250 BYTES: COLLAPSED FUNCTION sub_40B308. PRESS	KEYPAD "+" TO EXPAND]
; [00000035 BYTES: COLLAPSED FUNCTION _ThrowExceptionLDTC(void *,void *,void *,void *,uint,uint,uint,uchar *,void *). PRESS KEYPAD "+" TO EXPAND]
; [0000006B BYTES: COLLAPSED FUNCTION _ReThrowException(uint,uchar *). PRESS KEYPAD "+"	TO EXPAND]
; [0000003F BYTES: COLLAPSED FUNCTION __Global_unwind. PRESS KEYPAD "+"	TO EXPAND]
; [00000075 BYTES: COLLAPSED FUNCTION sub_40B637. PRESS	KEYPAD "+" TO EXPAND]
; [00000088 BYTES: COLLAPSED FUNCTION sub_40B6AC. PRESS	KEYPAD "+" TO EXPAND]
; [000000EA BYTES: COLLAPSED FUNCTION _CatchCleanup(void). PRESS KEYPAD	"+" TO EXPAND]
; ---------------------------------------------------------------------------
		pop	edi
		pop	esi
		pop	ebx
		mov	esp, ebp
		pop	ebp
		retn
; [000002D4 BYTES: COLLAPSED FUNCTION sub_40B825. PRESS	KEYPAD "+" TO EXPAND]
; [0000016B BYTES: COLLAPSED FUNCTION sub_40BAF9. PRESS	KEYPAD "+" TO EXPAND]
; [00000013 BYTES: COLLAPSED FUNCTION __Local_unwind. PRESS KEYPAD "+" TO EXPAND]
; [0000001C BYTES: COLLAPSED FUNCTION __Return_unwind. PRESS KEYPAD "+"	TO EXPAND]
; [00000045 BYTES: COLLAPSED FUNCTION sub_40BC93. PRESS	KEYPAD "+" TO EXPAND]
; [0000035D BYTES: COLLAPSED FUNCTION ____ExceptionHandler. PRESS KEYPAD "+" TO	EXPAND]
; [000000F7 BYTES: COLLAPSED FUNCTION sub_40C035. PRESS	KEYPAD "+" TO EXPAND]
; [0000004B BYTES: COLLAPSED FUNCTION sub_40C12C. PRESS	KEYPAD "+" TO EXPAND]
; [000002B0 BYTES: COLLAPSED FUNCTION sub_40C177. PRESS	KEYPAD "+" TO EXPAND]
; [00000124 BYTES: COLLAPSED FUNCTION sub_40C427. PRESS	KEYPAD "+" TO EXPAND]
; [00000087 BYTES: COLLAPSED FUNCTION sub_40C54B. PRESS	KEYPAD "+" TO EXPAND]
; [00000484 BYTES: COLLAPSED FUNCTION sub_40C5D2. PRESS	KEYPAD "+" TO EXPAND]
; [00000054 BYTES: COLLAPSED FUNCTION __CurrExcContext.	PRESS KEYPAD "+" TO EXPAND]
		align 4
; [00000006 BYTES: COLLAPSED FUNCTION CloseHandle. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION CreateFileA. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION DeleteCriticalSection. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION DeleteFileA. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION EnterCriticalSection. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION ExitProcess. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetACP. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetCPInfo. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetCommandLineA. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetCurrentThreadId. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetEnvironmentStrings. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetFileAttributesA. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetFileType. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetLastError. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetLocalTime. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetModuleFileNameA. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetModuleHandleA.	PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetOEMCP.	PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetProcAddress. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetProcessHeap. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetStartupInfoA. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetStdHandle. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetStringTypeW. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetVersion. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GetVersionExA. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION GlobalMemoryStatus. PRESS	KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HeapAlloc. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION HeapFree.	PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION InitializeCriticalSection. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION LeaveCriticalSection. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION LoadLibraryA. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION MultiByteToWideChar. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION RaiseException. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION ReadFile.	PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION RtlUnwind. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION SetConsoleCtrlHandler. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION SetFilePointer. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION SetHandleCount. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION SetLastError. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION TlsAlloc.	PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION TlsFree. PRESS KEYPAD "+"	TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION TlsGetValue. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION TlsSetValue. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION VirtualAlloc. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION VirtualFree. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION VirtualQuery. PRESS KEYPAD "+" TO	EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION WideCharToMultiByte. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION WriteFile. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION EnumThreadWindows. PRESS KEYPAD "+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION MessageBoxA. PRESS KEYPAD	"+" TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION wsprintfA. PRESS KEYPAD "+" TO EXPAND]
		db 2 dup(0CCh)
		dd 8 dup(0)
		dd 100h	dup(?)
_text		ends

; Section 2. (virtual address 0000D000)
; Virtual size			: 00008000 (  32768.)
; Section size in file		: 00003C00 (  15360.)
; Offset to raw	data for section: 0000C200
; Flags	C0000040: Data Readable	Writable
; Alignment	: default
; ===========================================================================

; Segment type:	Pure data
; Segment permissions: Read/Write
_data		segment	para public 'DATA' use32
		assume cs:_data
		;org 40D000h
aBorlandCCopyri	db 'Borland C++ - Copyright 2002 Borland Corporation',0
		align 4
off_40D034	dd offset byte_401000	; DATA XREF: start+41o
		dd offset byte_401090
		dd offset byte_401090
		dd offset unk_4010D8
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset _main
		dd offset __matherr
		dd offset __matherrl
		db    0
		db    0
		db    0
		db    0
		dd offset unk_40F110
		dd offset off_4100C8
		dd offset off_4100CC
		dd offset __handle_setargv
		dd offset __handle_exitargv
		dd offset __handle_wsetargv
		dd offset __handle_wexitargv
		dd offset dword_40EB90
		db    0
byte_40D07D	db 0			; DATA XREF: .text:00401140r
		dd offset unk_410028
		dd offset unk_4100F0
		dd offset unk_40FE84
		db    0
; DWORD	TlsIndex
TlsIndex	dd 0			; DATA XREF: start:loc_4010F2r
					; .text:00401162r ...
dword_40D08F	dd 0			; DATA XREF: start+1Aw
dword_40D093	dd 0			; DATA XREF: start+4Dw
					; .text:__getHInstancer
		db  90h	; ê
; Exported entry   2. ___CPPdebugHook
		public ___CPPdebugHook
___CPPdebugHook	db    0			; DATA XREF: start+Eo .text:0040475Co	...
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
; char arglist[]
arglist		dd 3			; DATA XREF: _main+12r	sub_401A04+1Er	...
dword_40D0A8	dd 0			; DATA XREF: _main+Cr sub_401A04+18r ...
dword_40D0AC	dd 0			; DATA XREF: _main+292w
					; sub_401620:loc_401646w ...
aL_eof		db '**l_eof**',0        ; DATA XREF: sub_401620+1Fo
					; sub_4016EC:loc_4016F4o ...
		align 4
off_40D0BC	dd offset unk_40DDF4	; DATA XREF: _main:loc_4013BBw
					; _main+1A3r
off_40D0C0	dd offset aMetas	; DATA XREF: _main+9Dw	sub_401EE4+7r
					; "Metas"
off_40D0C4	dd offset aActs		; DATA XREF: _main+ABw	sub_401F5C+40r
					; "Acts"
dword_40D0C8	dd 0			; DATA XREF: _main+83w
dword_40D0CC	dd 0			; DATA XREF: _main:loc_4013A3w
dword_40D0D0	dd 0			; DATA XREF: _main:loc_4013E2w
					; sub_401EE4+12r ...
unk_40D0D4	db    0			; DATA XREF: _main+1E7o _main+1FDo ...
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset aZZ		; "Z z"
		db    0
		db    0
		db    0
		db    0
		db  64h	; d
		db    0
		db    0
		db    0
; char byte_40D0E8[]
byte_40D0E8	db 100h	dup(0)		; DATA XREF: sub_401620+Eo
					; sub_401620+2Co ...
; char *s1
s1		dd offset byte_40D0E8	; DATA XREF: sub_401620+2Cw
					; sub_401620:loc_401656r ...
; int dword_40D1EC
dword_40D1EC	dd 0			; DATA XREF: sub_401800+5Dr
					; sub_401800+74r ...
; int dword_40D1F0[]
dword_40D1F0	dd 100h	dup(0)		; DATA XREF: sub_401A04+E0r
					; sub_401A04+106r
; int dword_40D5F0[]
dword_40D5F0	dd 100h	dup(0)		; DATA XREF: sub_401800+7Aw
					; sub_401EE4:loc_401F2Cr
; int dword_40D9F0
dword_40D9F0	dd 0			; DATA XREF: sub_401800:loc_4019D0r
					; sub_401800+1E7r ...
; int dword_40D9F4[]
dword_40D9F4	dd 100h	dup(0)		; DATA XREF: sub_401800+1EDw
					; sub_401F5C:loc_401F6Er ...
unk_40DDF4	db  68h	; h		; DATA XREF: .data:off_40D0BCo
unk_40DDF5	db    0			; DATA XREF: sub_401A04:loc_401E8Eo
					; sub_401EE4:loc_401F06o ...
aMetas		db 'Metas',0            ; DATA XREF: .data:off_40D0C0o
aActs		db 'Acts',0             ; DATA XREF: .data:off_40D0C4o
aZZ		db 'Z z',0              ; DATA XREF: .data:0040D0DCo
; char aNoMemory[]
aNoMemory	db 0Ah			; DATA XREF: sub_401304+Eo
		db 0Ah
		db 7,'No memory !!!',0Ah,0
; char format[]
format		db 'Symbol Table Maker v%d.%02d. Copyright 1991-2007 Ilfak Guilfanov.'
					; DATA XREF: _main+18o
		db ' Apr 30 2007',0Ah,0
aHpp		db 'hpp',0              ; DATA XREF: _main:loc_4013BBo
; char aUsageStmIinclI[]
aUsageStmIinclI	db 'Usage: stm [-Iincl] [-iincl] [-P] [-aacts] [-mmetas] infile outfi'
					; DATA XREF: _main:loc_4013EEo
		db 'le',0Ah,0
; char aBadSwitchC[]
aBadSwitchC	db 'Bad switch ',27h,'%c',27h,0Ah,0 ; DATA XREF: _main+DBo
; char mode[]
mode		db 'r',0                ; DATA XREF: _main+104o
; char aCanTOpenInputF[]
aCanTOpenInputF	db 'Can',27h,'t open input file %s',0Ah,0 ; DATA XREF: _main+126o
; char aW[]
aW		db 'w',0                ; DATA XREF: _main:loc_40146Bo
					; _main+19Eo
; char aCanTOpenOutput[]
aCanTOpenOutput	db 'Can',27h,'t open output file %s',0Ah,0 ; DATA XREF: _main+15Do
; char aCanTOpenHeader[]
aCanTOpenHeader	db 'Can',27h,'t open header file %s',0Ah,0 ; DATA XREF: _main+1CBo
; char aAny[]
aAny		db 'any',0              ; DATA XREF: _main+1E2o
; char aNext[]
aNext		db 'next',0             ; DATA XREF: _main+1F8o
; char aThis[]
aThis		db 'this',0             ; DATA XREF: _main+20Eo
; char aStart[]
aStart		db 'start',0            ; DATA XREF: _main+224o
; char aError[]
aError		db 'error',0            ; DATA XREF: _main+23Ao
					; sub_401A04+496o
; char aEnd[]
aEnd		db 'end',0              ; DATA XREF: _main+250o
; char a0[]
a0		db '0',0                ; DATA XREF: _main+266o
aEot		db 'EOT',0              ; DATA XREF: _main+29Co sub_4016EC+CEo
; char s2[]
s2		db '//',0               ; DATA XREF: sub_401620+A7o
; char aTermCodeErrorA[]
aTermCodeErrorA	db 'Term Code Error at line %d: %s and %s',0Ah,0 ; DATA XREF: sub_4016EC+7Bo
; char aTermRedeclarat[]
aTermRedeclarat	db 'Term Redeclaration Error at line %d (%s)',0Ah,0
					; DATA XREF: sub_4016EC+B2o
aSymbol		db 'symbol',0           ; DATA XREF: sub_401800+18o
					; sub_401A04+6Ao
; char aSymbolErrorAtL[]
aSymbolErrorAtL	db 'Symbol Error at line %d',0Ah,0 ; DATA XREF: sub_401800+41o
					; sub_401A04+93o
; char aMetaRedeclarat[]
aMetaRedeclarat	db 'Meta Redeclaration Error at line %d (%s)',0Ah,0
					; DATA XREF: sub_401800+97o
aEos		db 'EOS',0              ; DATA XREF: sub_401800+B7o
					; sub_401A04+136o
asc_40DFDA	db ':',0                ; DATA XREF: sub_401800+13Do
					; sub_401A04+1A8o
; char aLabelRedeclara[]
aLabelRedeclara	db 'Label Redeclaration Error at line %d (%s)',0Ah,0
					; DATA XREF: sub_401800+118o
; char aUndefinedTermA[]
aUndefinedTermA	db 'Undefined term at line %d (%s)',0Ah,0 ; DATA XREF: sub_401800+179o
					; sub_401A04+207o
; char aIllegalUseOfAc[]
aIllegalUseOfAc	db 'Illegal use of action at line %d (%s)',0Ah,0
					; DATA XREF: sub_401800+1BBo
; char aThisFileIsGene[]
aThisFileIsGene	db 0Ah			; DATA XREF: sub_401A04+24o
		db '/*',9,'This file is generated by Symbol Table Maker.',0Ah
		db 9,'Copyright (c) 1991-2006 by I.Guilfanov. Version %d.%02d */',0Ah
		db 0Ah,0
; char aThisFileIsGe_0[]
aThisFileIsGe_0	db '/*',0Ah             ; DATA XREF: sub_401A04+3Do
		db 9,'This file is generated by Symbol Table Maker.',0Ah
		db 9,'Copyright (c) 1991-2006 by I.Guilfanov. Version %d.%02d',0Ah
		db 0Ah
		db 9,'This file must be included as a part of the parser_t class defin'
		db 'ition.',0Ah
		db '*/',0Ah
		db 0Ah,0
; char aMetaNotFoundAt[]
aMetaNotFoundAt	db 'Meta not found at line %d (%s)',0Ah,0 ; DATA XREF: sub_401A04+C8o
; char aSymbolSIsEmpty[]
aSymbolSIsEmpty	db 'Symbol %s is empty !',0Ah,0 ; DATA XREF: sub_401A04+EEo
; char aStaticConstSSD[]
aStaticConstSSD	db 'static const %s %s[%d] =',0Ah ; DATA XREF: sub_401A04+115o
		db '{',0Ah,0
aPsymbol_t	db 'psymbol_t',0        ; DATA XREF: sub_401A04+110o
					; sub_401EE4+Do
; char aBadLastChoiceA[]
aBadLastChoiceA	db 'Bad last choice at line %d',0Ah,0 ; DATA XREF: sub_401A04+16Ao
; char asc_40E1EF[]
asc_40E1EF	db 0Ah			; DATA XREF: sub_401A04:loc_401B83o
					; sub_401F5C+A5o
		db '};',0Ah
		db 0Ah,0
; char aTermMismatchAt[]
aTermMismatchAt	db 'Term mismatch at line %d (%s)',0Ah,0 ; DATA XREF: sub_401A04+24Eo
; char aUndefinedMetaA[]
aUndefinedMetaA	db 'Undefined meta at line %d (%s)',0Ah,0 ; DATA XREF: sub_401A04+277o
; char aMetaMismatchAt[]
aMetaMismatchAt	db 'Meta mismatch at line %d (%s)',0Ah,0 ; DATA XREF: sub_401A04+2C6o
; char aUndefinedNextL[]
aUndefinedNextL	db 'Undefined next label at line %d',0Ah,0 ; DATA XREF: sub_401A04+2E8o
; char aNextLabelIsDef[]
aNextLabelIsDef	db 'Next label is defined as term or meta at line %d (%s)',0Ah,0
					; DATA XREF: sub_401A04+31Co
; char aUnknownSystemL[]
aUnknownSystemL	db 'Unknown system label type %d',0Ah,0 ; DATA XREF: sub_401A04+385o
; char aTypeMismatchOf[]
aTypeMismatchOf	db 'Type mismatch of Action at line %d',0Ah,0 ; DATA XREF: sub_401A04+3D1o
; char asc_40E2ED[]
asc_40E2ED	db ',',0Ah,0            ; DATA XREF: sub_401A04+417o
					; sub_401EE4+3Do ...
; char a2d8sD[]
a2d8sD		db '/* %2d %-8s*/ { %d,',9,0 ; DATA XREF: sub_401A04+44Bo
; char aD[]
aD		db '%d',0               ; DATA XREF: sub_401A04+461o
; char aS[]
aS		db '%s',0               ; DATA XREF: sub_401A04+471o
; char aDDSS[]
aDDSS		db ',',9,'%d,',9,'%d,',9,'} /* %s,%s */',0 ; DATA XREF: sub_401A04+4C6o
; char aSconstSConstSD[]
aSconstSConstSD	db '%sconst %s *const %s[ %d ] = {',0Ah,0 ; DATA XREF: sub_401EE4+28o
aStatic		db 'static ',0          ; DATA XREF: sub_401EE4+1Bo
					; sub_401F5C+55o
; char a2dS[]
a2dS		db '/* %2d */ %s',0     ; DATA XREF: sub_401EE4+53o
; char asc_40E358[]
asc_40E358	db 0Ah			; DATA XREF: sub_401EE4+6Bo
		db '};',0Ah,0
; char a2dSIdaapiSVoid[]
a2dSIdaapiSVoid	db '/* %2d */ %s idaapi %s(void);',0Ah,0 ; DATA XREF: sub_401F5C+22o
aError_t	db 'error_t',0          ; DATA XREF: sub_401F5C+1Co
; char aSconstSSD[]
aSconstSSD	db 0Ah			; DATA XREF: sub_401F5C+62o
		db '%sconst %s %s[%d] =',0Ah
		db '{',0Ah,0
aAction_t	db 'action_t',0         ; DATA XREF: sub_401F5C+46o
; char a2dParser_tS[]
a2dParser_tS	db '/* %2d */ &parser_t::%s',0 ; DATA XREF: sub_401F5C+8Do
		align 10h
stru_40E3C0	_excInfo <offset @$xt$13std@bad_alloc, 4, -4> ;	DATA XREF: .data:0040E3D8o
					; `__tpdsc__'[std::bad_alloc]
		dd 0
stru_40E3D0	_excHdr	<0, -40>	; DATA XREF: operator new(uint)+6o
					; end of descriptors
		_excData <50000h, 0, offset stru_40E3C0>
stru_40E3E4	_excInfo <offset @$xt$p13std@bad_alloc,	5, 8> ;	DATA XREF: .data:0040E3FCo
					; `__tpdsc__'[std::bad_alloc *]
		dd 0
stru_40E3F4	_excHdr	<0, -36>	; DATA XREF: std::bad_alloc::bad_alloc(std::bad_alloc &)+6o
					; end of descriptors
		_excData <50000h, 0, offset stru_40E3E4>
		dd offset @$xt$13std@exception ; `__tpdsc__'[std::exception]
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
off_40E414	dd offset unknown_libname_4 ; DATA XREF: operator new(uint)+38o
					; std::bad_alloc::bad_alloc(std::bad_alloc &)+16o ...
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		dd offset sub_402394
		dd offset @$xt$13std@bad_alloc ; `__tpdsc__'[std::bad_alloc]
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
off_40E428	dd offset unknown_libname_5 ; DATA XREF: operator new(uint)+4Do
					; std::bad_alloc::bad_alloc(std::bad_alloc &)+23o ...
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
		dd offset sub_4023A0
stru_40E430	_excInfo <offset @$xt$13std@bad_alloc, 4, -4> ;	DATA XREF: .data:0040E448o
					; `__tpdsc__'[std::bad_alloc]
		dd 0
stru_40E440	_excHdr	<0, -40>	; DATA XREF: unknown_libname_1+6o
					; end of descriptors
		_excData <50000h, 0, offset stru_40E430>
off_40E454	dd offset @$xt$p13std@bad_alloc	; DATA XREF: .data:0040E474o
					; `__tpdsc__'[std::bad_alloc *]
		db    5
		db    0
		db    0
		db    0
		db    8
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0DCh	; ‹
		db 0FFh
		db 0FFh
		db 0FFh
		db    0
		db    0
		db    5
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset off_40E454
off_40E478	dd offset @$xt$13std@bad_alloc ; DATA XREF: .data:0040E490o
					; `__tpdsc__'[std::bad_alloc]
		align 10h
		dd offset dword_410AFC
		align 8
stru_40E488	_excHdr	<0, -36>	; DATA XREF: sub_40241C+6o
		_excData <50000h, 0, offset off_40E478>
stru_40E49C	_excHdr	<0, -36>	; DATA XREF: sub_40245C+6o
dword_40E4A4	dd 0			; DATA XREF: @_virt_reserve+7r
					; @_virt_reserve:loc_4024B0w ...
aBorlndmm	db 'borlndmm',0         ; DATA XREF: .text:004025A4o
aHrdir_b_cLoadl	db 'hrdir_b.c: LoadLibrary != mmdll borlndmm failed',0
					; DATA XREF: .text:004025B6o
; char ModuleName[]
ModuleName	db 'borlndmm',0         ; DATA XREF: ___CRTL_MEM_GetBorMemPtrs:loc_4025E2o
; char ProcName[]
ProcName	db '@Borlndmm@SysGetMem$qqri',0
					; DATA XREF: ___CRTL_MEM_GetBorMemPtrs:loc_4025F6o
; char a[]
a@borlndmm@sysf	db '@Borlndmm@SysFreeMem$qqrpv',0 ; DATA XREF: ___CRTL_MEM_GetBorMemPtrs+3Fo
; char a[]
a@borlndmm@sysr	db '@Borlndmm@SysReallocMem$qqrpvi',0
					; DATA XREF: ___CRTL_MEM_GetBorMemPtrs+4Co
		align 10h
dword_40E540	dd 0			; DATA XREF: .text:loc_402718w
					; __free_heapsr
		db  1Ch
		db    0
		db    0
		db    0
dword_40E548	dd 0			; DATA XREF: ___CRTL_MEM_Revector+41w
dword_40E54C	dd 0			; DATA XREF: ___CRTL_MEM_Revector+34w
off_40E550	dd offset sub_4026C4	; DATA XREF: _free+7r
					; ___CRTL_MEM_Revector+Cw ...
off_40E554	dd offset sub_4026DC	; DATA XREF: _malloc+7r
					; ___CRTL_MEM_Revector+16w ...
off_40E558	dd offset sub_4026F4	; DATA XREF: _realloc+Br
					; ___CRTL_MEM_Revector+20w ...
off_40E55C	dd offset nullsub_5	; DATA XREF: ___CRTL_MEM_Revector+2Aw
					; __free_heaps+9r
dword_40E560	dd 400000h		; DATA XREF: sub_402998+172r
					; sub_402998+17Ar
unk_40E564	db    0			; DATA XREF: sub_402998+9o
		db    0
		db    1
		db    0
dword_40E568	dd 1000h		; DATA XREF: sub_402998:loc_402A15r
					; sub_402998:loc_402A32r ...
		db    0
		db    0
		db  10h
		db    0
dword_40E570	dd 1000h		; DATA XREF: sub_40276C:loc_402789r
					; sub_40276C+25r ...
dword_40E574	dd 20000h		; DATA XREF: sub_402C5C+21r
					; sub_402D7C+F0r
dword_40E578	dd 2000h		; DATA XREF: sub_402C5C:loc_402C85r
					; sub_402D7C:loc_402E74r
dword_40E57C	dd 0			; DATA XREF: sub_4027AC+34r
					; sub_4027AC+46r ...
dword_40E580	dd 0			; DATA XREF: sub_4027AC:loc_402804w
dword_40E584	dd 0			; DATA XREF: sub_40276C+Br
					; sub_40276C+2Er ...
unk_40E588	db    1			; DATA XREF: sub_402EF4+8Eo
					; sub_402EF4+F0o ...
		db    0
		db    0
		db    0
off_40E58C	dd offset unk_40E588	; DATA XREF: sub_402EF4:loc_402F7Ar
		dd offset unk_40E588
off_40E594	dd offset unk_40E588	; DATA XREF: sub_4027AC:loc_402886r
					; sub_402D7C+2Dr ...
dword_40E598	dd 0			; DATA XREF: sub_402998+1Dr
					; sub_402998+2Bw ...
dword_40E59C	dd 0			; DATA XREF: sub_402998+69r
					; sub_402998:loc_402A1Br ...
aCreatingHeapLo	db 'creating heap lock',0 ; DATA XREF: .text:__init_locko
		align 4
off_40E5B4	dd offset @$xt$11_RWSTDMutex ; DATA XREF: .data:0040E5E4o
					; `__tpdsc__'[_RWSTDMutex]
		db    0
		db    0
		db    0
		db    0
		dd offset stru_410B1C
		dd offset @$xt$12std@bad_cast ;	`__tpdsc__'[std::bad_cast]
		align 8
		dd offset dword_410B38
		dd offset @$xt$14std@bad_typeid	; `__tpdsc__'[std::bad_typeid]
		db    0
		db    0
		db    0
		db    0
		dd offset dword_410B3C
		db    0
		db    0
		db    0
		db    0
stru_40E5DC	_excHdr	<0, -36>	; DATA XREF: sub_403464+6o
		_excData <50000h, 0, offset off_40E5B4>
stru_40E5F0	_excHdr	<0, -36>	; DATA XREF: sub_4034D8+6o
		_excData <50000h, 0, 0>
stru_40E604	_excHdr	<0, -36>	; DATA XREF: __rwstd::facet_imp::~facet_imp(void)+6o
stru_40E60C	_excHdr	<0, -36>	; DATA XREF: __rwstd::facet_imp::~facet_imp(void)+6o
		dd offset @$xt$14std@bad_typeid	; `__tpdsc__'[std::bad_typeid]
		align 10h
off_40E620	dd offset @__rwstd@facet_imp@$bdtr$qv ;	DATA XREF: sub_403464+59o
					; sub_404097+5o ...
					; __rwstd::facet_imp::~facet_imp(void)
		dd offset sub_402394
		dd offset @$xt$12std@bad_cast ;	`__tpdsc__'[std::bad_cast]
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
off_40E634	dd offset @__rwstd@facet_imp@$bdtr$qv_0	; DATA XREF: sub_403464+3Bo
					; sub_404097+1Ao
					; __rwstd::facet_imp::~facet_imp(void)
		dd offset sub_402394
off_40E63C	dd offset aNoNamedExcepti ; DATA XREF: sub_402394+3r
					; "no named exception thrown"
		dd offset aBadExceptionTh ; "bad exception thrown"
off_40E644	dd offset aBadAllocExcept ; DATA XREF: sub_4023A0+3r
					; "bad alloc exception thrown"
		dd offset aError_0	; "Error"
		align 10h
off_40E650	dd offset @$xt$11_RWSTDMutex ; DATA XREF: .data:0040E668o
					; `__tpdsc__'[_RWSTDMutex]
		align 8
		dd offset stru_410B40
		align 10h
stru_40E660	_excHdr	<0, -36>	; DATA XREF: unknown_libname_3+6o
		_excData <50000h, 0, offset off_40E650>
stru_40E674	_excHdr	<0, -36>	; DATA XREF: sub_403728+6o
		_excData <50000h, 0, 0>
aNoNamedExcepti	db 'no named exception thrown',0 ; DATA XREF: .data:off_40E63Co
aBadExceptionTh	db 'bad exception thrown',0 ; DATA XREF: .data:0040E640o
aBadAllocExcept	db 'bad alloc exception thrown',0 ; DATA XREF: .data:off_40E644o
aError_0	db 'Error',0            ; DATA XREF: .data:0040E648o
aRwstderr	db 'rwstderr',0
		align 4
stru_40E6E4	_excInfo <offset @$xt$p13std@bad_alloc,	5, 8> ;	DATA XREF: .data:0040E6FCo
					; `__tpdsc__'[std::bad_alloc *]
		dd 0
stru_40E6F4	_excHdr	<0, -36>	; DATA XREF: unknown_libname_5+6o
					; end of descriptors
		_excData <50000h, 0, offset stru_40E6E4>
dword_40E708	dd 0			; DATA XREF: .text:00403BBDr
stru_40E70C	_excHdr	<0, -36>	; DATA XREF: sub_403D3B+8o
aNotype		db '<notype>',0         ; DATA XREF: __typeIDname(tpid *)+Bo
; char aIdTpname[]
aIdTpname	db 'id->tpName',0       ; DATA XREF: __typeIDname(tpid *)+21o
; char aXxtype_cpp_9[]
aXxtype_cpp_9	db 'xxtype.cpp',0       ; DATA XREF: __typeIDname(tpid *)+1Co
; char aTp1[]
aTp1		db 'tp1',0              ; DATA XREF: __isSameTypeID(tpid *,tpid *)+1Ao
; char aXxtype_cpp_10[]
aXxtype_cpp_10	db 'xxtype.cpp',0       ; DATA XREF: __isSameTypeID(tpid *,tpid *)+15o
; char aTp2[]
aTp2		db 'tp2',0              ; DATA XREF: __isSameTypeID(tpid *,tpid *)+35o
; char aXxtype_cpp_11[]
aXxtype_cpp_11	db 'xxtype.cpp',0       ; DATA XREF: __isSameTypeID(tpid *,tpid *)+30o
; char aTp1Tpname[]
aTp1Tpname	db 'tp1->tpName',0      ; DATA XREF: __isSameTypeID(tpid *,tpid *)+8Co
; char aXxtype_cpp_12[]
aXxtype_cpp_12	db 'xxtype.cpp',0       ; DATA XREF: __isSameTypeID(tpid *,tpid *)+87o
; char aTp2Tpname[]
aTp2Tpname	db 'tp2->tpName',0      ; DATA XREF: __isSameTypeID(tpid *,tpid *)+B0o
; char aXxtype_cpp_13[]
aXxtype_cpp_13	db 'xxtype.cpp',0       ; DATA XREF: __isSameTypeID(tpid *,tpid *)+ABo
; char cond[]
cond		db 'IS_STRUC(base->tpMask)',0 ; DATA XREF: unknown_libname_6+1Co
; char file[]
file		db 'xxtype.cpp',0       ; DATA XREF: unknown_libname_6+17o
; char aIs_strucDervTp[]
aIs_strucDervTp	db 'IS_STRUC(derv->tpMask)',0 ; DATA XREF: unknown_libname_6+3Co
; char aXxtype_cpp_0[]
aXxtype_cpp_0	db 'xxtype.cpp',0       ; DATA XREF: unknown_libname_6+37o
; char aDervTpclass_tp[]
aDervTpclass_tp	db 'derv->tpClass.tpcFlags & CF_HAS_BASES',0
					; DATA XREF: unknown_libname_6+5Co
; char aXxtype_cpp_1[]
aXxtype_cpp_1	db 'xxtype.cpp',0       ; DATA XREF: unknown_libname_6+57o
; char aUnsigned__farV[]
aUnsigned__farV	db '((unsigned __far *)vtablePtr)[-1] == 0',0
					; DATA XREF: __GetTypeInfo(void	*,void *,void *)+74o
; char aXxtype_cpp_14[]
aXxtype_cpp_14	db 'xxtype.cpp',0       ; DATA XREF: __GetTypeInfo(void *,void *,void *)+6Fo
aNotype_0	db '<notype>',0         ; DATA XREF: unknown_libname_8+22o
; char aToptypptr0Is_s[]
aToptypptr0Is_s	db 'topTypPtr != 0 && IS_STRUC(topTypPtr->tpMask)',0
					; DATA XREF: sub_403D8E+31o
; char aXxtype_cpp_2[]
aXxtype_cpp_2	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+2Co
; char aTgttypptr0Is_s[]
aTgttypptr0Is_s	db 'tgtTypPtr != 0 && IS_STRUC(tgtTypPtr->tpMask)',0
					; DATA XREF: sub_403D8E+57o
; char aXxtype_cpp_3[]
aXxtype_cpp_3	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+52o
; char aSrctypptr0Is_s[]
aSrctypptr0Is_s	db 'srcTypPtr == 0 || IS_STRUC(srcTypPtr->tpMask)',0
					; DATA XREF: sub_403D8E+7Do
; char aXxtype_cpp_4[]
aXxtype_cpp_4	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+78o
; char a__issametypeid[]
a__issametypeid	db '__isSameTypeID(srcTypPtr, tgtTypPtr) == 0',0 ; DATA XREF: sub_403D8E+ACo
; char aXxtype_cpp_5[]
aXxtype_cpp_5	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+A7o
; char aTgttypptr0[]
aTgttypptr0__is	db 'tgtTypPtr != 0 && __isSameTypeID(topTypPtr, tgtTypPtr) == 0',0
					; DATA XREF: sub_403D8E+F4o
; char aXxtype_cpp_6[]
aXxtype_cpp_6	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+EFo
; char aSrctypptr[]
aSrctypptr	db 'srcTypPtr',0        ; DATA XREF: sub_403D8E+1DFo
; char aXxtype_cpp_7[]
aXxtype_cpp_7	db 'xxtype.cpp',0       ; DATA XREF: sub_403D8E+1DAo
aUnsigned__fa_1	db '((unsigned __far *)vtablePtr)[-1] == 0',0
aXxtype_cpp	db 'xxtype.cpp',0
; char aAddr[]
aAddr		db 'addr',0             ; DATA XREF: sub_403FF5+1Co
; char aXxtype_cpp_8[]
aXxtype_cpp_8	db 'xxtype.cpp',0       ; DATA XREF: sub_403FF5+17o
aCanTAdjustClas	db 'Can',27h,'t adjust class address (no base class entry found)',0
					; DATA XREF: __adjustClassAdr(void *,tpid *,tpid *):loc_4045A8o
; char aCanTAdjustCl_0[]
aCanTAdjustCl_0	db '!"Can',27h,'t adjust class address (no base class entry found)"',0
					; DATA XREF: __adjustClassAdr(void *,tpid *,tpid *)+67o
; char aXxtype_cpp_15[]
aXxtype_cpp_15	db 'xxtype.cpp',0       ; DATA XREF: __adjustClassAdr(void *,tpid *,tpid *)+62o
		align 4
stru_40EA2C	_excHdr	<0, -36>	; DATA XREF: __GetTypeInfo(void	*,void *,void *)+6o
		dd offset @$xt$14type_info_hash	; `__tpdsc__'[type_info_hash]
		align 10h
off_40EA40	dd offset @std@bad_typeid@$bdtr$qv
					; DATA XREF: __GetTypeInfo(void	*,void *,void *)+EFo
					; std::bad_typeid::~bad_typeid(void)
		dd offset @$xt$13std@type_info ; `__tpdsc__'[std::type_info]
		align 10h
off_40EA50	dd offset unknown_libname_7 ; DATA XREF: unknown_libname_7+Ao
					; __GetTypeInfo(void *,void *,void *)+DCo
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
dword_40EA54	dd 0			; DATA XREF: _InitTermAndUnexPtrs(void)r
					; _InitTermAndUnexPtrs(void)+9w ...
dword_40EA58	dd 0			; DATA XREF: _InitTermAndUnexPtrs(void):loc_4046AFr
					; _InitTermAndUnexPtrs(void)+1Cw ...
stru_40EA5C	_excInfo2 <0, 0, offset	loc_4046F8, 0, 0> ; DATA XREF: .data:0040EA84o
stru_40EA7C	_excHdr	<0, -36>	; DATA XREF: std::terminate(void)+6o
		_excData2 <30000h, offset stru_40EA5C, 40000h>
unk_40EA90	db    0			; DATA XREF: __GetExceptDLLinfoInternal+1Do
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
dword_40EAA4	dd 0			; DATA XREF: __GetExceptDLLinfoInternal+12w
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
; size_t size
size		dd 9Ch			; DATA XREF: __thread_data_new+61r
					; __thread_data_new:loc_40AD10r
a___cppdebughoo	db '___CPPdebugHook',0  ; DATA XREF: .text:loc_40473Co
stru_40EB40	_excInfo2 <0, 0, offset	loc_4047BE, 0, 0> ; DATA XREF: .data:0040EB68o
stru_40EB60	_excHdr	<0, -36>	; DATA XREF: ___call_terminate+6o
		_excData2 <30000h, offset stru_40EB40, 40000h>
dword_40EB74	dd 0			; DATA XREF: sub_404894+44r
; char aStackOverflow[]
aStackOverflow	db 'Stack Overflow!',0  ; DATA XREF: sub_404894+4Do
off_40EB88	dd offset unknown_libname_10 ; DATA XREF: __init_handles:loc_405D27w
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
dword_40EB8C	dd 0FFFFFFFFh		; DATA XREF: ___open+A0r
dword_40EB90	dd 0			; DATA XREF: __initfileinfo+Cw
					; .data:0040D078o
; FILE stru_40EB94
stru_40EB94	FILE <0, 0, 0, 0, 0, 209h, 0, 0, 0> ; DATA XREF: __flushall+10o
					; __flushout+11o ...
unk_40EBAC	db    0			; DATA XREF: _printf+4o _printf+1Bo ...
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  0Ah
		db    2
		db    0
		db    0
		db    1
		db    0
; FILE stru_40EBC4
stru_40EBC4	FILE <0, 0, 0, 0, 0, 202h, 0, 2, 0> ; DATA XREF: sub_401304+13o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
; UINT uNumber[]
uNumber		dd 32h			; DATA XREF: ___close+Ar ___eof+9r ...
unk_40F048	db    0			; DATA XREF: ___close+48w ___eof+22r ...
byte_40F049	db 60h			; DATA XREF: ___read+41r ___read+66r ...
byte_40F04A	db 0			; DATA XREF: ___close+22r
		align 4
		db    1
		db  60h	; `
		db    0
		db    0
		db    1
		db  60h	; `
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
unk_40F110	db    0			; DATA XREF: .data:0040D05Co
					; .data:off_40F114o
		db  40h	; @
		db    0
		db    0
off_40F114	dd offset unk_40F110	; DATA XREF: ___open+14r
					; __initfmode+6w ...
dword_40F118	dd 0			; DATA XREF: __cleanup_handle_locks:loc_405A9Cw
					; __unlock_handle+35r
; char aAllocatingHand[]
aAllocatingHand	db 'allocating handle lock table',0 ; DATA XREF: __lock_handle+3Eo
; char aCreatingHandle[]
aCreatingHandle	db 'creating handle lock',0 ; DATA XREF: __lock_handle+66o
; char aHlocks[]
aHlocks		db 'hlocks',0           ; DATA XREF: __unlock_handle+16o
; char aHandles_c[]
aHandles_c	db 'handles.c',0        ; DATA XREF: __unlock_handle+11o
; char aCreatingGlob_0[]
aCreatingGlob_0	db 'creating global handle lock',0 ; DATA XREF: __init_handles+6o
		align 4
byte_40F17C	db 0			; DATA XREF: ___IOerror+1Fr
		db  13h
		db    2
		db    2
		db    4
		db    5
		db    6
		db    8
		db    8
		db    8
		db  14h
		db  15h
		db  13h
		db  13h
		db  0Eh
		db    2
		db    5
		db  16h
		db    2
		db  1Eh
		db  29h	; )
		db  2Ch	; ,
		db  28h	; (
		db  28h	; (
		db  28h	; (
		db  28h	; (
		db  28h	; (
		db  29h	; )
		db  2Ch	; ,
		db  28h	; (
		db  28h	; (
		db  28h	; (
		db    5
		db    5
		db  29h	; )
		db  17h
		db  17h
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Fh
		db  2Ch	; ,
		db  23h	; #
		db    2
		db  2Ch	; ,
		db  0Fh
		db  2Ah	; *
		db  28h	; (
		db  28h	; (
		db  28h	; (
		db  13h
		db  1Bh
		db  1Ch
		db    2
		db    2
		db    5
		db  0Fh
		db    2
		db  17h
		db  28h	; (
		db  2Ah	; *
		db  13h
		db  2Ah	; *
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  0Eh
		db  23h	; #
		db  0Eh
		db    5
		db    5
		db  17h
		db  23h	; #
		db  25h	; %
		db  13h
		db  28h	; (
		db  2Ah	; *
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  2Ch	; ,
		db  2Ah	; *
		db  2Ah	; *
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  16h
		db    5
		db  20h
		db    2
		db  13h
		db  1Ch
		db    4
		db    6
		db  0Eh
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db    2
		db  13h
		db  13h
		db  13h
		db  26h	; &
		db  18h
		db  18h
		db    6
		db  13h
		db    5
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  2Ah	; *
		db  13h
		db  13h
		db  31h	; 1
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db    5
		db  13h
		db  13h
		db    2
		db  13h
		db  13h
		db  2Ah	; *
		db  13h
		db  13h
		db    5
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  23h	; #
		db  18h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db    2
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  2Ah	; *
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  20h
		db  2Ah	; *
		db  13h
		db  20h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  13h
		db  90h	; ê
; char aTmp[]
aTmp		db 'TMP',0              ; DATA XREF: ___mkname+23o
; char src[]
src		db '.$$$',0             ; DATA XREF: ___mkname+44o
		align 4
		dd offset aError0	; "Error 0"
		dd offset aInvalidFunctio ; "Invalid function number"
		dd offset aNoSuchFileOrDi ; "No	such file or directory"
		dd offset aPathNotFound	; "Path	not found"
		dd offset aTooManyOpenFil ; "Too many open files"
		dd offset aPermissionDeni ; "Permission	denied"
		dd offset aBadFileNumber ; "Bad	file number"
		dd offset aMemoryArenaTra ; "Memory arena trashed"
		dd offset aNotEnoughMemor ; "Not enough	memory"
		dd offset aInvalidMemoryB ; "Invalid memory block address"
		dd offset aInvalidEnviron ; "Invalid environment"
		dd offset aInvalidFormat ; "Invalid format"
		dd offset aInvalidAccessC ; "Invalid access code"
		dd offset aInvalidData	; "Invalid data"
		dd offset aBadAddress	; "Bad address"
		dd offset aNoSuchDevice	; "No such device"
		dd offset aAttemptedToRem ; "Attempted to remove current directory"
		dd offset aNotSameDevice ; "Not	same device"
		dd offset aNoMoreFiles	; "No more files"
		dd offset aInvalidArgumen ; "Invalid argument"
		dd offset aArgListTooBig ; "Arg	list too big"
		dd offset aExecFormatErro ; "Exec format error"
		dd offset aCrossDeviceLin ; "Cross-device link"
		dd offset aTooManyOpenF_0 ; "Too many open files"
		dd offset aNoChildProcess ; "No	child processes"
		dd offset aInappropriateI ; "Inappropriate I/O control operation"
		dd offset aExecutableFile ; "Executable	file in	use"
		dd offset aFileTooLarge	; "File	too large"
		dd offset aNoSpaceLeftOnD ; "No	space left on device"
		dd offset aIllegalSeek	; "Illegal seek"
		dd offset aReadOnlyFileSy ; "Read-only file system"
		dd offset aTooManyLinks	; "Too many links"
		dd offset aBrokenPipe	; "Broken pipe"
		dd offset aMathArgument	; "Math	argument"
		dd offset aResultTooLarge ; "Result too	large"
		dd offset aFileAlreadyExi ; "File already exists"
		dd offset aPossibleDeadlo ; "Possible deadlock"
		dd offset aOperationNotPe ; "Operation not permitted"
		dd offset aNoSuchProcess ; "No such process"
		dd offset aInterruptedFun ; "Interrupted function call"
		dd offset aInputOutputErr ; "Input/output error"
		dd offset aNoSuchDeviceOr ; "No	such device or address"
		dd offset aResourceTempor ; "Resource temporarily unavailable"
		dd offset aBlockDeviceReq ; "Block device required"
		dd offset aResourceBusy	; "Resource busy"
		dd offset aNotADirectory ; "Not	a directory"
		dd offset aIsADirectory	; "Is a	directory"
		dd offset unk_40F707
		dd offset aDirectoryNotEm ; "Directory not empty"
dword_40F378	dd 31h			; DATA XREF: ___IOerror+2Cr
aError0		db 'Error 0',0          ; DATA XREF: .data:0040F2B4o
aInvalidFunctio	db 'Invalid function number',0 ; DATA XREF: .data:0040F2B8o
aNoSuchFileOrDi	db 'No such file or directory',0 ; DATA XREF: .data:0040F2BCo
aPathNotFound	db 'Path not found',0   ; DATA XREF: .data:0040F2C0o
aTooManyOpenFil	db 'Too many open files',0 ; DATA XREF: .data:0040F2C4o
aPermissionDeni	db 'Permission denied',0 ; DATA XREF: .data:0040F2C8o
aBadFileNumber	db 'Bad file number',0  ; DATA XREF: .data:0040F2CCo
aMemoryArenaTra	db 'Memory arena trashed',0 ; DATA XREF: .data:0040F2D0o
aNotEnoughMemor	db 'Not enough memory',0 ; DATA XREF: .data:0040F2D4o
aInvalidMemoryB	db 'Invalid memory block address',0 ; DATA XREF: .data:0040F2D8o
aInvalidEnviron	db 'Invalid environment',0 ; DATA XREF: .data:0040F2DCo
aInvalidFormat	db 'Invalid format',0   ; DATA XREF: .data:0040F2E0o
aInvalidAccessC	db 'Invalid access code',0 ; DATA XREF: .data:0040F2E4o
aInvalidData	db 'Invalid data',0     ; DATA XREF: .data:0040F2E8o
aBadAddress	db 'Bad address',0      ; DATA XREF: .data:0040F2ECo
aNoSuchDevice	db 'No such device',0   ; DATA XREF: .data:0040F2F0o
aAttemptedToRem	db 'Attempted to remove current directory',0 ; DATA XREF: .data:0040F2F4o
aNotSameDevice	db 'Not same device',0  ; DATA XREF: .data:0040F2F8o
aNoMoreFiles	db 'No more files',0    ; DATA XREF: .data:0040F2FCo
aInvalidArgumen	db 'Invalid argument',0 ; DATA XREF: .data:0040F300o
aArgListTooBig	db 'Arg list too big',0 ; DATA XREF: .data:0040F304o
aExecFormatErro	db 'Exec format error',0 ; DATA XREF: .data:0040F308o
aCrossDeviceLin	db 'Cross-device link',0 ; DATA XREF: .data:0040F30Co
aTooManyOpenF_0	db 'Too many open files',0 ; DATA XREF: .data:0040F310o
aNoChildProcess	db 'No child processes',0 ; DATA XREF: .data:0040F314o
aInappropriateI	db 'Inappropriate I/O control operation',0 ; DATA XREF: .data:0040F318o
aExecutableFile	db 'Executable file in use',0 ; DATA XREF: .data:0040F31Co
aFileTooLarge	db 'File too large',0   ; DATA XREF: .data:0040F320o
aNoSpaceLeftOnD	db 'No space left on device',0 ; DATA XREF: .data:0040F324o
aIllegalSeek	db 'Illegal seek',0     ; DATA XREF: .data:0040F328o
aReadOnlyFileSy	db 'Read-only file system',0 ; DATA XREF: .data:0040F32Co
aTooManyLinks	db 'Too many links',0   ; DATA XREF: .data:0040F330o
aBrokenPipe	db 'Broken pipe',0      ; DATA XREF: .data:0040F334o
aMathArgument	db 'Math argument',0    ; DATA XREF: .data:0040F338o
aResultTooLarge	db 'Result too large',0 ; DATA XREF: .data:0040F33Co
aFileAlreadyExi	db 'File already exists',0 ; DATA XREF: .data:0040F340o
aPossibleDeadlo	db 'Possible deadlock',0 ; DATA XREF: .data:0040F344o
aOperationNotPe	db 'Operation not permitted',0 ; DATA XREF: .data:0040F348o
aNoSuchProcess	db 'No such process',0  ; DATA XREF: .data:0040F34Co
aInterruptedFun	db 'Interrupted function call',0 ; DATA XREF: .data:0040F350o
aInputOutputErr	db 'Input/output error',0 ; DATA XREF: .data:0040F354o
aNoSuchDeviceOr	db 'No such device or address',0 ; DATA XREF: .data:0040F358o
aResourceTempor	db 'Resource temporarily unavailable',0 ; DATA XREF: .data:0040F35Co
aBlockDeviceReq	db 'Block device required',0 ; DATA XREF: .data:0040F360o
aResourceBusy	db 'Resource busy',0    ; DATA XREF: .data:0040F364o
aNotADirectory	db 'Not a directory',0  ; DATA XREF: .data:0040F368o
aIsADirectory	db 'Is a directory',0   ; DATA XREF: .data:0040F36Co
unk_40F707	db    0			; DATA XREF: .data:0040F370o
aDirectoryNotEm	db 'Directory not empty',0 ; DATA XREF: .data:0040F374o
aUnknownError	db 'Unknown error',0
		db ': ',0
		db 0Ah,0
		align 10h
dword_40F730	dd 0			; DATA XREF: __cleanup_stream_locks:loc_406504w
					; __unlock_stream+44r
; char aCreatingGlobal[]
aCreatingGlobal	db 'creating global stream lock',0 ; DATA XREF: __init_streams+6o
; char aAllocatingStre[]
aAllocatingStre	db 'allocating stream lock table',0 ; DATA XREF: __lock_stream+4Eo
; char aCreatingStream[]
aCreatingStream	db 'creating stream lock',0 ; DATA XREF: __lock_stream+76o
; char aStrm_locks[]
aStrm_locks	db 'strm_locks',0       ; DATA XREF: __unlock_stream+16o
; char aStreams_c[]
aStreams_c	db 'streams.c',0        ; DATA XREF: __unlock_stream+11o
		align 4
aNull_0		db '(null)',0           ; DATA XREF: ___vprinter+5BDo
		align 10h
aNull:					; DATA XREF: ___vprinter+59Co
		unicode	0, <(null)>,0
byte_40F7AE	db 0			; DATA XREF: ___vprinter+E0r
		db  16h
		db  16h
		db    1
		db  16h
		db  17h
		db  16h
		db  16h
		db  16h
		db  16h
		db    2
		db    0
		db  16h
		db    3
		db    4
		db  16h
		db    9
		db    5
		db    5
		db    5
		db    5
		db    5
		db    5
		db    5
		db    5
		db    5
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  12h
		db  16h
		db  0Fh
		db  19h
		db  0Fh
		db    8
		db  1Ah
		db  16h
		db  16h
		db    7
		db  16h
		db  18h
		db  16h
		db  16h
		db  16h
		db  16h
		db  13h
		db  16h
		db  16h
		db  16h
		db  16h
		db  0Dh
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  10h
		db  0Ah
		db  0Fh
		db  0Fh
		db  0Fh
		db    8
		db  0Ah
		db  16h
		db  16h
		db    6
		db  16h
		db  14h
		db  0Bh
		db  0Eh
		db  16h
		db  16h
		db  11h
		db  16h
		db  0Ch
		db  16h
		db  16h
		db  0Dh
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  16h
		db  90h	; ê
		db  90h	; ê
		db    0
		db    0
word_40F812	dw 20h			; DATA XREF: ___isctype+29r
					; ___iswctype+2Er
		unicode	0, <	    (((((		   H>
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  84h	; Ñ
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  81h	; Å
		db    1
		db  81h	; Å
		db    1
		db  81h	; Å
		db    1
		db  81h	; Å
		db    1
		db  81h	; Å
		db    1
		db  81h	; Å
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db    1
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  82h	; Ç
		db    1
		db  82h	; Ç
		db    1
		db  82h	; Ç
		db    1
		db  82h	; Ç
		db    1
		db  82h	; Ç
		db    1
		db  82h	; Ç
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db    2
		db    1
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  10h
		db    0
		db  20h
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  90h	; ê
		db  90h	; ê
unk_40FA14	db    2			; DATA XREF: .data:0040FB38o
		db    0
		db    2
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset unk_40FB54
		dd offset unk_40FB55
		dd offset unk_40FB57
		dd offset unk_40FB58
		dd offset unk_40FB59
		dd offset unk_40FB5A
		dd offset unk_40FB5B
		dd offset aV		; "($v)"
off_40FA48	dd offset unk_40FB62	; DATA XREF: .data:0040FB3Co
		dd offset a_		; "."
		dd offset unk_40FB65
		dd offset unk_40FB66
		dd offset asc_40FB67	; "-"
		db    2
		db    0
		db    0
		db    0
off_40FA60	dd offset asc_40FB69	; DATA XREF: .data:0040FB44o
					; "/"
		dd offset asc_40FB6B	; ":"
		dd offset aHMS		; "%H:%M:%S"
		dd offset aMDY		; "%m/%d/%y"
		dd offset aABDY		; "%A, %B %d, %Y"
		dd offset aAm		; "AM"
		dd offset aPm		; "PM"
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset aMonday	; "Monday"
		dd offset aTuesday	; "Tuesday"
		dd offset aWednesday	; "Wednesday"
		dd offset aThursday	; "Thursday"
		dd offset aFriday	; "Friday"
		dd offset aSaturday	; "Saturday"
		dd offset aSunday	; "Sunday"
		dd offset aMon		; "Mon"
		dd offset aTue		; "Tue"
		dd offset aWed		; "Wed"
		dd offset aThu		; "Thu"
		dd offset aFri		; "Fri"
		dd offset aSat		; "Sat"
		dd offset aSun		; "Sun"
		dd offset aJanuary	; "January"
		dd offset aFebruary	; "February"
		dd offset aMarch	; "March"
		dd offset aApril	; "April"
		dd offset aMay		; "May"
		dd offset aJune		; "June"
		dd offset aJuly		; "July"
		dd offset aAugust	; "August"
		dd offset aSeptember	; "September"
		dd offset aOctober	; "October"
		dd offset aNovember	; "November"
		dd offset aDecember	; "December"
		dd offset aJan		; "Jan"
		dd offset aFeb		; "Feb"
		dd offset aMar		; "Mar"
		dd offset aApr		; "Apr"
		dd offset aMay_0	; "May"
		dd offset aJun		; "Jun"
		dd offset aJul		; "Jul"
		dd offset aAug		; "Aug"
		dd offset aSep		; "Sep"
		dd offset aOct		; "Oct"
		dd offset aNov		; "Nov"
		dd offset aDec		; "Dec"
unk_40FB24	db    0			; DATA XREF: .data:off_40FB50o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    1
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		dd offset unk_40FA14
		dd offset off_40FA48
		db    0
		db    0
		db    0
		db    0
		dd offset off_40FA60
		dd offset aC		; "C"
		dd offset aC_0		; "C"
off_40FB50	dd offset unk_40FB24	; DATA XREF: __getLocaleNumericInfo+3r
					; ___isctype:loc_4072BDr ...
unk_40FB54	db    0			; DATA XREF: .data:0040FA28o
unk_40FB55	db  2Eh	; .		; DATA XREF: .data:0040FA2Co
		db    0
unk_40FB57	db    0			; DATA XREF: .data:0040FA30o
unk_40FB58	db    0			; DATA XREF: .data:0040FA34o
unk_40FB59	db    0			; DATA XREF: .data:0040FA38o
unk_40FB5A	db    0			; DATA XREF: .data:0040FA3Co
unk_40FB5B	db  2Dh	; -		; DATA XREF: .data:0040FA40o
		db    0
aV		db '($v)',0             ; DATA XREF: .data:0040FA44o
unk_40FB62	db    0			; DATA XREF: .data:off_40FA48o
a_		db '.',0                ; DATA XREF: .data:0040FA4Co
unk_40FB65	db    0			; DATA XREF: .data:0040FA50o
unk_40FB66	db    0			; DATA XREF: .data:0040FA54o
asc_40FB67	db '-',0                ; DATA XREF: .data:0040FA58o
asc_40FB69	db '/',0                ; DATA XREF: .data:off_40FA60o
asc_40FB6B	db ':',0                ; DATA XREF: .data:0040FA64o
aHMS		db '%H:%M:%S',0         ; DATA XREF: .data:0040FA68o
aMDY		db '%m/%d/%y',0         ; DATA XREF: .data:0040FA6Co
aABDY		db '%A, %B %d, %Y',0    ; DATA XREF: .data:0040FA70o
aAm		db 'AM',0               ; DATA XREF: .data:0040FA74o
aPm		db 'PM',0               ; DATA XREF: .data:0040FA78o
aMonday		db 'Monday',0           ; DATA XREF: .data:0040FA8Co
aTuesday	db 'Tuesday',0          ; DATA XREF: .data:0040FA90o
aWednesday	db 'Wednesday',0        ; DATA XREF: .data:0040FA94o
aThursday	db 'Thursday',0         ; DATA XREF: .data:0040FA98o
aFriday		db 'Friday',0           ; DATA XREF: .data:0040FA9Co
aSaturday	db 'Saturday',0         ; DATA XREF: .data:0040FAA0o
aSunday		db 'Sunday',0           ; DATA XREF: .data:0040FAA4o
aMon		db 'Mon',0              ; DATA XREF: .data:0040FAA8o
aTue		db 'Tue',0              ; DATA XREF: .data:0040FAACo
aWed		db 'Wed',0              ; DATA XREF: .data:0040FAB0o
aThu		db 'Thu',0              ; DATA XREF: .data:0040FAB4o
aFri		db 'Fri',0              ; DATA XREF: .data:0040FAB8o
aSat		db 'Sat',0              ; DATA XREF: .data:0040FABCo
aSun		db 'Sun',0              ; DATA XREF: .data:0040FAC0o
aJanuary	db 'January',0          ; DATA XREF: .data:0040FAC4o
aFebruary	db 'February',0         ; DATA XREF: .data:0040FAC8o
aMarch		db 'March',0            ; DATA XREF: .data:0040FACCo
aApril		db 'April',0            ; DATA XREF: .data:0040FAD0o
aMay		db 'May',0              ; DATA XREF: .data:0040FAD4o
aJune		db 'June',0             ; DATA XREF: .data:0040FAD8o
aJuly		db 'July',0             ; DATA XREF: .data:0040FADCo
aAugust		db 'August',0           ; DATA XREF: .data:0040FAE0o
aSeptember	db 'September',0        ; DATA XREF: .data:0040FAE4o
aOctober	db 'October',0          ; DATA XREF: .data:0040FAE8o
aNovember	db 'November',0         ; DATA XREF: .data:0040FAECo
aDecember	db 'December',0         ; DATA XREF: .data:0040FAF0o
aJan		db 'Jan',0              ; DATA XREF: .data:0040FAF4o
aFeb		db 'Feb',0              ; DATA XREF: .data:0040FAF8o
aMar		db 'Mar',0              ; DATA XREF: .data:0040FAFCo
aApr		db 'Apr',0              ; DATA XREF: .data:0040FB00o
aMay_0		db 'May',0              ; DATA XREF: .data:0040FB04o
aJun		db 'Jun',0              ; DATA XREF: .data:0040FB08o
aJul		db 'Jul',0              ; DATA XREF: .data:0040FB0Co
aAug		db 'Aug',0              ; DATA XREF: .data:0040FB10o
aSep		db 'Sep',0              ; DATA XREF: .data:0040FB14o
aOct		db 'Oct',0              ; DATA XREF: .data:0040FB18o
aNov		db 'Nov',0              ; DATA XREF: .data:0040FB1Co
aDec		db 'Dec',0              ; DATA XREF: .data:0040FB20o
aC		db 'C',0                ; DATA XREF: .data:0040FB48o
aC_0:					; DATA XREF: .data:0040FB4Co
		unicode	0, <C>,0
dword_40FC74	dd 0			; DATA XREF: __pow10+57r
dword_40FC78	dd 80000000h		; DATA XREF: __pow10+61r
word_40FC7C	dw 3FFFh		; DATA XREF: __pow10+6Br
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0A0h	; †
		db    2
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0C8h	; »
		db    5
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0FAh	; ˙
		db    8
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  40h	; @
		db  9Ch	; ú
		db  0Ch
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  50h	; P
		db 0C3h	; √
		db  0Fh
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  24h	; $
		db 0F4h	; Ù
		db  12h
		db  40h	; @
		db    0
		db    0
		db    0
		db    0
		db    0
		db  80h	; Ä
		db  96h	; ñ
		db  98h	; ò
		db  16h
		db  40h	; @
tbyte_40FCC4	dt 1.0e8		; DATA XREF: __pow10+79r
		align 10h
tbyte_40FCD0	dt 1.0e16		; DATA XREF: __pow10+96r
unk_40FCDA	db  9Eh	; û		; DATA XREF: __pow10+ABo
		db 0B5h	; µ
		db  70h	; p
		db  2Bh	; +
		db 0A8h	; ®
		db 0ADh	; ≠
		db 0C5h	; ≈
		db  9Dh	; ù
		db  69h	; i
		db  40h	; @
unk_40FCE4	db 0D5h	; ’		; DATA XREF: __pow10+C1o
		db 0A6h	; ¶
		db 0CFh	; œ
		db 0FFh
		db  49h	; I
		db  1Fh
		db  78h	; x
		db 0C2h	; ¬
		db 0D3h	; ”
		db  40h	; @
unk_40FCEE	db 0E0h	; ‡		; DATA XREF: __pow10+D7o
		db  8Ch	; å
		db 0E9h	; È
		db  80h	; Ä
		db 0C9h	; …
		db  47h	; G
		db 0BAh	; ∫
		db  93h	; ì
		db 0A8h	; ®
		db  41h	; A
unk_40FCF8	db  8Eh	; é		; DATA XREF: __pow10+EDo
		db 0DEh	; ﬁ
		db 0F9h	; ˘
		db  9Dh	; ù
		db 0FBh	; ˚
		db 0EBh	; Î
		db  7Eh	; ~
		db 0AAh	; ™
		db  51h	; Q
		db  43h	; C
unk_40FD02	db 0C7h	; «		; DATA XREF: __pow10+103o
		db  91h	; ë
		db  0Eh
		db 0A6h	; ¶
		db 0AEh	; Æ
		db 0A0h	; †
		db  19h
		db 0E3h	; „
		db 0A3h	; £
		db  46h	; F
unk_40FD0C	db  17h			; DATA XREF: __pow10+119o
		db  0Ch
		db  75h	; u
		db  81h	; Å
		db  86h	; Ü
		db  75h	; u
		db  76h	; v
		db 0C9h	; …
		db  48h	; H
		db  4Dh	; M
unk_40FD16	db 0E5h	; Â		; DATA XREF: __pow10+12Fo
		db  5Dh	; ]
		db  3Dh	; =
		db 0C5h	; ≈
		db  5Dh	; ]
		db  3Bh	; ;
		db  8Bh	; ã
		db  9Eh	; û
		db  92h	; í
		db  5Ah	; Z
unk_40FD20	db  9Bh	; õ		; DATA XREF: __pow10+145o
		db  97h	; ó
		db  20h
		db  8Ah	; ä
		db    2
		db  52h	; R
		db  60h	; `
		db 0C4h	; ƒ
		db  25h	; %
		db  75h	; u
unk_40FD2A	db    0			; DATA XREF: __pow10+25o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  80h	; Ä
		db 0FFh
		db  7Fh	; 
off_40FD34	dd offset loc_407C70	; DATA XREF: sub_407C58r
					; .text:__cvt_initw
; int (*off_40FD38)(void)
off_40FD38	dd offset loc_407C70	; DATA XREF: sub_407C5Er
					; .text:004083AEw
off_40FD3C	dd offset unknown_libname_14 ; DATA XREF: sub_407C5E+6r
					; .text:loc_408BBCw
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
off_40FD40	dd offset unknown_libname_14 ; DATA XREF: sub_407C5E+Cr
					; .text:00408BC6w
					; BCC v4.x/5.x & BCB v1.0/v7.0 BDS2006 win32 runtime
; char aPrintfFloating[]
aPrintfFloating	db 'printf : floating point formats not linked',0
					; DATA XREF: sub_407C5E:loc_407C70o
; char aScanfFloatingP[]
aScanfFloatingP	db 'scanf : floating point formats not linked',0
					; DATA XREF: unknown_libname_14o
		align 4
off_40FD9C	dd offset sub_407C88	; DATA XREF: .text:__cvt_initww
off_40FDA0	dd offset sub_407C88	; DATA XREF: .text:004086E2w
off_40FDA4	dd offset sub_407C94	; DATA XREF: .text:__scan_initww
off_40FDA8	dd offset sub_407C94	; DATA XREF: .text:004090A6w
; char aPrintfFloati_0[]
aPrintfFloati_0	db 'printf : floating point formats not linked',0 ; DATA XREF: sub_407C88o
; char aScanfFloatin_0[]
aScanfFloatin_0	db 'scanf : floating point formats not linked',0 ; DATA XREF: sub_407C94o
		align 4
; unsigned int newcw
newcw		dd 1332h		; DATA XREF: __control87+12w
					; __fpreset+7r	...
		db    0
		db    0
		db  80h	; Ä
		db  7Fh	; 
; int dword_40FE0C
dword_40FE0C	dd 0			; DATA XREF: sub_408B3C+1Br
					; sub_40901C+1Br
; int dword_40FE10
dword_40FE10	dd 7FF00000h		; DATA XREF: sub_408B3C+15r
					; sub_40901C+15r
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  80h	; Ä
		db 0FFh
		db  7Fh	; 
		db 0FFh
		db 0FFh
		db  7Fh	; 
		db  7Fh	; 
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0EFh	; Ô
		db  7Fh	; 
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FFh
		db 0FEh	; ˛
		db  7Fh	; 
		db    0
		db    0
		db 0C0h	; ¿
		db  7Fh	; 
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  80h	; Ä
		db    1
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db  7Fh	; 
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db 0FFh
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db 0F8h	; ¯
		db  7Fh	; 
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db 0F8h	; ¯
		db 0FFh
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db 0F0h	; 
		db  7Fh	; 
		db    0
		db    0
		db    0
		db    0
		db    0
		db 0F0h	; 
		db 0F0h	; 
		db 0FFh
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  80h	; Ä
unk_40FE84	db    0			; DATA XREF: .data:0040D086o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
off_40FE8C	dd offset __matherr	; DATA XREF: __initmatherr+9w
off_40FE90	dd offset __matherrl	; DATA XREF: __initmatherr+Ew
aInf		db '-INF',0             ; DATA XREF: sub_408104+8Do
aInf_0		db '+INF',0             ; DATA XREF: sub_408104:loc_408198o
aNan		db '-NAN',0             ; DATA XREF: sub_408104+CDo
aNan_0		db '+NAN',0             ; DATA XREF: sub_408104:loc_4081D8o
; wchar_t aInf_1
aInf_1:					; DATA XREF: sub_408408+95o
		unicode	0, <-INF>,0
asc_40FEB2	db '+',0                ; DATA XREF: sub_408408:loc_4084A4o
aInf_2:
		unicode	0, <INF>,0
; wchar_t aNan_1
aNan_1:					; DATA XREF: sub_408408+BEo
		unicode	0, <-NAN>,0
asc_40FEC6	db '+',0                ; DATA XREF: sub_408408:loc_4084CDo
		dd offset aNoSpaceForComm+22h
		db  4Eh	; N
		db    0
		db    0
		db    0
stru_40FED0	db 4 dup(0)		; DATA XREF: sub_4086F0:loc_408A97o
					; sub_408B3C:loc_408B8Eo
		dd 80000000h		; anonymous_0
		dw 7FFFh		; anonymous_1
stru_40FEDA	db 4 dup(0)		; DATA XREF: sub_4086F0+38Ao
		dd 80000000h		; anonymous_0
		dw 0FFFFh		; anonymous_1
stru_40FEE4	db 1, 3	dup(0)		; DATA XREF: sub_4086F0:loc_408B15o
		dd 0C0000000h		; anonymous_0
		dw 7FFFh		; anonymous_1
stru_40FEEE	db 1, 3	dup(0)		; DATA XREF: sub_4086F0+408o
		dd 0C0000000h		; anonymous_0
		dw 0FFFFh		; anonymous_1
stru_40FEF8	db 4 dup(0)		; DATA XREF: sub_408BD4:loc_408F78o
					; sub_40901C:loc_40906Eo
		dd 80000000h		; anonymous_0
		dw 7FFFh		; anonymous_1
stru_40FF02	db 4 dup(0)		; DATA XREF: sub_408BD4+387o
		dd 80000000h		; anonymous_0
		dw 0FFFFh		; anonymous_1
stru_40FF0C	db 1, 3	dup(0)		; DATA XREF: sub_408BD4:loc_408FF6o
		dd 0C0000000h		; anonymous_0
		dw 7FFFh		; anonymous_1
stru_40FF16	db 1, 3	dup(0)		; DATA XREF: sub_408BD4+405o
		dd 0C0000000h		; anonymous_0
		dw 0FFFFh		; anonymous_1
byte_40FF20	db 0A6h			; DATA XREF: __setmbcp+CCr
byte_40FF21	db 0DFh			; DATA XREF: __setmbcp+E0r
byte_40FF22	db 0A1h			; DATA XREF: __setmbcp+ECr
byte_40FF23	db 0A5h			; DATA XREF: __setmbcp+100r
; char Buffer[]
Buffer		db 'Error: system code page access failure; MBCS table not initialize'
					; DATA XREF: __setmbcp+45o
		db 'd',0
		align 4
aAssertionFaile	db 'Assertion failed: ',0 ; DATA XREF: __assert+17o
aFile		db ', file ',0          ; DATA XREF: __assert+Eo
aLine		db ', line ',0          ; DATA XREF: __assert+5o
		align 4
; char a02d02d04d02d02[]
a02d02d04d02d02	db '%02d/%02d/%04d %02d:%02d:%02d.%03d ',0 ; DATA XREF: sub_4098D4+33o
dword_40FFB0	dd 0			; DATA XREF: __ErrorMessage+1Br
					; __ErrorMessage:loc_409ADEr ...
; LPCSTR lpFileName
lpFileName	dd 0			; DATA XREF: __ErrorMessage+9r
					; __ErrorMessage:loc_409AF8r ...
unk_40FFB8	db  0Dh			; DATA XREF: __ErrorMessage+A5o
		db  0Ah
		db    0
unk_40FFBB	db  0Dh			; DATA XREF: __ErrorMessage+CDo
		db  0Ah
		db    0
		db    0
		db    0
; char aKernel32_dll[]
aKernel32_dll	db 'kernel32.dll',0     ; DATA XREF: unknown_libname_18+7o
; char aGetprocaddress[]
aGetprocaddress	db 'GetProcAddress',0   ; DATA XREF: unknown_libname_18+13o
aBorland32	db 'Borland32',0        ; DATA XREF: unknown_libname_18+1Eo
		align 4
; char aAbnormalProgra[]
aAbnormalProgra	db 'Abnormal program termination',0 ; DATA XREF: __aborto
		align 4
dword_410008	dd 0			; DATA XREF: sub_409BFC+10r
					; sub_409BFC+19r ...
off_41000C	dd offset nullsub_4	; DATA XREF: __allocbuf+3Cw
					; sub_409BFC+24r
off_410010	dd offset nullsub_4	; DATA XREF: sub_40561C:loc_4056D8w
					; sub_409BFC+3Dr
off_410014	dd offset nullsub_4	; DATA XREF: sub_409BFC+43r
off_410018	dd offset __handle_setargv ; DATA XREF:	__init_setargv_handlers+9w
					; __setargv+3Fr
off_41001C	dd offset __handle_exitargv ; DATA XREF: __init_setargv_handlers+Ew
					; __exitargvr
off_410020	dd offset __handle_wsetargv ; DATA XREF: __init_setargv_handlers+1Aw
off_410024	dd offset __handle_wexitargv ; DATA XREF: __init_setargv_handlers+20w
unk_410028	db    0			; DATA XREF: .data:0040D07Eo
		db    0
		db    0
		db    0
; char aNoSpaceForComm[]
aNoSpaceForComm	db 'No space for command line argument vector',0 ; DATA XREF: sub_409DE0+3Fo
; char aNoSpaceForCo_0[]
aNoSpaceForCo_0	db 'No space for command line argument',0 ; DATA XREF: sub_409DE0+65o
		align 4
dword_41007C	dd 0			; DATA XREF: sub_40A004:loc_40A026r
					; sub_40A228:loc_40A24Dr
; char aNoSpaceForCopy[]
aNoSpaceForCopy	db 'No space for copy of command line',0 ; DATA XREF: __handle_setargv+86o
		align 4
; char aNoSpaceForCo_1[]
aNoSpaceForCo_1	db 'No space for copy of command line',0 ; DATA XREF: __handle_wsetargv+A0o
		align 4
off_4100C8	dd offset __argv_default_expand	; DATA XREF: __init_wild_handlers+Bw
					; __handle_setargv+121r ...
off_4100CC	dd offset __argv_default_expand_0 ; DATA XREF: __init_wild_handlers+13w
					; __handle_wsetargv+159r ...
; LPSTR	lpFilename
lpFilename	dd 0			; DATA XREF: __setargv+1Er
					; unknown_libname_19+Ew ...
; char aOutOfMemoryIn_[]
aOutOfMemoryIn_	db 'Out of memory in _setargv0',0 ; DATA XREF: unknown_libname_19+18o
		align 10h
unk_4100F0	db    0			; DATA XREF: .data:0040D082o
		db    0
		db    0
		db    0
; char aGetenvironment[]
aGetenvironment	db 'GetEnvironmentStrings failed',0 ; DATA XREF: __expandblock+25o
aCouldNotAlloca	db 'Could not allocate memory for environment block',0
					; DATA XREF: .text:0040A491o
aCreatingEnviro	db 'creating environment lock',0 ; DATA XREF: .text:0040A4A7o
		align 4
byte_41015C	db 0			; DATA XREF: _signal+6r _signal+28w
		align 10h
unk_410160	db    0			; DATA XREF: _signal:loc_40A751o
					; _raise:loc_40A7C3o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
dword_410188	dd 2			; DATA XREF: sub_40A4BC+5o
					; sub_40A4DC+1C1r ...
		db    4
		db    0
		db    0
		db    0
		db    8
		db    0
		db    0
		db    0
		db  0Bh
		db    0
		db    0
		db    0
		db  0Fh
		db    0
		db    0
		db    0
		db  10h
		db    0
		db    0
		db    0
		db  11h
		db    0
		db    0
		db    0
		db  14h
		db    0
		db    0
		db    0
		db  15h
		db    0
		db    0
		db    0
		db  16h
		db    0
		db    0
		db    0
byte_4101B0	db 0			; DATA XREF: _raise+7Er
		db  15h
		db  8Ch	; å
		db  0Bh
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db  90h	; ê
		db  90h	; ê
dword_4101BC	dd 1			; DATA XREF: __init_handles+135r
					; __init_handles+144r ...
dword_4101C0	dd 0			; DATA XREF: __cleanup+3r __cleanup+Cw
aCreatingAtexit	db 'creating atexit lock',0 ; DATA XREF: .text:loc_40A9BCo
		align 4
aCreatingThread	db 'creating thread data lock',0 ; DATA XREF: .text:loc_40AD6Co
		align 4
aSemaphoreError	db 'Semaphore error ',0 ; DATA XREF: __lock_error+8o
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
stru_410210	_excInfo2 <0, 0, offset	loc_40B504, 0, 0> ; DATA XREF: .data:00410238o
stru_410230	_excHdr	<0, -36>	; DATA XREF: sub_40B308+6o
		_excData2 <30000h, offset stru_410210, 40000h>
stru_410244	_excInfo2 <0, 0, offset	loc_40B68C, 0, 0> ; DATA XREF: .data:0041026Co
stru_410264	_excHdr	<0, -36>	; DATA XREF: sub_40B637+6o
		_excData2 <30000h, offset stru_410244, 40000h>
stru_410278	_excInfo2 <0, 0, offset	loc_40C0F5, 0, 0> ; DATA XREF: .data:004102CCo
stru_410298	_excInfo2 <0, 0, offset	loc_40C10D, 0, 0> ; DATA XREF: .data:004102C0o
stru_4102B8	_excHdr	<0, -36>	; DATA XREF: sub_40C035+6o
		_excData2 <30000h, offset stru_410298, 40000h>
		_excData2 <30008h, offset stru_410278, 40008h>
a___cppdebugh_0	db '___CPPdebugHook',0  ; DATA XREF: .text:loc_40AF08o
; char aCtormask0x0100[]
aCtormask0x0100	db '(ctorMask & 0x0100) != 0 || (ctorMask & 0x0020) == 0',0
					; DATA XREF: sub_40B077+23o
; char aXx_cpp[]
aXx_cpp		db 'xx.cpp',0           ; DATA XREF: sub_40B077+1Eo
; char aCtormask0x0080[]
aCtormask0x0080	db '(ctorMask & 0x0080) == 0',0 ; DATA XREF: sub_40B077+3Fo
; char aXx_cpp_0[]
aXx_cpp_0	db 'xx.cpp',0           ; DATA XREF: sub_40B077+3Ao
aWhat?		db 'what?',0            ; DATA XREF: sub_40B077:loc_40B10Ao
; char aWhat?_0[]
aWhat?_0	db '!"what?"',0         ; DATA XREF: sub_40B077+A6o
; char aXx_cpp_1[]
aXx_cpp_1	db 'xx.cpp',0           ; DATA XREF: sub_40B077+A1o
aWhat?_1	db 'what?',0            ; DATA XREF: sub_40B077:loc_40B160o
; char aWhat?_2[]
aWhat?_2	db '!"what?"',0         ; DATA XREF: sub_40B077+FCo
; char aXx_cpp_2[]
aXx_cpp_2	db 'xx.cpp',0           ; DATA XREF: sub_40B077+F7o
; char aDtormask0x0080[]
aDtormask0x0080	db '(dtorMask & 0x0080) == 0',0 ; DATA XREF: sub_40B1BA+63o
; char aXx_cpp_3[]
aXx_cpp_3	db 'xx.cpp',0           ; DATA XREF: sub_40B1BA+5Eo
aWhat?_3	db 'what?',0            ; DATA XREF: sub_40B1BA:loc_40B265o
; char aWhat?_4[]
aWhat?_4	db '!"what?"',0         ; DATA XREF: sub_40B1BA+BEo
; char aXx_cpp_4[]
aXx_cpp_4	db 'xx.cpp',0           ; DATA XREF: sub_40B1BA+B9o
; char aMfnmask0x00800[]
aMfnmask0x00800	db '(mfnMask & 0x0080) == 0',0 ; DATA XREF: sub_40B28A+16o
; char aXx_cpp_5[]
aXx_cpp_5	db 'xx.cpp',0           ; DATA XREF: sub_40B28A+11o
aWhat?_5	db 'what?',0            ; DATA XREF: sub_40B28A:loc_40B2E5o
; char aWhat?_6[]
aWhat?_6	db '!"what?"',0         ; DATA XREF: sub_40B28A+6Eo
; char aXx_cpp_6[]
aXx_cpp_6	db 'xx.cpp',0           ; DATA XREF: sub_40B28A+69o
; char aCctraddr[]
aCctraddr	db 'cctrAddr',0         ; DATA XREF: sub_40B308+1C0o
; char aXx_cpp_7[]
aXx_cpp_7	db 'xx.cpp',0           ; DATA XREF: sub_40B308+1BBo
; char aDtoraddr[]
aDtoraddr	db 'dtorAddr',0         ; DATA XREF: sub_40B637+24o
; char aXx_cpp_8[]
aXx_cpp_8	db 'xx.cpp',0           ; DATA XREF: sub_40B637+1Fo
; char aArgtype[]
aArgtype	db 'argType',0          ; DATA XREF: sub_40B6AC+53o
; char aXx_cpp_9[]
aXx_cpp_9	db 'xx.cpp',0           ; DATA XREF: sub_40B6AC+4Eo
; char a__cppexception[]
a__cppexception	db '__CPPexceptionList',0 ; DATA XREF: _CatchCleanup(void)+2Ao
; char aXx_cpp_10[]
aXx_cpp_10	db 'xx.cpp',0           ; DATA XREF: _CatchCleanup(void)+25o
; char aXl[]
aXl		db 'xl',0               ; DATA XREF: _CatchCleanup(void)+69o
; char aXx_cpp_11[]
aXx_cpp_11	db 'xx.cpp',0           ; DATA XREF: _CatchCleanup(void)+64o
; char aXdrptrXderradd[]
aXdrptrXderradd	db 'xdrPtr->xdERRaddr == xl',0 ; DATA XREF: _CatchCleanup(void)+85o
; char aXx_cpp_12[]
aXx_cpp_12	db 'xx.cpp',0           ; DATA XREF: _CatchCleanup(void)+80o
; char aDscptrXderradd[]
aDscptrXderradd	db 'dscPtr->xdERRaddr == errPtr',0 ; DATA XREF: sub_40B825+1Eo
; char aXx_cpp_13[]
aXx_cpp_13	db 'xx.cpp',0           ; DATA XREF: sub_40B825+19o
; char aDscptrXdhtabad[]
aDscptrXdhtabad	db 'dscPtr->xdHtabAdr == hdtPtr',0 ; DATA XREF: sub_40B825+3Do
; char aXx_cpp_14[]
aXx_cpp_14	db 'xx.cpp',0           ; DATA XREF: sub_40B825+38o
; char aDscptrXdargcop[]
aDscptrXdargcop	db 'dscPtr->xdArgCopy == 0',0 ; DATA XREF: sub_40B825+5Ao
; char aXx_cpp_15[]
aXx_cpp_15	db 'xx.cpp',0           ; DATA XREF: sub_40B825+55o
; char aDscptrXdmaskTm[]
aDscptrXdmaskTm	db '(dscPtr->xdMask & TM_IS_PTR) == 0',0 ; DATA XREF: sub_40B825+10Do
; char aXx_cpp_16[]
aXx_cpp_16	db 'xx.cpp',0           ; DATA XREF: sub_40B825+108o
; char aMaskTm_is_ptr[]
aMaskTm_is_ptr	db 'mask & TM_IS_PTR',0 ; DATA XREF: sub_40B825+131o
; char aXx_cpp_17[]
aXx_cpp_17	db 'xx.cpp',0           ; DATA XREF: sub_40B825+12Co
; char aDscptrXdmask_0[]
aDscptrXdmask_0	db 'dscPtr->xdMask & TM_IS_PTR',0 ; DATA XREF: sub_40B825+14Eo
; char aXx_cpp_18[]
aXx_cpp_18	db 'xx.cpp',0           ; DATA XREF: sub_40B825+149o
; char aDscptrXdtypeid[]
aDscptrXdtypeid	db 'dscPtr->xdTypeID == dscPtr->xdBase',0 ; DATA XREF: sub_40B825+1CBo
; char aXx_cpp_19[]
aXx_cpp_19	db 'xx.cpp',0           ; DATA XREF: sub_40B825+1C6o
; char aHdtptrHdcctrad[]
aHdtptrHdcctrad	db 'hdtPtr->HDcctrAddr',0 ; DATA XREF: sub_40B825+21Ao
; char aXx_cpp_20[]
aXx_cpp_20	db 'xx.cpp',0           ; DATA XREF: sub_40B825+215o
; char aDscptrXdsizeSi[]
aDscptrXdsizeSi	db 'dscPtr->xdSize == size',0 ; DATA XREF: sub_40B825+287o
; char aXx_cpp_21[]
aXx_cpp_21	db 'xx.cpp',0           ; DATA XREF: sub_40B825+282o
; char aXdrptrXdrptrXd[]
aXdrptrXdrptrXd	db 'xdrPtr && xdrPtr == *xdrLPP',0 ; DATA XREF: sub_40BAF9+ECo
; char aXx_cpp_22[]
aXx_cpp_22	db 'xx.cpp',0           ; DATA XREF: sub_40BAF9+E7o
aBogusContextIn	db 'bogus context in Local_unwind()',0 ; DATA XREF: sub_40BAF9:loc_40BC2Eo
; char aBogusContext_0[]
aBogusContext_0	db '!"bogus context in Local_unwind()"',0 ; DATA XREF: sub_40BAF9+148o
; char aXx_cpp_23[]
aXx_cpp_23	db 'xx.cpp',0           ; DATA XREF: sub_40BAF9+143o
aBogusContext_1	db 'bogus context in _ExceptionHandler()',0
					; DATA XREF: ____ExceptionHandler:loc_40BFFEo
; char aBogusContext_2[]
aBogusContext_2	db '!"bogus context in _ExceptionHandler()"',0
					; DATA XREF: ____ExceptionHandler+339o
; char aXx_cpp_24[]
aXx_cpp_24	db 'xx.cpp',0           ; DATA XREF: ____ExceptionHandler+334o
; char aVartypeTpclass[]
aVartypeTpclass	db 'varType->tpClass.tpcFlags & CF_HAS_DTOR',0 ; DATA XREF: sub_40C035+2Co
; char aXx_cpp_25[]
aXx_cpp_25	db 'xx.cpp',0           ; DATA XREF: sub_40C035+27o
; char aVartypeTpcla_0[]
aVartypeTpcla_0	db 'varType->tpClass.tpcDtorAddr',0 ; DATA XREF: sub_40C035+49o
; char aXx_cpp_26[]
aXx_cpp_26	db 'xx.cpp',0           ; DATA XREF: sub_40C035+44o
; char aErrptrErrcinit[]
aErrptrErrcinit	db '(errPtr->ERRcInitDtc >= varType->tpClass.tpcDtorCount) || flags',0
					; DATA XREF: sub_40C035+7Bo
; char aXx_cpp_27[]
aXx_cpp_27	db 'xx.cpp',0           ; DATA XREF: sub_40C035+76o
; char aVartypeTpcla_1[]
aVartypeTpcla_1	db 'varType->tpClass.tpcFlags & CF_HAS_DTOR',0 ; DATA XREF: sub_40C177+1Fo
; char aXx_cpp_28[]
aXx_cpp_28	db 'xx.cpp',0           ; DATA XREF: sub_40C177+1Ao
; char aDtorcntVarcoun[]
aDtorcntVarcoun	db 'dtorCnt < varCount',0 ; DATA XREF: sub_40C177+72o
; char aXx_cpp_29[]
aXx_cpp_29	db 'xx.cpp',0           ; DATA XREF: sub_40C177+6Do
; char aIs_strucBltype[]
aIs_strucBltype	db 'IS_STRUC(blType->tpMask)',0 ; DATA XREF: sub_40C177+B0o
; char aXx_cpp_30[]
aXx_cpp_30	db 'xx.cpp',0           ; DATA XREF: sub_40C177+ABo
; char aIs_strucBlty_0[]
aIs_strucBlty_0	db 'IS_STRUC(blType->tpMask)',0 ; DATA XREF: sub_40C177+125o
; char aXx_cpp_31[]
aXx_cpp_31	db 'xx.cpp',0           ; DATA XREF: sub_40C177+120o
; char aMemtype[]
aMemtype	db 'memType',0          ; DATA XREF: sub_40C177+1B5o
; char aXx_cpp_32[]
aXx_cpp_32	db 'xx.cpp',0           ; DATA XREF: sub_40C177+1B0o
; char aMemtypeTpclass[]
aMemtypeTpclass	db 'memType->tpClass.tpcFlags & CF_HAS_DTOR',0 ; DATA XREF: sub_40C177+1E8o
; char aXx_cpp_33[]
aXx_cpp_33	db 'xx.cpp',0           ; DATA XREF: sub_40C177+1E3o
; char aVartypeTpmaskT[]
aVartypeTpmaskT	db 'varType->tpMask & TM_IS_ARRAY',0 ; DATA XREF: sub_40C427+1Fo
; char aXx_cpp_34[]
aXx_cpp_34	db 'xx.cpp',0           ; DATA XREF: sub_40C427+1Ao
; char aVartypeTparr_t[]
aVartypeTparr_t	db 'varType->tpArr.tpaElemType->tpClass.tpcFlags & CF_HAS_DTOR',0
					; DATA XREF: sub_40C427+3Fo
; char aXx_cpp_35[]
aXx_cpp_35	db 'xx.cpp',0           ; DATA XREF: sub_40C427+3Ao
; char aVdtcount[]
aVdtcount	db 'vdtCount',0         ; DATA XREF: sub_40C427+66o
; char aXx_cpp_36[]
aXx_cpp_36	db 'xx.cpp',0           ; DATA XREF: sub_40C427+61o
; char aEtdcountElemco[]
aEtdcountElemco	db 'etdCount <= elemCount || elemCount == 0',0 ; DATA XREF: sub_40C427+A3o
; char aXx_cpp_37[]
aXx_cpp_37	db 'xx.cpp',0           ; DATA XREF: sub_40C427+9Eo
; char aDtrcountVdtcou[]
aDtrcountVdtcou	db 'dtrCount <= vdtCount',0 ; DATA XREF: sub_40C427+C7o
; char aXx_cpp_38[]
aXx_cpp_38	db 'xx.cpp',0           ; DATA XREF: sub_40C427+C2o
; char aIs_classVartyp[]
aIs_classVartyp	db 'IS_CLASS(varType->tpMask)',0 ; DATA XREF: sub_40C54B+1Eo
; char aXx_cpp_39[]
aXx_cpp_39	db 'xx.cpp',0           ; DATA XREF: sub_40C54B+19o
; char aUnsigned__fa_0[]
aUnsigned__fa_0	db '((unsigned __far *)vftAddr)[-1] == 0',0 ; DATA XREF: sub_40C54B+6Eo
; char aXx_cpp_40[]
aXx_cpp_40	db 'xx.cpp',0           ; DATA XREF: sub_40C54B+69o
; char aDttptrDttflags[]
aDttptrDttflags	db 'dttPtr->dttFlags & (DTCVF_PTRVAL|DTCVF_RETVAL)',0
					; DATA XREF: sub_40C5D2+46o
; char aXx_cpp_41[]
aXx_cpp_41	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+41o
; char aDttptrDtttypeT[]
aDttptrDtttypeT	db 'dttPtr->dttType->tpMask & TM_IS_PTR',0 ; DATA XREF: sub_40C5D2+68o
; char aXx_cpp_42[]
aXx_cpp_42	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+63o
; char aDttptrDtttyp_0[]
aDttptrDtttyp_0	db 'dttPtr->dttType->tpPtr.tppBaseType->tpClass.tpcFlags & CF_HAS_DTO'
					; DATA XREF: sub_40C5D2+8Do
		db 'R',0
; char aXx_cpp_43[]
aXx_cpp_43	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+88o
; char aIs_classDttptr[]
aIs_classDttptr	db 'IS_CLASS(dttPtr->dttType->tpMask) && (dttPtr->dttType->tpClass.tp'
					; DATA XREF: sub_40C5D2+D1o
		db 'cFlags & CF_HAS_DTOR)',0
; char aXx_cpp_44[]
aXx_cpp_44	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+CCo
; char aDtvtptrDtttype[]
aDtvtptrDtttype	db 'dtvtPtr->dttType->tpMask & TM_IS_ARRAY',0 ; DATA XREF: sub_40C5D2+142o
; char aXx_cpp_45[]
aXx_cpp_45	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+13Do
; char aVartypeTpcla_2[]
aVartypeTpcla_2	db 'varType->tpClass.tpcFlags & CF_HAS_DTOR',0 ; DATA XREF: sub_40C5D2+1A6o
; char aXx_cpp_46[]
aXx_cpp_46	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+1A1o
; char aElemtypeTpclas[]
aElemtypeTpclas	db 'elemType->tpClass.tpcFlags & CF_HAS_DTOR',0 ; DATA XREF: sub_40C5D2+21Ao
; char aXx_cpp_47[]
aXx_cpp_47	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+215o
; char aVartypeTpmas_0[]
aVartypeTpmas_0	db 'varType->tpMask & TM_IS_ARRAY',0 ; DATA XREF: sub_40C5D2+277o
; char aXx_cpp_48[]
aXx_cpp_48	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+272o
; char aVartypeTpmas_1[]
aVartypeTpmas_1	db 'varType->tpMask & TM_IS_PTR',0 ; DATA XREF: sub_40C5D2+2AEo
; char aXx_cpp_49[]
aXx_cpp_49	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+2A9o
; char aBl[]
aBl		db 'bl',0               ; DATA XREF: sub_40C5D2+352o
; char aXx_cpp_50[]
aXx_cpp_50	db 'xx.cpp',0           ; DATA XREF: sub_40C5D2+34Do
aBccxh1		db '**BCCxh1',0         ; DATA XREF: __CurrExcContext+35o
; FILE *stream
stream		dd 0			; DATA XREF: _main+114w _main+119r ...
; FILE *dword_410A9C
dword_410A9C	dd 0			; DATA XREF: sub_401230+Ar _main+14Bw	...
; FILE *dword_410AA0
dword_410AA0	dd 0			; DATA XREF: sub_40124C+Ar _main+1B7w	...
unk_410AA4	db    0			; DATA XREF: _main+175o _main+194o ...
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
dword_410AF4	dd 0			; DATA XREF: sub_4016EC+A2r
					; sub_401800+87r ...
dword_410AF8	dd 0			; DATA XREF: std::set_new_handler(void (*)(void))+3r
					; std::set_new_handler(void (*)(void))+Bw ...
dword_410AFC	dd 0			; DATA XREF: sub_40241C+21w
					; sub_40241C+2Cw ...
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
dword_410B14	dd 0			; DATA XREF: .text:004025AEr
; LPCRITICAL_SECTION lpCriticalSection
lpCriticalSection dd 0			; DATA XREF: .text:0040273Do
					; __lock_heapr	...
; struct _RTL_CRITICAL_SECTION stru_410B1C
stru_410B1C	_RTL_CRITICAL_SECTION <0> ; DATA XREF: sub_403464+16o
					; sub_4034D8+48o ...
dword_410B34	dd 0			; DATA XREF: sub_403464+2Cw
					; sub_4034D8+3Dr ...
dword_410B38	dd 0			; DATA XREF: sub_403464+40w
					; sub_403464+46w ...
dword_410B3C	dd 0			; DATA XREF: sub_403464+54w
					; sub_403464+5Ew ...
; struct _RTL_CRITICAL_SECTION stru_410B40
stru_410B40	_RTL_CRITICAL_SECTION <0> ; DATA XREF: unknown_libname_3+16o
					; sub_403728+1Eo ...
dword_410B58	dd 0			; DATA XREF: unknown_libname_3+20w
					; sub_403728+13r ...
dword_410B5C	dd 0			; DATA XREF: sub_404097+Aw
					; sub_404097+Fw ...
; int dword_410B60[]
dword_410B60	dd 28h dup(0), 0D8h dup(?) ; DATA XREF:	sub_403D3B:loc_403D4Fr
					; __GetTypeInfo(void *,void *,void *)+9Ar ...
dword_410F60	dd ?			; DATA XREF: sub_404097+1Fw
					; sub_404097+25w ...
		align 8
dword_410F68	dd ?			; DATA XREF: .text:0040474Ew
					; .text:00404753r ...
; int (__cdecl *dword_410F6C)(_DWORD, _DWORD, _DWORD, _DWORD)
dword_410F6C	dd ?			; DATA XREF: sub_404894:loc_40490Dr
					; sub_404894+89r ...
; int (__cdecl *dword_410F70)(_DWORD, _DWORD, _DWORD, _DWORD)
dword_410F70	dd ?			; DATA XREF: sub_404894:loc_4048ECr
					; sub_404894+68r ...
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
; HANDLE hObject
hObject		dd ?			; DATA XREF: ___close+36r ___close+4Fw ...
dword_411040	dd ?			; DATA XREF: __init_handles+112w
dword_411044	dd ?			; DATA XREF: __init_handles+11Ew
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
; LPCRITICAL_SECTION dword_411104
dword_411104	dd ?			; DATA XREF: __lock_all_handlesr
					; __unlock_all_handlesr ...
; void *block
block		dd ?			; DATA XREF: __cleanup_handle_locksr
					; __cleanup_handle_locks+12w ...
byte_41110C	db ?			; DATA XREF: unknown_libname_12+26w
					; unknown_libname_12+7Bw ...
		align 10h
; LPCRITICAL_SECTION dword_411110
dword_411110	dd ?			; DATA XREF: __init_streams+Bo
					; __lock_all_streamsr ...
; void *dword_411114
dword_411114	dd ?			; DATA XREF: __lock_stream+18r
					; __lock_stream+2Cr ...
unk_411118	db    ?	;		; DATA XREF: __setmbcp+5Ao
dword_411119	dd ?			; DATA XREF: ___vprinter+64r
					; _mblen+1Er ...
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
dword_41121C	dd ?			; DATA XREF: __setmbcp:loc_409786w
					; __setmbcp+114w ...
; char s[]
s		db 100h	dup(?)		; DATA XREF: __assert+21o __assert+2Eo ...
; char byte_411320[]
byte_411320	db 1Ch dup(?)		; DATA XREF: sub_4098D4+38o
					; sub_4098D4+45o
dword_41133C	dd ?			; DATA XREF: @_virt_reserve+10r
					; unknown_libname_18+2Aw ...
; void *dword_411340
dword_411340	dd ?			; DATA XREF: __setargv+18w
					; __setargv+64w ...
dword_411344	dd ?			; DATA XREF: __setargv+Ew
					; sub_409DE0+Er ...
; void *dword_411348
dword_411348	dd ?			; DATA XREF: __setargv+2Dw
					; __exitargv+Fr
; void *dword_41134C
dword_41134C	dd ?			; DATA XREF: __handle_setargv+79w
					; __handle_exitargvr ...
; void *dword_411350
dword_411350	dd ?			; DATA XREF: __handle_wsetargv+93w
					; __handle_wexitargvr ...
; void *dword_411354
dword_411354	dd ?			; DATA XREF: .text:loc_40A318r
					; .text:0040A332w ...
; char *dword_411358
dword_411358	dd ?			; DATA XREF: .text:loc_40A308r
					; .text:0040A32Cw ...
dword_41135C	dd ?			; DATA XREF: __expandblock+A6w
dword_411360	dd ?			; DATA XREF: .text:__lock_envr
					; .text:__unlock_envr ...
dword_411364	dd ?			; DATA XREF: __setargv+75w
					; __startup+169r
dword_411368	dd ?			; DATA XREF: __setargv+80w
					; __startup+162r
dword_41136C	dd ?			; DATA XREF: .text:0040A4A2w
					; __startup:loc_40AB2Br
dword_411370	dd ?			; DATA XREF: __setargv+1r
					; __setargv+38r ...
; char *dword_411374
dword_411374	dd ?			; DATA XREF: __expandblock+Er
					; __expandblock+1Cw ...
dword_411378	dd ?			; DATA XREF: __setargv+13w
					; __setargv+58w ...
unk_41137C	db    ?	;		; DATA XREF: __cleanup+27o
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
dword_411384	dd ?			; DATA XREF: .text:loc_4049E4r
					; sub_4049F8r ...
		align 10h
; LPCRITICAL_SECTION dword_411390
dword_411390	dd ?			; DATA XREF: __lock_exitr
					; __unlock_exitr ...
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
dword_41139C	dd ?			; DATA XREF: __cleanup+18o
					; __startup+40w ...
dword_4113A0	dd ?			; DATA XREF: __startup+4Aw
		align 8
; void *dword_4113A8
dword_4113A8	dd ?			; DATA XREF: __thread_data_new+Dr
					; __thread_data_new+19w ...
; LPCRITICAL_SECTION dword_4113AC
dword_4113AC	dd ?			; DATA XREF: __thread_data_new+1r
					; __thread_data_new:loc_40AD24r ...
; struct _RTL_CRITICAL_SECTION CriticalSection
CriticalSection	_RTL_CRITICAL_SECTION <?> ; DATA XREF: __create_lock+3o
					; __create_lock+2Fo ...
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
		db    ?	;
dword_4143B0	dd ?			; DATA XREF: __create_lock+Dr
					; __create_lock:loc_40AE53r ...
dword_4143B4	dd ?			; DATA XREF: sub_40B308:loc_40B4D5r
					; sub_40B308+20Fw ...
dword_4143B8	dd ?			; DATA XREF: sub_404894:loc_40492Er
					; sub_404894+A3r ...
dword_4143BC	dd ?			; DATA XREF: sub_40BAF9+77w
					; sub_40BAF9+93o
dword_4143C0	dd ?			; DATA XREF: ____ExceptionHandler+2ACw
					; ____ExceptionHandler+2C2o
		align 1000h
_data		ends

; Section 3. (virtual address 00015000)
; Virtual size			: 00001000 (   4096.)
; Section size in file		: 00000200 (	512.)
; Offset to raw	data for section: 0000FE00
; Flags	C0000040: Data Readable	Writable
; Alignment	: default
; ===========================================================================

; Segment type:	Pure data
; Segment permissions: Read/Write
_tls		segment	para public 'DATA' use32
		assume cs:_tls
		;org 415000h
TlsStart	db    0			; DATA XREF: .rdata:TlsDirectoryo
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
TlsEnd		db    0			; DATA XREF: .rdata:TlsEnd_ptro
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		db    0
		align 1000h
_tls		ends

; Section 4. (virtual address 00016000)
; Virtual size			: 00001000 (   4096.)
; Section size in file		: 00000200 (	512.)
; Offset to raw	data for section: 00010000
; Flags	50000040: Data Shareable Readable
; Alignment	: default
; ===========================================================================

; Segment type:	Pure data
; Segment permissions: Read
_rdata		segment	para public 'DATA' use32
		assume cs:_rdata
		;org 416000h
TlsDirectory	dd offset TlsStart
TlsEnd_ptr	dd offset TlsEnd
TlsIndex_ptr	dd offset TlsIndex
TlsCallbacks_ptr dd offset TlsSizeOfZeroFill
TlsSizeOfZeroFill dd 0			; DATA XREF: .rdata:TlsCallbacks_ptro
TlsCharacteristics dd 0
		align 1000h
_rdata		ends

;
; Imports from KERNEL32.DLL
;
; Section 5. (virtual address 00017000)
; Virtual size			: 00001000 (   4096.)
; Section size in file		: 00000600 (   1536.)
; Offset to raw	data for section: 00010200
; Flags	40000040: Data Readable
; Alignment	: default
; ===========================================================================

; Segment type:	Externs
; _idata
; BOOL __stdcall CloseHandle(HANDLE hObject)
		extrn __imp_CloseHandle:dword ;	DATA XREF: CloseHandler
; HANDLE __stdcall CreateFileA(LPCSTR lpFileName, DWORD	dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE	hTemplateFile)
		extrn __imp_CreateFileA:dword ;	DATA XREF: CreateFileAr
; void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
		extrn __imp_DeleteCriticalSection:dword	; DATA XREF: DeleteCriticalSectionr
; BOOL __stdcall DeleteFileA(LPCSTR lpFileName)
		extrn __imp_DeleteFileA:dword ;	DATA XREF: DeleteFileAr
; void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
		extrn __imp_EnterCriticalSection:dword ; DATA XREF: EnterCriticalSectionr
; void __stdcall ExitProcess(UINT uExitCode)
		extrn __imp_ExitProcess:dword ;	DATA XREF: ExitProcessr
; UINT GetACP(void)
		extrn __imp_GetACP:dword ; DATA	XREF: GetACPr
; BOOL __stdcall GetCPInfo(UINT	CodePage, LPCPINFO lpCPInfo)
		extrn __imp_GetCPInfo:dword ; DATA XREF: GetCPInfor
; LPSTR	GetCommandLineA(void)
		extrn __imp_GetCommandLineA:dword ; DATA XREF: GetCommandLineAr
; DWORD	GetCurrentThreadId(void)
		extrn __imp_GetCurrentThreadId:dword ; DATA XREF: GetCurrentThreadIdr
; LPSTR	GetEnvironmentStrings(void)
		extrn __imp_GetEnvironmentStrings:dword	; DATA XREF: GetEnvironmentStringsr
; DWORD	__stdcall GetFileAttributesA(LPCSTR lpFileName)
		extrn __imp_GetFileAttributesA:dword ; DATA XREF: GetFileAttributesAr
; DWORD	__stdcall GetFileType(HANDLE hFile)
		extrn __imp_GetFileType:dword ;	DATA XREF: GetFileTyper
; DWORD	GetLastError(void)
		extrn __imp_GetLastError:dword ; DATA XREF: GetLastErrorr
; void __stdcall GetLocalTime(LPSYSTEMTIME lpSystemTime)
		extrn __imp_GetLocalTime:dword ; DATA XREF: GetLocalTimer
; DWORD	__stdcall GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename,	DWORD nSize)
		extrn __imp_GetModuleFileNameA:dword ; DATA XREF: GetModuleFileNameAr
; HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)
		extrn __imp_GetModuleHandleA:dword ; DATA XREF:	GetModuleHandleAr
; UINT GetOEMCP(void)
		extrn __imp_GetOEMCP:dword ; DATA XREF:	GetOEMCPr
; FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
		extrn __imp_GetProcAddress:dword ; DATA	XREF: GetProcAddressr
; HANDLE GetProcessHeap(void)
		extrn __imp_GetProcessHeap:dword ; DATA	XREF: GetProcessHeapr
; void __stdcall GetStartupInfoA(LPSTARTUPINFOA	lpStartupInfo)
		extrn __imp_GetStartupInfoA:dword ; DATA XREF: GetStartupInfoAr
; HANDLE __stdcall GetStdHandle(DWORD nStdHandle)
		extrn __imp_GetStdHandle:dword ; DATA XREF: GetStdHandler
; BOOL __stdcall GetStringTypeW(DWORD dwInfoType, LPCWSTR lpSrcStr, int	cchSrc,	LPWORD lpCharType)
		extrn __imp_GetStringTypeW:dword ; DATA	XREF: GetStringTypeWr
; DWORD	GetVersion(void)
		extrn __imp_GetVersion:dword ; DATA XREF: GetVersionr
; BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA	lpVersionInformation)
		extrn __imp_GetVersionExA:dword	; DATA XREF: GetVersionExAr
; void __stdcall GlobalMemoryStatus(LPMEMORYSTATUS lpBuffer)
		extrn __imp_GlobalMemoryStatus:dword ; DATA XREF: GlobalMemoryStatusr
; LPVOID __stdcall HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
		extrn __imp_HeapAlloc:dword ; DATA XREF: HeapAllocr
; BOOL __stdcall HeapFree(HANDLE hHeap,	DWORD dwFlags, LPVOID lpMem)
		extrn __imp_HeapFree:dword ; DATA XREF:	HeapFreer
; void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
		extrn __imp_InitializeCriticalSection:dword
					; DATA XREF: InitializeCriticalSectionr
; void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
		extrn __imp_LeaveCriticalSection:dword ; DATA XREF: LeaveCriticalSectionr
; HMODULE __stdcall LoadLibraryA(LPCSTR	lpLibFileName)
		extrn __imp_LoadLibraryA:dword ; DATA XREF: LoadLibraryAr
; int __stdcall	MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr,	int cchWideChar)
		extrn __imp_MultiByteToWideChar:dword ;	DATA XREF: MultiByteToWideCharr
; void __stdcall RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
		extrn __imp_RaiseException:dword ; DATA	XREF: RaiseExceptionr
; BOOL __stdcall ReadFile(HANDLE hFile,	LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
		extrn __imp_ReadFile:dword ; DATA XREF:	ReadFiler
		extrn __imp_RtlUnwind:dword ; DATA XREF: RtlUnwindr
; BOOL __stdcall SetConsoleCtrlHandler(PHANDLER_ROUTINE	HandlerRoutine,	BOOL Add)
		extrn __imp_SetConsoleCtrlHandler:dword	; DATA XREF: SetConsoleCtrlHandlerr
; DWORD	__stdcall SetFilePointer(HANDLE	hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
		extrn __imp_SetFilePointer:dword ; DATA	XREF: SetFilePointerr
; UINT __stdcall SetHandleCount(UINT uNumber)
		extrn __imp_SetHandleCount:dword ; DATA	XREF: SetHandleCountr
; void __stdcall SetLastError(DWORD dwErrCode)
		extrn __imp_SetLastError:dword ; DATA XREF: SetLastErrorr
; DWORD	TlsAlloc(void)
		extrn __imp_TlsAlloc:dword ; DATA XREF:	TlsAllocr
; BOOL __stdcall TlsFree(DWORD dwTlsIndex)
		extrn __imp_TlsFree:dword ; DATA XREF: TlsFreer
; LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)
		extrn __imp_TlsGetValue:dword ;	DATA XREF: TlsGetValuer
; BOOL __stdcall TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
		extrn __imp_TlsSetValue:dword ;	DATA XREF: TlsSetValuer
; LPVOID __stdcall VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
		extrn __imp_VirtualAlloc:dword ; DATA XREF: VirtualAllocr
; BOOL __stdcall VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
		extrn __imp_VirtualFree:dword ;	DATA XREF: VirtualFreer
; DWORD	__stdcall VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, DWORD dwLength)
		extrn __imp_VirtualQuery:dword ; DATA XREF: VirtualQueryr
; int __stdcall	WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR	lpMultiByteStr,	int cbMultiByte, LPCSTR	lpDefaultChar, LPBOOL lpUsedDefaultChar)
		extrn __imp_WideCharToMultiByte:dword ;	DATA XREF: WideCharToMultiByter
; BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,	LPDWORD	lpNumberOfBytesWritten,	LPOVERLAPPED lpOverlapped)
		extrn __imp_WriteFile:dword ; DATA XREF: WriteFiler

;
; Imports from USER32.DLL
;
; BOOL __stdcall EnumThreadWindows(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam)
		extrn __imp_EnumThreadWindows:dword ; DATA XREF: EnumThreadWindowsr
; int __stdcall	MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,	UINT uType)
		extrn __imp_MessageBoxA:dword ;	DATA XREF: MessageBoxAr
; int wsprintfA(LPSTR, LPCSTR, ...)
		extrn __imp_wsprintfA:dword ; DATA XREF: wsprintfAr


		end start
