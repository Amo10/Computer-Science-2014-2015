//
//  File.s
//  
//
//  Created by Andrew Morris on 10/29/14.
//
//
MOV $23815,%ebx
MOV $16617,%eax
MOV $8264,%ecx
CMP %eax,%ebx
JL L1
JMP L2
L1:
IMUL %eax,%ebx
ADD %eax,%ebx
MOV %ebx,%eax
SUB %ecx,%eax
JMP L3
L2:
IMUL %eax,%ebx
ebx= eax*ebx
SUB %eax,%ebx
ebx = ebx-eax
MOV %ebx,%eax
eax = ebx
ADD %ecx,%eax
eax = eax + ecx
L3:
NOP

