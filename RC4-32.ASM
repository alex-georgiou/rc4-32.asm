;RC4-32 brute force cracker for pwl files with an RC-4 32-bit key encryption
;    1999 Alexandros Georgiou <alex.georgiou@gmail.com>
;
;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.
;
;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <http://www.gnu.org/licenses/>.

.use16

jmp start
key	dd 0			; set this to start of keyspace search

s	db 256 dup(1)
k	db 256 dup(2)
filename db 12 dup(0)		; will need space for extension
username db 8 dup(0)		; will not
handle	dw 0			; file i/o handle
ext	db '.PWL'
hex	db '0123456789ABCDEF'
output	dd 0,0
usage	db 'To crack user.pwl type rc4-32 user (do not supply .pwl extension)$'

;Show 'E'
err:	push ax
	push bx
	push cx
	mov cx,1
	mov ax,0a45h
	xor bx,bx
	int 10h
	pop cx
	pop bx
	pop ax
	ret

;Load the pwl file
loadpwl:
	mov di,81h
	mov si,81h
	xor ch,ch
	mov cl,[80h]
	cmp cl,1
	ja upcase

	mov dx,usage+100h		; no parameter was supplied
	mov ah,9h
	int 21h				; print usage and exit
	jmp exit

upcase:	lodsb
	cmp al,97
	jb ok
	cmp al,122
	ja ok
	sub al,20h
ok:	stosb
	loop upcase		; now the parameter is uppercase

	xor cx,cx
	mov si,82h
	xor ch,ch
	mov cl,[80h]
	dec cl			; don't want CRLF in filename
	mov di,filename+100h
	rep movsb
	mov cx,4
	mov si,ext+100h
	rep movsb		; now filename = parameter + ext

	mov si,filename+100h
	mov di,username+100h
copy:	lodsb
	cmp al,46
	jz endcopy
	stosb
	jmp copy
endcopy:			; now username = filename - ext
	
	mov dx,filename+100h
	mov ah,3dh
	xor al,al
	int 21h			; open file
	jc error
	mov [handle+100h],ax

	mov ah,3fh
	mov bx,[handle+100h]
	mov dx,1000h		; buffer at 1000
	mov cx,21ch
	int 21h
	jc error
	cmp ax,21ch
	jne error

	mov ah,3eh
	xor al,al
	mov bx,[handle+100h]
	int 21h			; close file
	jc error

	mov bx,1208h		; start of known plaintext
	mov cx,8		; max len of username
	mov si,username+100h
pad:	lodsb
	xor [bx],al
	inc bx
	loop pad		; now the key is xor padded

	ret

;Fill the k and s tables in parallel (32bit code)
; (modifies: edx,cx,si,di)
; (expects : key in eax)
fill:	mov cx,40h		; do it again
	mov edx,03020100h
	mov si,s+100h		; si=pointer to s table
	mov di,k+100h		; di=pointer to k table
l1:	mov [si],edx		; fill s table sequentially
	add edx,04040404h
	mov [di],eax		; fill k table with 32bit key
	add si,4
	add di,4
	loop l1



;Initial permutations on s and k
;(modifies: di,si,bx,bp,cx,dx)
;(expects : s,k tables filled, bx,bp pointers to s,k)

	xor di,di		; di=i
	xor si,si		; si=j
	mov cx,100h		; do it again

				; s(i) is [bx+di], s(j) is [bx+si]
				; k(i) is [bp+di], k(j) is [bp+si]

	xor dh,dh		; only use low byte with add si,dx
l2:	add si,[bp+di]		; add k(i) to j
	mov dl,[bx+di]		; load s(i)
	add si,dx		; add s(i) to j
	and si,0ffh		; j=j (mod 256)

				; swap buffer is dh
	mov dh,[bx+si]		; dh=s(j)
	mov [bx+si],dl		; s(j)=s(i)
	mov [bx+di],dh		; s(i)=dh

	inc di
	loop l2
	ret

;Returns next byte in dl
;(expects: s,k tables filled and initialised, i,j in di,si
; bx pointer to s)

next:	inc di			; no need for mod, i<20
				; no need to clear dh
	mov dl,[bx+di]		; load s(i) in dl
	add si,dx		; j=j+s(i)
	and si,0FFh		; j=j (mod 256)
	mov dh,[bx+si]		; load s(j) in dh
	mov [bx+si],dl		; s(j)=dl
	add dl,dh		; dl=s(i)+s(j)
	mov [bx+di],dh		; s(i)=dh
	push si			; need to use si
	xor dh,dh
	mov si,dx		; put dl in si low
	mov dl,[bx+si]		; dl=s(dl)
	pop si
ret

;Entry point - load key to start from
start:	call loadpwl
	mov eax,dword ptr [key+100h]
	mov bx,s+100h		; bx=pointer to s table
	mov bp,k+100h		; bp=pointer to k table

;this is the main loop - runs 4,294,967,168 times
main:	call fill
	xor di,di		; i=0
	xor si,si		; j=0

	xor dh,dh		; "next:" needs this for the first loop
strcmp:	call next		; next byte from stream in dl
	cmp dl,[di+1207h]
	jz strcmp		; if char match then check next char

	cmp di,19		; debug
	jg found		; if i>19 then whole string match

	inc eax
	jnz main

found:	mov edx,eax
	mov cx,8
	mov di,output+100h
conv:	rol edx,4
	mov ebx,edx
	and ebx,0fh
	mov al,[bx+hex+100h]
	stosb
	loop conv

	mov al,36		; trailing $
	stosb

	mov dx,output+100h
	mov ax,900h
	int 21h
	
	mov cx,1
	mov ax,0a68h
	xor bx,bx
	int 10h

	jmp exit
error:	call err
exit:	xor ax,ax
	int 21h
