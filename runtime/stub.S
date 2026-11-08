.intel_syntax noprefix
.code64
.global np_stub_start
.global np_stub_end

# NovaProtect x64 loader stub
# On entry the stack follows the normal Windows executable entry contract.
# Data format v2 is documented in src/packer.cpp.
np_stub_start:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rax, qword ptr gs:[0x60]

    # image base and data pointer
    mov rbx, qword ptr [rax+0x10]
    mov edi, 0xDEADBEEF
    add rdi, rbx
    mov rsi, rdi

    # validate header magic/version
    cmp dword ptr [rsi], 0x41564F4E
    jne np_hard_fail
    cmp dword ptr [rsi+4], 3
    jne np_hard_fail

    # Runtime protection switches are packed into the payload header.
    mov r10d, dword ptr [rsi+88]

    test r10d, 1
    jz np_skip_ad
    mov rax, qword ptr gs:[0x60]
    movzx ecx, byte ptr [rax+0x02]
    test ecx, ecx
    jnz np_hard_fail
    mov ecx, dword ptr [rax+0xBC]
    and ecx, 0x70
    cmp ecx, 0x70
    je np_hard_fail
np_skip_ad:

    test r10d, 2
    jz np_skip_vm
    # Block third-party hypervisors only. Microsoft Hyper-V is allowed because
    # VBS / Memory Integrity on physical Windows hosts sets the hypervisor bit.
    mov r15, rax
    mov r12, rbx
    mov eax, 0x40000000
    cpuid
    cmp ebx, 0x61774D56
    jne np_vm_kvm
    cmp ecx, 0x4D567265
    jne np_vm_kvm
    cmp edx, 0x65726177
    je np_vm_fail
np_vm_kvm:
    cmp ebx, 0x4B4D564B
    jne np_vm_xen
    cmp ecx, 0x564B4D56
    jne np_vm_xen
    cmp edx, 0x0000004D
    je np_vm_fail
np_vm_xen:
    cmp ebx, 0x566E6558
    jne np_vm_vbox
    cmp ecx, 0x65584D4D
    jne np_vm_vbox
    cmp edx, 0x4D4D566E
    je np_vm_fail
np_vm_vbox:
    cmp ebx, 0x786F4256
    jne np_vm_parallels
    cmp ecx, 0x786F4256
    jne np_vm_parallels
    cmp edx, 0x786F4256
    je np_vm_fail
np_vm_parallels:
    cmp ebx, 0x206C7270
    jne np_vm_bhyve
    cmp ecx, 0x65707968
    jne np_vm_bhyve
    cmp edx, 0x20207672
    je np_vm_fail
np_vm_bhyve:
    cmp ebx, 0x76796862
    jne np_vm_restore
    cmp ecx, 0x68622065
    jne np_vm_restore
    cmp edx, 0x20657679
    je np_vm_fail
np_vm_restore:
    mov rax, r15
    mov rbx, r12
np_skip_vm:

    mov r12d, dword ptr [rsi+8]         # region count
    mov r14d, dword ptr [rsi+12]        # original entry RVA
    lea r13, [rsi+128]                  # region records (after TLS field at +96)
    mov rax, r12
    shl rax, 5
    lea r15, [r13+rax]                  # payload pointer

np_region_loop:
    test r12d, r12d
    jz np_apply_relocs
    mov r11d, dword ptr [r13+8]
    mov r10d, dword ptr [r13+4]
    mov eax, dword ptr [r13]
    lea rdi, [rbx+rax]

    # decrypt in place when the region record says payload encryption is enabled
    test dword ptr [r13+12], 4
    jz np_decrypt_done
    xor r8d, r8d
np_decrypt_loop:
    cmp r8d, r11d
    jae np_decrypt_done
    mov al, byte ptr [r15+r8]
    mov r9, r8
    and r9, 31
    xor al, byte ptr [rsi+16+r9]
    mov byte ptr [r15+r8], al
    inc r8d
    jmp np_decrypt_loop

np_decrypt_done:
    test dword ptr [r13+12], 1
    jnz np_rle_copy

np_copy_loop:
    xor r8d, r8d
np_copy_loop_body:
    cmp r8d, r10d
    jae np_integrity_start
    mov al, byte ptr [r15+r8]
    mov byte ptr [rdi+r8], al
    inc r8d
    jmp np_copy_loop_body

np_rle_copy:
    xor r8d, r8d
    xor r9d, r9d
np_rle_loop:
    cmp r9d, r10d
    jae np_integrity_start
    movzx eax, byte ptr [r15+r8]
    inc r8d
    test al, 0x80
    jnz np_rle_run
    and eax, 0x7F
    inc eax
    xor edx, edx
np_rle_lit:
    cmp edx, eax
    jae np_rle_loop
    mov cl, byte ptr [r15+r8]
    mov byte ptr [rdi+r9], cl
    inc r8d
    inc r9d
    inc edx
    jmp np_rle_lit

np_rle_run:
    and eax, 0x7F
    inc eax
    mov cl, byte ptr [r15+r8]
    inc r8d
    xor edx, edx
np_rle_run_loop:
    cmp edx, eax
    jae np_rle_loop
    mov byte ptr [rdi+r9], cl
    inc r9d
    inc edx
    jmp np_rle_run_loop

np_integrity_start:
    # Region integrity: FNV-1a over restored bytes before relocation replay.
    test dword ptr [r13+12], 2
    jz np_region_next
    xor r9, r9
    movabs r11, 0xCBF29CE484222325
np_integrity_loop:
    cmp r9, r10
    jae np_integrity_done
    movzx eax, byte ptr [rdi+r9]
    xor r11, rax
    movabs rdx, 0x100000001B3
    imul r11, rdx
    inc r9
    jmp np_integrity_loop
np_integrity_done:
    cmp r11, qword ptr [r13+16]
    jne np_hard_fail
np_region_next:
    mov eax, dword ptr [r13+8]
    add r13, 32
    add eax, 7
    and eax, 0xFFFFFFF8
    add r15, rax
    dec r12d
    jmp np_region_loop

# Replay relocations that target bytes restored from the encrypted payload.
# The Windows loader has already relocated all non-packed sections, so this
# pass is deliberately restricted to the stored region ranges.
np_apply_relocs:
    mov ecx, dword ptr [rsi+52]        # reloc size
    test ecx, ecx
    jz np_tls_init
    movsxd r9, ecx
    mov ecx, dword ptr [rsi+48]        # reloc RVA
    test ecx, ecx
    jz np_tls_init
    lea r8, [rbx+rcx]
    mov r15, rbx
    sub r15, qword ptr [rsi+80]        # actual base - preferred base

np_reloc_block:
    cmp r9, 8
    jb np_tls_init
    mov eax, dword ptr [r8]            # page RVA
    mov ecx, dword ptr [r8+4]          # block size
    test ecx, ecx
    jz np_tls_init
    cmp rcx, r9
    ja np_tls_init
    lea r10, [r8+8]
    mov r11d, ecx
    shr r11d, 1
    sub r11d, 4
    test r11d, r11d
    jz np_reloc_next

np_reloc_entry:
    movzx edx, word ptr [r10]
    add r10, 2
    mov ecx, edx
    shr ecx, 12
    test ecx, ecx
    jz np_reloc_entry_next
    and edx, 0xFFF
    add edx, eax

    mov r13, rsi
    add r13, 128
    mov r14d, dword ptr [rsi+8]
np_reloc_region:
    test r14d, r14d
    jz np_reloc_entry_next
    mov edi, dword ptr [r13]
    cmp edx, edi
    jb np_reloc_region_next
    add edi, dword ptr [r13+4]
    cmp edx, edi
    jae np_reloc_region_next

    lea rdi, [rbx+rdx]
    cmp ecx, 10                         # DIR64
    jne np_reloc_highlow
    add qword ptr [rdi], r15
    jmp np_reloc_region_next
np_reloc_highlow:
    cmp ecx, 3                          # HIGHLOW
    jne np_reloc_region_next
    add dword ptr [rdi], r15d

np_reloc_region_next:
    add r13, 32
    dec r14d
    jnz np_reloc_region

np_reloc_entry_next:
    dec r11d
    jnz np_reloc_entry
np_reloc_next:
    movsxd rcx, dword ptr [r8+4]
    add r8, rcx
    sub r9, rcx
    jmp np_reloc_block

# Replace the temporary TLS callback with the original callback list. The new
# list lives in writable .np_data, so thread attach callbacks keep working.
np_tls_init:
    call np_resolve_imports
    mov eax, dword ptr [rsi+56]        # original callback array RVA
    mov ecx, dword ptr [rsi+96]        # new callback array RVA (payload header)
    test ecx, ecx
    jnz np_tls_have_array
    mov ecx, dword ptr [rsi+60]        # legacy fallback
np_tls_have_array:
    mov r8d, dword ptr [rsi+64]        # capacity
    test eax, eax
    jz np_launch2
    test ecx, ecx
    jz np_launch2
    test r8d, r8d
    jz np_launch2
    lea rdi, [rbx+rcx]
    lea rcx, [rbx+rax]
    xor r9, r9
np_tls_copy:
    cmp r9, r8
    jae np_tls_call_prep
    mov rax, qword ptr [rcx+r9*8]
    test rax, rax
    jz np_tls_call_prep
    mov qword ptr [rdi+r9*8], rax
    inc r9
    jmp np_tls_copy

np_tls_call_prep:
    mov qword ptr [rdi+r9*8], 0
    # r9 (count) and the loop index live in volatile registers, but TLS
    # callbacks are free to clobber them. Keep both in stack locals so the
    # replay loop survives arbitrary callback register usage.
    sub rsp, 16
    mov qword ptr [rsp], r9
    mov qword ptr [rsp+8], 0
np_tls_call:
    mov r10, qword ptr [rsp+8]
    cmp r10, qword ptr [rsp]
    jae np_tls_call_done
    mov rax, qword ptr [rdi+r10*8]
    test rax, rax
    jz np_tls_call_done
    mov rcx, rbx
    mov edx, 1                         # DLL_PROCESS_ATTACH
    xor r8d, r8d
    call rax
    mov r10, qword ptr [rsp+8]
    inc r10
    mov qword ptr [rsp+8], r10
    jmp np_tls_call
np_tls_call_done:
    add rsp, 16
    jmp np_launch2

np_launch2:
    # ---- protection runtime (x64) --------------------------------------
    # The packer publishes the .np_prot sub-region RVAs in the payload header.
    # Offset +100 == 0 means no protection runtime was embedded, so the original
    # entry point is used unchanged.
    mov eax, dword ptr [rsi+100]
    test eax, eax
    jz np_no_prot

    # Keep the registers the protection runtime clobbers on the stack; rbx
    # (image base) and rsi (payload header) are callee saved and survive the
    # call by contract.
    # 48 (not 40): the fifteen entry pushes leave rsp 16-byte aligned, and the
    # x64 ABI requires rsp to still be 16-byte aligned *at* the call so the
    # runtime enters with rsp%16 == 8 like every other Windows function. With
    # 40 the runtime ran misaligned by 8 and any 16-byte-aligned stack local
    # (movaps/movdqa codegen) faulted with 0xC0000005.
    sub rsp, 48
    mov ecx, dword ptr [rsi+104]       # NPP1 data blob RVA
    lea rdx, [rbx+rcx]
    mov qword ptr [rsp], rdx
    mov ecx, dword ptr [rsi+108]       # mutation kernel RVA (0 = none)
    test ecx, ecx
    jz np_prot_no_kernel
    lea rdx, [rbx+rcx]
    mov qword ptr [rsp+8], rdx
np_prot_no_kernel:
    mov rcx, rbx                       # arg1: image base
    mov rdx, rsi                       # arg2: payload header
    mov r8, qword ptr [rsp]            # arg3: NPP1 data blob
    mov r9, qword ptr [rsp+8]          # arg4: mutation kernel
    mov eax, dword ptr [rsi+100]       # protection code RVA
    lea rax, [rbx+rax]
    call rax
    add rsp, 48
    test eax, eax
    jnz np_hard_fail
np_no_prot:

    mov r14d, dword ptr [rsi+12]
    add r14, rbx
    mov rax, r14
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    add rsp, 8
    popfq
    jmp rax

np_vm_fail:
    ud2
    jmp np_hard_fail

np_hard_fail:
    ud2
    jmp np_hard_fail

# ============================================================
# Runtime import resolution (import protection)
# Rebuilds the IAT from the NPM1 metadata container before any user
# code runs. Only the PEB loader list and the kernel32 export table are
# used, so the protected image ships without an import directory.
# ============================================================

# in : r11 = ASCII module name (NUL terminated)
# out: rax = module base or 0
# preserves rbx, rsi, r11
np_find_module:
    push rdi
    push r9
    mov rax, qword ptr gs:[0x60]
    mov rax, qword ptr [rax+0x18]
    lea r9, [rax+0x10]
    mov rdi, qword ptr [r9]
np_fm_loop:
    cmp rdi, r9
    je np_fm_no
    mov r10, qword ptr [rdi+0x60]
    test r10, r10
    jz np_fm_next
    movzx ecx, word ptr [rdi+0x58]
    shr ecx, 1
    test ecx, ecx
    jz np_fm_next
    xor edx, edx
np_fm_cmp:
    cmp edx, ecx
    jae np_fm_tail
    movzx eax, word ptr [r10+rdx*2]
    movzx r8d, byte ptr [r11+rdx]
    test r8d, r8d
    jz np_fm_next
    cmp eax, 65
    jb 1f
    cmp eax, 90
    ja 1f
    add eax, 32
1:  cmp r8d, 65
    jb 2f
    cmp r8d, 90
    ja 2f
    add r8d, 32
2:  cmp eax, r8d
    jne np_fm_next
    inc edx
    jmp np_fm_cmp
np_fm_tail:
    cmp byte ptr [r11+rdx], 0
    jne np_fm_next
    mov rax, qword ptr [rdi+0x30]
    pop r9
    pop rdi
    ret
np_fm_next:
    mov rdi, qword ptr [rdi]
    jmp np_fm_loop
np_fm_no:
    xor eax, eax
    pop r9
    pop rdi
    ret

# in : rcx = module base, rdx = ASCII export name
# out: rax = resolved address or 0
# preserves rbx, rsi
np_get_export:
    push rbx
    push rbp
    push rsi
    push rdi
    mov rbx, rcx
    mov ebp, dword ptr [rbx+0x3C]
    lea r8, [rbx+rbp+24]
    mov r9d, dword ptr [r8+0x70]
    test r9d, r9d
    jz np_ge_fail
    lea r9, [rbx+r9]
    mov r10d, dword ptr [r9+0x18]
    test r10d, r10d
    jz np_ge_fail
    mov r11d, dword ptr [r9+0x20]
    lea r11, [rbx+r11]
    mov r8d, dword ptr [r9+0x24]
    lea r8, [rbx+r8]
    mov r9d, dword ptr [r9+0x1C]
    lea r9, [rbx+r9]
    xor edi, edi
np_ge_loop:
    cmp edi, r10d
    jae np_ge_fail
    mov eax, dword ptr [r11+rdi*4]
    lea rsi, [rbx+rax]
    xor ecx, ecx
np_ge_cmp:
    movzx eax, byte ptr [rsi+rcx]
    movzx ebp, byte ptr [rdx+rcx]
    cmp eax, ebp
    jne np_ge_next
    test eax, eax
    jz np_ge_hit
    inc ecx
    jmp np_ge_cmp
np_ge_next:
    inc edi
    jmp np_ge_loop
np_ge_hit:
    movzx eax, word ptr [r8+rdi*2]
    mov eax, dword ptr [r9+rax*4]
    test eax, eax
    jz np_ge_fail
    add rax, rbx
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
np_ge_fail:
    xor eax, eax
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

# in : rbx = image base, rsi = payload header
np_resolve_imports:
    sub rsp, 0x138
    mov eax, dword ptr [rsi+72]
    test eax, eax
    jz np_ri_done
    mov ecx, dword ptr [rsi+76]
    test ecx, ecx
    jz np_ri_done
    lea r12, [rbx+rax]
    cmp dword ptr [r12], 0x314D504E
    jne np_ri_done
    mov r13d, dword ptr [r12+8]
    test r13d, r13d
    jz np_ri_done
    lea r14, [r12+16]
    xor r15d, r15d
np_ri_find:
    cmp r15d, r13d
    jae np_ri_done
    cmp dword ptr [r14], 6
    je np_ri_found
    add r14, 16
    inc r15d
    jmp np_ri_find
np_ri_found:
    mov eax, dword ptr [r14+8]
    mov rdx, r13
    shl rdx, 4
    add rdx, 16
    add rdx, r12
    add rdx, rax
    mov qword ptr [rsp+0x20], rdx

    # The import blob is stored encrypted so that "strings" on the protected
    # file does not reveal the import table.  Decrypt it in place before it
    # is walked; the plaintext is needed only here.
    mov rcx, qword ptr [rsp+0x20]
    call np_decrypt_blob
    # After decryption the blob starts with the plain descriptor list.
    mov rdx, qword ptr [rsp+0x20]
    add rdx, 8
    mov qword ptr [rsp+0x20], rdx

    # The three names the resolver needs are stored encrypted so that a
    # static scan of the protected file does not reveal them.  They are
    # decrypted into the stack frame before use.
    lea r11, [rip+np_str_kernel32]
    call np_find_module
    test rax, rax
    jz np_ri_done
    mov qword ptr [rsp+0x58], rax
    mov rcx, rax
    lea rdx, [rip+np_str_loadlib]
    call np_get_export
    mov qword ptr [rsp+0x48], rax
    mov rcx, qword ptr [rsp+0x58]
    lea rdx, [rip+np_str_getproc]
    call np_get_export
    mov qword ptr [rsp+0x50], rax
    cmp qword ptr [rsp+0x48], 0
    je np_ri_done
    cmp qword ptr [rsp+0x50], 0
    je np_ri_done

    mov r12, qword ptr [rsp+0x20]
    mov eax, dword ptr [r12]
    add r12, 4
    mov dword ptr [rsp+0x60], eax
np_ri_dll_loop:
    cmp dword ptr [rsp+0x60], 0
    je np_ri_done
    mov eax, dword ptr [r12]
    add r12, 4
    mov qword ptr [rsp+0x28], r12
    add r12, rax
    mov eax, dword ptr [r12]
    add r12, 4
    mov dword ptr [rsp+0x38], eax
    mov dword ptr [rsp+0x40], 0
    mov qword ptr [rsp+0x68], r12
    mov rcx, qword ptr [rsp+0x28]
    call qword ptr [rsp+0x48]
    mov qword ptr [rsp+0x30], rax
    test rax, rax
    jz np_ri_skip_dll
np_ri_fn_loop:
    mov eax, dword ptr [rsp+0x40]
    cmp eax, dword ptr [rsp+0x38]
    jae np_ri_dll_next
    mov r12, qword ptr [rsp+0x68]
    movzx eax, byte ptr [r12]
    mov dword ptr [rsp+0x80], eax
    add r12, 1
    movzx ecx, word ptr [r12]
    mov dword ptr [rsp+0x84], ecx
    add r12, 2
    mov edx, dword ptr [r12]
    mov dword ptr [rsp+0x88], edx
    add r12, 4
    mov r13d, dword ptr [r12]
    add r12, 4
    mov qword ptr [rsp+0x78], r12
    add r12, r13
    mov qword ptr [rsp+0x68], r12
    cmp dword ptr [rsp+0x80], 0
    jne np_ri_ordinal
    mov rcx, qword ptr [rsp+0x30]
    mov rdx, qword ptr [rsp+0x78]
    call qword ptr [rsp+0x50]
    jmp np_ri_store
np_ri_ordinal:
    mov rcx, qword ptr [rsp+0x30]
    mov edx, dword ptr [rsp+0x84]
    call qword ptr [rsp+0x50]
np_ri_store:
    test rax, rax
    jz np_ri_fn_next
    mov ecx, dword ptr [rsp+0x88]
    add rcx, rbx
    mov qword ptr [rcx], rax
np_ri_fn_next:
    inc dword ptr [rsp+0x40]
    jmp np_ri_fn_loop
np_ri_dll_next:
    dec dword ptr [rsp+0x60]
    jmp np_ri_dll_loop
np_ri_skip_dll:
    mov eax, dword ptr [rsp+0x38]
    test eax, eax
    jz np_ri_dll_next
np_ri_skip_loop:
    mov r12, qword ptr [rsp+0x68]
    add r12, 7
    mov r13d, dword ptr [r12]
    add r12, 4
    add r12, r13
    mov qword ptr [rsp+0x68], r12
    dec eax
    jnz np_ri_skip_loop
    jmp np_ri_dll_next
np_ri_done:
    add rsp, 0x138
    ret

np_str_kernel32:
    .asciz "kernel32.dll"
np_str_loadlib:
    .asciz "LoadLibraryA"
np_str_getproc:
    .asciz "GetProcAddress"

# Decrypt a short name into the caller's buffer.
#   in : rcx  = cipher bytes
#         edx  = length
#         r8d  = seed
#         rsi  = destination buffer
# Keystream: K(i) = (uint8_t)(rol32(seed, i & 0x1f) + (uint8_t)i)
# The length includes the terminating NUL, which the cipher also covers.
np_decrypt_str:
    push rbx
    push r9
    push r11
    mov r11, rcx                   # cipher pointer
    mov rsi, rcx                   # decrypt in place
    xor r9d, r9d
np_db_s_loop:
    cmp r9d, edx
    jae np_db_s_done
    mov r10d, r8d
    mov eax, r9d
    and eax, 0x1f
    test eax, eax
    jz np_db_s_norol
    mov ecx, r9d                   # "rol r32, cl" counts by cl
    rol r10d, cl
np_db_s_norol:
    add r10b, r9b
    mov al, byte ptr [r11+r9]
    xor al, r10b
    mov byte ptr [rsi+r9], al
    inc r9d
    jmp np_db_s_loop
np_db_s_done:
    pop r11
    pop r9
    pop rbx
    ret


# Decrypt the import blob in place.
#   in : rcx = pointer to the blob
#         [rcx+0] u32 seed
#         [rcx+4] u32 plain length
#         [rcx+8] cipher bytes
# The keystream is position dependent:
#   K(i) = (uint8_t)(rol32(seed, i & 0x1f) + (uint8_t)i)
# so the same routine both encrypts and decrypts.  The blob lives in the
# writable .np_data section, so it is decrypted where it is.
np_decrypt_blob:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    mov r12, rcx
    mov r13d, dword ptr [r12]        # seed
    mov esi, dword ptr [r12+4]       # length
    test esi, esi
    jz np_db_b_done
    lea rdi, [r12+8]
    xor ecx, ecx
np_db_b_loop:
    cmp ecx, esi
    jae np_db_b_done
    # r8d = rol32(seed, index & 0x1f)
    mov r8d, r13d
    mov eax, ecx
    and eax, 0x1f
    test eax, eax
    jz np_db_b_norol
    rol r8d, cl
np_db_b_norol:
    # r8b += (uint8_t)index
    add r8b, cl
    # ciphertext byte
    mov al, byte ptr [rdi+rcx]
    xor al, r8b
    mov byte ptr [rdi+rcx], al
    inc ecx
    jmp np_db_b_loop
np_db_b_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

# Unique marker + harmless callback used before the original image is restored.
.align 8
np_tls_stub:
    nop
    xor eax, eax
    ret

np_stub_end:



