.intel_syntax noprefix
.code32
.global np_stub32_start
.global np_stub32_end

# NovaProtect x86 loader stub.
# Payload header contract matches src/packer.cpp version 3. All addresses are
# RVAs relative to the actual image base taken from the x86 PEB.

np_stub32_start:
    pushfd
    pushad
    sub esp, 96

    # Local frame:
    #   0 image base          4 payload header       8 regions left
    #  12 record pointer      16 payload pointer     20 destination pointer
    #  24 stored size         28 original size      32 region flags
    #  36 unused              40 reloc bytes left   44 reloc pointer
    #  48 relocation delta    52 page RVA           56 block size
    #  60 entry pointer       64 entry count        68 TLS count
    #  72 TLS array pointer   76 target/index       80 timing scratch
    #  84 scratch             88 scratch
    mov eax, dword ptr fs:[0x30]
    mov ebx, dword ptr [eax+8]
    mov edi, 0xDEADBEEF
    add edi, ebx
    mov ebp, edi
    mov dword ptr [esp+0], ebx
    mov dword ptr [esp+4], ebp

    cmp dword ptr [ebp], 0x41564F4E
    jne np32_fail
    cmp dword ptr [ebp+4], 3
    jne np32_fail

    # Runtime flags: bit0 anti-debug, bit1 anti-VM, bits 4..5 AD level,
    # bits 6..7 anti-VM level.
    mov ecx, dword ptr [ebp+88]
    test ecx, 1
    jz np32_skip_ad

    mov eax, dword ptr fs:[0x30]
    movzx ecx, byte ptr [eax+2]
    test ecx, ecx
    jnz np32_fail

    mov ecx, dword ptr [eax+0x68]
    and ecx, 0x70
    cmp ecx, 0x70
    je np32_fail

    mov eax, dword ptr [eax+0x90]
    test eax, eax
    jz np32_ad_heap_done
    cmp dword ptr [eax+0x0C], 0
    jne np32_fail
np32_ad_heap_done:

    mov ecx, dword ptr [ebp+88]
    shr ecx, 4
    and ecx, 3
    cmp ecx, 2
    jb np32_skip_ad

    # Coarse timing check. The threshold is intentionally high to avoid
    # false positives on slow CPUs while still catching breakpoint-stepped runs.
    xor eax, eax
    cpuid
    rdtsc
    mov dword ptr [esp+80], eax
    xor eax, eax
    cpuid
    rdtsc
    sub eax, dword ptr [esp+80]
    cmp eax, 0x00100000
    ja np32_fail
np32_skip_ad:

    mov ecx, dword ptr [ebp+88]
    test ecx, 2
    jz np32_skip_vm

    # Hypervisor vendor string from CPUID leaf 0x40000000. Block third-party
    # hypervisors only (VMware/VirtualBox/KVM/Xen/Parallels/Bhyve). Microsoft
    # Hyper-V is deliberately allowed: Windows enables VBS / Memory Integrity
    # on ordinary physical machines, which sets the hypervisor-present bit and
    # reports "Microsoft Hv", so failing on that bit breaks every modern host.
    mov eax, 0x40000000
    cpuid

    cmp ebx, 0x61774D56
    jne np32_vm_kvm
    cmp ecx, 0x4D567265
    jne np32_vm_kvm
    cmp edx, 0x65726177
    je np32_vm_fail

np32_vm_kvm:
    cmp ebx, 0x4B4D564B
    jne np32_vm_xen
    cmp ecx, 0x564B4D56
    jne np32_vm_xen
    cmp edx, 0x0000004D
    je np32_vm_fail

np32_vm_xen:
    cmp ebx, 0x566E6558
    jne np32_vm_vbox
    cmp ecx, 0x65584D4D
    jne np32_vm_vbox
    cmp edx, 0x4D4D566E
    je np32_vm_fail

np32_vm_vbox:
    cmp ebx, 0x786F4256
    jne np32_vm_parallels
    cmp ecx, 0x786F4256
    jne np32_vm_parallels
    cmp edx, 0x786F4256
    je np32_vm_fail

np32_vm_parallels:
    cmp ebx, 0x206C7270
    jne np32_vm_bhyve
    cmp ecx, 0x65707968
    jne np32_vm_bhyve
    cmp edx, 0x20207672
    je np32_vm_fail

np32_vm_bhyve:
    cmp ebx, 0x76796862
    jne np32_skip_vm
    cmp ecx, 0x68622065
    jne np32_skip_vm
    cmp edx, 0x20657679
    je np32_vm_fail
np32_skip_vm:
    mov ebx, dword ptr [esp+0]
    mov ebp, dword ptr [esp+4]

    mov eax, dword ptr [ebp+8]
    mov dword ptr [esp+8], eax
    lea eax, [ebp+128]
    mov dword ptr [esp+12], eax
    mov eax, dword ptr [esp+8]
    shl eax, 5
    add eax, dword ptr [esp+12]
    mov dword ptr [esp+16], eax

np32_region_loop:
    cmp dword ptr [esp+8], 0
    je np32_apply_relocs

    mov esi, dword ptr [esp+12]
    mov edi, dword ptr [esp+16]
    mov eax, dword ptr [esi]
    add eax, ebx
    mov dword ptr [esp+20], eax
    mov eax, dword ptr [esi+4]
    mov dword ptr [esp+28], eax
    mov eax, dword ptr [esi+8]
    mov dword ptr [esp+24], eax
    mov eax, dword ptr [esi+12]
    mov dword ptr [esp+32], eax

    # Decrypt the stored region payload in place when enabled.
    test dword ptr [esp+32], 4
    jz np32_decrypt_done
    xor ecx, ecx
np32_decrypt_loop:
    cmp ecx, dword ptr [esp+24]
    jae np32_decrypt_done
    mov al, byte ptr [edi+ecx]
    mov edx, ecx
    and edx, 31
    xor al, byte ptr [ebp+16+edx]
    mov byte ptr [edi+ecx], al
    inc ecx
    jmp np32_decrypt_loop

np32_decrypt_done:
    test dword ptr [esp+32], 1
    jnz np32_rle_copy

    xor ecx, ecx
np32_copy_loop:
    cmp ecx, dword ptr [esp+28]
    jae np32_integrity_start
    mov al, byte ptr [edi+ecx]
    mov edx, dword ptr [esp+20]
    mov byte ptr [edx+ecx], al
    inc ecx
    jmp np32_copy_loop

np32_rle_copy:
    mov dword ptr [esp+80], 0
    mov dword ptr [esp+84], 0
np32_rle_loop:
    mov eax, dword ptr [esp+84]
    cmp eax, dword ptr [esp+28]
    jae np32_integrity_start
    mov ecx, dword ptr [esp+80]
    movzx eax, byte ptr [edi+ecx]
    inc ecx
    mov dword ptr [esp+80], ecx
    test al, 0x80
    jnz np32_rle_run

    and eax, 0x7F
    inc eax
    mov dword ptr [esp+88], eax
    mov edx, dword ptr [esp+84]
np32_rle_literal_loop:
    cmp dword ptr [esp+88], 0
    je np32_rle_loop
    mov ecx, dword ptr [esp+80]
    mov al, byte ptr [edi+ecx]
    inc ecx
    mov dword ptr [esp+80], ecx
    mov ecx, dword ptr [esp+20]
    mov byte ptr [ecx+edx], al
    inc edx
    mov dword ptr [esp+84], edx
    dec dword ptr [esp+88]
    jmp np32_rle_literal_loop

np32_rle_run:
    and eax, 0x7F
    inc eax
    mov dword ptr [esp+88], eax
    mov ecx, dword ptr [esp+80]
    mov al, byte ptr [edi+ecx]
    inc ecx
    mov dword ptr [esp+80], ecx
    mov edx, dword ptr [esp+84]
np32_rle_run_loop:
    cmp dword ptr [esp+88], 0
    je np32_rle_loop
    mov ecx, dword ptr [esp+20]
    mov byte ptr [ecx+edx], al
    inc edx
    mov dword ptr [esp+84], edx
    dec dword ptr [esp+88]
    jmp np32_rle_run_loop

np32_integrity_start:
    test dword ptr [esp+32], 2
    jz np32_region_next
    mov edx, 0x811C9DC5
    xor ecx, ecx
np32_integrity_loop:
    cmp ecx, dword ptr [esp+28]
    jae np32_integrity_done
    mov eax, dword ptr [esp+20]
    movzx eax, byte ptr [eax+ecx]
    xor edx, eax
    imul edx, edx, 0x01000193
    inc ecx
    jmp np32_integrity_loop
np32_integrity_done:
    mov esi, dword ptr [esp+12]
    cmp edx, dword ptr [esi+16]
    jne np32_fail

np32_region_next:
    mov eax, dword ptr [esp+24]
    add eax, 7
    and eax, 0xFFFFFFF8
    add dword ptr [esp+16], eax
    add dword ptr [esp+12], 32
    dec dword ptr [esp+8]
    jmp np32_region_loop

# Replay HIGHLOW relocations only when the target lies in a restored region.
np32_apply_relocs:
    mov eax, dword ptr [ebp+52]
    test eax, eax
    jz np32_tls_init
    mov dword ptr [esp+40], eax
    mov eax, dword ptr [ebp+48]
    test eax, eax
    jz np32_tls_init
    add eax, ebx
    mov dword ptr [esp+44], eax
    mov eax, ebx
    sub eax, dword ptr [ebp+80]
    mov dword ptr [esp+48], eax

np32_reloc_block:
    cmp dword ptr [esp+40], 8
    jb np32_tls_init
    mov esi, dword ptr [esp+44]
    mov eax, dword ptr [esi]
    mov dword ptr [esp+52], eax
    mov eax, dword ptr [esi+4]
    mov dword ptr [esp+56], eax
    test eax, eax
    jz np32_tls_init
    cmp eax, dword ptr [esp+40]
    ja np32_tls_init
    lea eax, [esi+8]
    mov dword ptr [esp+60], eax
    mov eax, dword ptr [esp+56]
    shr eax, 1
    sub eax, 4
    mov dword ptr [esp+64], eax
    test eax, eax
    jz np32_reloc_next

np32_reloc_entry:
    mov esi, dword ptr [esp+60]
    movzx eax, word ptr [esi]
    add dword ptr [esp+60], 2
    mov edx, eax
    shr edx, 12
    test edx, edx
    jz np32_reloc_entry_next
    and eax, 0x0FFF
    add eax, dword ptr [esp+52]
    mov dword ptr [esp+76], eax

    mov ecx, dword ptr [ebp+8]
    lea esi, [ebp+128]
np32_reloc_region_scan:
    test ecx, ecx
    jz np32_reloc_entry_next
    mov eax, dword ptr [esi]
    cmp dword ptr [esp+76], eax
    jb np32_reloc_region_next
    add eax, dword ptr [esi+4]
    cmp dword ptr [esp+76], eax
    jae np32_reloc_region_next

    cmp edx, 3
    jne np32_reloc_entry_next
    mov eax, dword ptr [esp+76]
    add eax, ebx
    mov ecx, dword ptr [esp+48]
    add dword ptr [eax], ecx
    jmp np32_reloc_entry_next

np32_reloc_region_next:
    add esi, 32
    dec ecx
    jmp np32_reloc_region_scan

np32_reloc_entry_next:
    dec dword ptr [esp+64]
    jnz np32_reloc_entry

np32_reloc_next:
    mov esi, dword ptr [esp+44]
    mov eax, dword ptr [esi+4]
    add dword ptr [esp+44], eax
    sub dword ptr [esp+40], eax
    jmp np32_reloc_block

# ============================================================
# Runtime import resolution (x86). Mirrors the x64 resolver.
# in: ebx = image base, ebp = payload header
# ============================================================
np32_resolve_imports:
    pushad
    mov eax, ebp
    sub esp, 0x40
    mov ebp, esp
    mov dword ptr [ebp+0x3C], eax

    mov eax, dword ptr [ebp+0x3C]
    mov ecx, dword ptr [eax+72]
    test ecx, ecx
    jz np32_ri_done
    mov edx, dword ptr [eax+76]
    test edx, edx
    jz np32_ri_done
    add ecx, ebx
    mov dword ptr [ebp+0x00], ecx
    cmp dword ptr [ecx], 0x314D504E
    jne np32_ri_done
    mov edx, dword ptr [ecx+8]
    test edx, edx
    jz np32_ri_done
    lea esi, [ecx+16]
    xor edi, edi
np32_ri_find:
    cmp edi, edx
    jae np32_ri_done
    cmp dword ptr [esi], 6
    je np32_ri_found
    add esi, 16
    inc edi
    jmp np32_ri_find
np32_ri_found:
    mov eax, dword ptr [esi+8]
    mov ecx, edx
    shl ecx, 4
    add ecx, 16
    add ecx, dword ptr [ebp+0x00]
    add ecx, eax
    mov dword ptr [ebp+0x04], ecx

    # The import blob is stored encrypted so that "strings" on the protected
    # file does not reveal the import table.  Decrypt it in place before it
    # is walked.
    mov ecx, dword ptr [ebp+0x04]
    call np32_decrypt_blob
    mov eax, dword ptr [ebp+0x04]
    add eax, 8
    mov dword ptr [ebp+0x04], eax

    call np32_ri_pc
np32_ri_pc:
    pop eax
    mov dword ptr [ebp+0x38], eax

    mov esi, eax
    add esi, np32_str32_kernel32 - np32_ri_pc
    call np32_find_module
    test eax, eax
    jz np32_ri_done
    mov dword ptr [ebp+0x0C], eax

    mov ecx, eax
    mov edx, dword ptr [ebp+0x38]
    add edx, np32_str32_loadlib - np32_ri_pc
    call np32_get_export
    mov dword ptr [ebp+0x10], eax

    mov ecx, dword ptr [ebp+0x0C]
    mov edx, dword ptr [ebp+0x38]
    add edx, np32_str32_getproc - np32_ri_pc
    call np32_get_export
    mov dword ptr [ebp+0x14], eax

    cmp dword ptr [ebp+0x10], 0
    je np32_ri_done
    cmp dword ptr [ebp+0x14], 0
    je np32_ri_done

    mov esi, dword ptr [ebp+0x04]
    mov eax, dword ptr [esi]
    add esi, 4
    mov dword ptr [ebp+0x08], eax

np32_ri_dll_loop:
    cmp dword ptr [ebp+0x08], 0
    je np32_ri_done
    mov eax, dword ptr [esi]
    add esi, 4
    mov dword ptr [ebp+0x18], esi
    add esi, eax
    mov eax, dword ptr [esi]
    add esi, 4
    mov dword ptr [ebp+0x1C], eax
    mov dword ptr [ebp+0x20], 0
    mov dword ptr [ebp+0x28], esi

    mov ecx, dword ptr [ebp+0x18]
    mov eax, dword ptr [ebp+0x10]
    mov edi, esp
    and esp, 0xFFFFFFF0
    sub esp, 12
    push ecx
    call eax
    mov esp, edi
    mov dword ptr [ebp+0x24], eax
    test eax, eax
    jz np32_ri_skip_dll

np32_ri_fn_loop:
    mov eax, dword ptr [ebp+0x20]
    cmp eax, dword ptr [ebp+0x1C]
    jae np32_ri_dll_next
    mov esi, dword ptr [ebp+0x28]
    movzx eax, byte ptr [esi]
    mov dword ptr [ebp+0x2C], eax
    add esi, 1
    movzx eax, word ptr [esi]
    mov dword ptr [ebp+0x30], eax
    add esi, 2
    mov eax, dword ptr [esi]
    mov dword ptr [ebp+0x34], eax
    add esi, 4
    mov eax, dword ptr [esi]
    add esi, 4
    mov dword ptr [ebp+0x38], esi
    add esi, eax
    mov dword ptr [ebp+0x28], esi

    mov ecx, dword ptr [ebp+0x24]
    cmp dword ptr [ebp+0x2C], 0
    jne np32_ri_ordinal
    mov edx, dword ptr [ebp+0x38]
    jmp np32_ri_call_gpa
np32_ri_ordinal:
    mov edx, dword ptr [ebp+0x30]
np32_ri_call_gpa:
    mov eax, dword ptr [ebp+0x14]
    mov edi, esp
    and esp, 0xFFFFFFF0
    sub esp, 8
    push edx
    push ecx
    call eax
    mov esp, edi
    test eax, eax
    jz np32_ri_fn_next
    mov ecx, dword ptr [ebp+0x34]
    add ecx, ebx
    mov dword ptr [ecx], eax
np32_ri_fn_next:
    inc dword ptr [ebp+0x20]
    jmp np32_ri_fn_loop

np32_ri_dll_next:
    dec dword ptr [ebp+0x08]
    jmp np32_ri_dll_loop

np32_ri_skip_dll:
    mov eax, dword ptr [ebp+0x1C]
    test eax, eax
    jz np32_ri_dll_next
np32_ri_skip_loop:
    mov esi, dword ptr [ebp+0x28]
    add esi, 7
    mov ecx, dword ptr [esi]
    add esi, 4
    add esi, ecx
    mov dword ptr [ebp+0x28], esi
    dec eax
    jnz np32_ri_skip_loop
    jmp np32_ri_dll_next

np32_ri_done:
    add esp, 0x40
    popad
    ret

np32_str32_kernel32:
    .asciz "kernel32.dll"
np32_str32_loadlib:
    .asciz "LoadLibraryA"
np32_str32_getproc:
    .asciz "GetProcAddress"

# Decrypt a short name into the caller's buffer.
#   in : ecx = cipher bytes
#         edx = length
#         eax = seed
#         edi = destination buffer
np32_decrypt_str:
    push ebx
    push esi
    push ebp
    mov ebp, eax                   # seed
    mov esi, edx                   # length
    mov ebx, ecx                   # cipher pointer == destination
    xor edx, edx
np32_db_s_loop:
    cmp edx, esi
    jae np32_db_s_done
    mov eax, ebp                   # rol32(seed, index & 0x1f)
    mov ebx, edx
    and ebx, 0x1f
    test ebx, ebx
    jz np32_db_s_norol
    rol eax, cl                    # x86 masks the count to 5 bits
np32_db_s_norol:
    add al, dl                     # + (uint8_t)index
    xor byte ptr [ebx+edx], al
    inc edx
    jmp np32_db_s_loop
np32_db_s_done:
    pop ebp
    pop esi
    pop ebx
    ret

# Decrypt the import blob in place (see the x64 stub for the format).
#   in : ecx = pointer to the blob
#         [ecx+0] u32 seed
#         [ecx+4] u32 plain length
#         [ecx+8] cipher bytes
# Keystream: K(i) = (uint8_t)(rol32(seed, i & 0x1f) + (uint8_t)i)
np32_decrypt_blob:
    push ebx
    push esi
    push edi
    push ebp
    mov ebp, ecx                   # blob pointer
    mov edx, dword ptr [ebp]       # seed
    mov esi, dword ptr [ebp+4]     # length
    test esi, esi
    jz np32_db_b_done
    lea edi, [ebp+8]               # cipher bytes
    xor ecx, ecx                   # index
np32_db_b_loop:
    cmp ecx, esi
    jae np32_db_b_done
    # eax = rol32(seed, index & 0x1f)
    mov eax, edx
    mov ebx, ecx
    and ebx, 0x1f
    test ebx, ebx
    jz np32_db_b_norol
    rol eax, cl                    # x86 masks the count to 5 bits
np32_db_b_norol:
    # al += (uint8_t)index
    add al, cl
    xor byte ptr [edi+ecx], al
    inc ecx
    jmp np32_db_b_loop
np32_db_b_done:
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret

# in : esi = ASCII module name -> out: eax = module base or 0
np32_find_module:
    push ebp
    push ebx
    push edi
    sub esp, 8
    mov eax, dword ptr fs:[0x30]
    mov eax, dword ptr [eax+0x0C]
    lea eax, [eax+0x0C]
    mov dword ptr [esp+0], eax
    mov eax, dword ptr [eax]
    mov dword ptr [esp+4], eax
np32_fm_loop:
    mov eax, dword ptr [esp+4]
    cmp eax, dword ptr [esp+0]
    je np32_fm_no
    mov ecx, dword ptr [eax+0x30]
    test ecx, ecx
    jz np32_fm_next
    movzx edx, word ptr [eax+0x2C]
    shr edx, 1
    test edx, edx
    jz np32_fm_next
    xor edi, edi
np32_fm_cmp:
    cmp edi, edx
    jae np32_fm_tail
    movzx ebx, word ptr [ecx+edi*2]
    movzx eax, byte ptr [esi+edi]
    test eax, eax
    jz np32_fm_next
    cmp ebx, 65
    jb np32_fm_l1
    cmp ebx, 90
    ja np32_fm_l1
    add ebx, 32
np32_fm_l1:
    cmp eax, 65
    jb np32_fm_l2
    cmp eax, 90
    ja np32_fm_l2
    add eax, 32
np32_fm_l2:
    cmp ebx, eax
    jne np32_fm_next
    inc edi
    jmp np32_fm_cmp
np32_fm_tail:
    cmp byte ptr [esi+edi], 0
    jne np32_fm_next
    mov eax, dword ptr [esp+4]
    mov eax, dword ptr [eax+0x18]
    jmp np32_fm_out
np32_fm_next:
    mov eax, dword ptr [esp+4]
    mov eax, dword ptr [eax]
    mov dword ptr [esp+4], eax
    jmp np32_fm_loop
np32_fm_no:
    xor eax, eax
np32_fm_out:
    add esp, 8
    pop edi
    pop ebx
    pop ebp
    ret

# in : ecx = module base, edx = ASCII export name -> out: eax = address or 0
np32_get_export:
    push ebx
    push ebp
    push esi
    push edi
    sub esp, 16
    mov ebx, ecx
    mov ebp, dword ptr [ebx+0x3C]
    add ebp, ebx
    mov ebp, dword ptr [ebp+0x78]
    test ebp, ebp
    jz np32_ge_fail
    add ebp, ebx
    mov eax, dword ptr [ebp+0x18]
    test eax, eax
    jz np32_ge_fail
    mov dword ptr [esp+0], eax
    mov eax, dword ptr [ebp+0x20]
    add eax, ebx
    mov dword ptr [esp+8], eax
    mov eax, dword ptr [ebp+0x24]
    add eax, ebx
    mov dword ptr [esp+12], eax
    mov edi, dword ptr [ebp+0x1C]
    add edi, ebx
    mov dword ptr [esp+4], 0
np32_ge_loop:
    mov ecx, dword ptr [esp+4]
    cmp ecx, dword ptr [esp+0]
    jae np32_ge_fail
    mov eax, dword ptr [esp+8]
    mov eax, dword ptr [eax+ecx*4]
    add eax, ebx
    mov esi, eax
    xor ecx, ecx
np32_ge_cmp:
    mov al, byte ptr [esi+ecx]
    cmp al, byte ptr [edx+ecx]
    jne np32_ge_next
    test al, al
    jz np32_ge_hit
    inc ecx
    jmp np32_ge_cmp
np32_ge_next:
    inc dword ptr [esp+4]
    jmp np32_ge_loop
np32_ge_hit:
    mov ecx, dword ptr [esp+4]
    mov eax, dword ptr [esp+12]
    movzx ecx, word ptr [eax+ecx*2]
    mov eax, dword ptr [edi+ecx*4]
    test eax, eax
    jz np32_ge_fail
    add eax, ebx
    jmp np32_ge_out
np32_ge_fail:
    xor eax, eax
np32_ge_out:
    add esp, 16
    pop edi
    pop esi
    pop ebp
    pop ebx
    ret
# Copy the original callback pointer array into writable .np_data, terminate it,
# then replay DLL_PROCESS_ATTACH. Loader relocation has already fixed pointers in
# the original array because that section is not stripped.
np32_tls_init:
    call np32_resolve_imports
    mov eax, dword ptr [ebp+56]
    test eax, eax
    jz np32_launch
    # New callback array RVA comes from the payload header (offset 96) so it is
    # valid before the image headers are patched. Fall back to offset 60 only if
    # the newer field is absent.
    mov ecx, dword ptr [ebp+96]
    test ecx, ecx
    jnz np32_tls_have_array
    mov ecx, dword ptr [ebp+60]
np32_tls_have_array:
    test ecx, ecx
    jz np32_launch
    mov edx, dword ptr [ebp+64]
    test edx, edx
    jz np32_launch

    add eax, ebx
    add ecx, ebx
    mov dword ptr [esp+72], ecx
    xor esi, esi
np32_tls_copy:
    cmp esi, edx
    jae np32_tls_terminate
    mov edi, dword ptr [eax+esi*4]
    test edi, edi
    jz np32_tls_terminate
    mov ecx, dword ptr [esp+72]
    mov dword ptr [ecx+esi*4], edi
    inc esi
    jmp np32_tls_copy

np32_tls_terminate:
    mov ecx, dword ptr [esp+72]
    mov dword ptr [ecx+esi*4], 0
    mov dword ptr [esp+68], esi
    mov dword ptr [esp+76], 0

np32_tls_call_loop:
    mov esi, dword ptr [esp+76]
    cmp esi, dword ptr [esp+68]
    jae np32_launch
    mov ecx, dword ptr [esp+72]
    mov eax, dword ptr [ecx+esi*4]
    test eax, eax
    jz np32_launch
    push 0
    push 1
    push ebx
    call eax
    inc dword ptr [esp+76]
    jmp np32_tls_call_loop

np32_launch:
    # popad restores EAX from the pushad frame, so write the jump target into the
    # saved-EAX slot (locals+96+28 = +124) before popad, else EAX is clobbered.
    mov eax, dword ptr [esp+0]
    add eax, dword ptr [ebp+12]
    mov dword ptr [esp+124], eax
    add esp, 96
    popad
    popfd
    jmp eax

np32_vm_fail:
    ud2
    jmp np32_fail

np32_fail:
    ud2
    jmp np32_fail

.align 8
np32_tls_stub:
    nop
    xor eax, eax
    ret

np_stub32_end:
