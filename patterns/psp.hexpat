struct PSP {
    /// Usually set to INT 0x20 (0xcd20) prog terminate
    u16 exit;
    /// "Segment of the first byte beyond the memory allocated to the program"
    /// Yeah that wording sucks. Basically the segment alloc ends
    /// So if we've alloc'd 0x0 -> 0x2000 it'd be 0x2001 /probably/
    u16 alloc_end;
    u8 resv;
    /// Far call instruction to MSDos function dispatcher
    u8 call_disp[5];
    /// .COM programs bytes available in segment (CP/M)
    // com_bytes: u32,
    /// Terminate address used by INT 22, we need to jump to this addr on exit
    /// This forces a child program to return to it's parent program
    u32 term_addr;
    /// The Ctrl-Break exit address, a location of a subroutine for us to run
    /// when we encounter a Ctrl-Break
    u32 ctrl_break_addr;
    /// Similar to the above. If we critically error, run the routine here
    u32 crit_err_addr;
    /// Parent process's segment address
    u16 parent_addr;
    /// File handle array for the process. It's completely undocumented for 2.x+
    /// /probably/ not in use for our case
    u8 file_handle_array[20];
    /// Segment address of the environment, or zero
    u16 env_segment_addr;
    /// SS:SP of the last program that called INT 0x21,0
    u32 last_exit_addr;
    /// File handle array size
    u16 file_handle_size;
    /// File handle array pointer
    u32 file_handle_addr;
    /// Pointer to previous PSP
    u32 prev_psp;
    u8 resv1[4];
    u16 dos_ver;
    u8 resv2[14];
    u8 far_call_dos[3];
    u8 resv3[9];
    u8 fcb[16];
    u8 fcb2[20];
    u8 bytes_cmd;
    u8 cmd_tail[127];
};

