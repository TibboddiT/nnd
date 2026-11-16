use crate::{*, symbols::*, error::*, symbols_registry::*, util::*, procfs::*, settings::*, common_ui::*};
use std::{fmt::Write, ops::Range, collections::HashSet};
use iced_x86::*;

pub const MAX_X86_INSTRUCTION_BYTES: usize = 15;

// Disassembled function - a sequence of lines.
// For each line, a prefix is formatted by the UI on the fly (with some dynamic elements), a suffix is pre-formatted (in `text`).
//
// Example:
//  text                                                        DisassemblyLineKind       leaf_line   subfunction_idx
//
//  /usr/lib/x86_64-linux-gnu/libc.so.6                         Intro
//  dwarf offset: 0x1bee14                                      Intro
//                                                              Intro
//                         futex-internal.c:138:1               LeafLineNumber            138
//  7ffff7c91030 <  +0>    endbr64                              Instruction               138
//  7ffff7c91034 <  +4>    push r13                             Instruction               138
//  7ffff7c91036 <  +6>    mov r13d,esi                         Instruction               138
//                         futex-internal.c:138:1               LeafLineNumber            138
//  7ffff7c91039 <  +9>    push r12                             Instruction               138
//  7ffff7c9103b <  +b>    push rbx                             Instruction               138
//  7ffff7c9103c <  +c>    sub rsp,20h                          Instruction               138
//                         futex-internal.c:139:10              InlinedCallLineNumber     139         
//                         __futex_abstimed_wait_common         InlinedFunctionName       139
//                         ┆futex-internal.c:77:6               LeafLineNumber            77          42 (or whatever the idx of this inlined __futex_abstimed_wait_common is)
//  7ffff7c91040 < +10>    ┆test rcx,rcx                        Instruction               77          42
//  7ffff7c91043 < +13>  ↓ ┆jne near _+100h                     Instruction               77          42
//                         ┆futex-internal.c:80:6               LeafLineNumber            80          42
//  7ffff7c91049 < +19>    ┆cmp edx,1                           Instruction               80          42

pub struct Disassembly {
    pub text: StyledText,
    pub lines: Vec<DisassemblyLineInfo>, // parallel to `text` lines
    pub error: Option<Error>, // also baked into `lines`

    pub max_abs_relative_addr: usize,
    pub indent_width: usize,
    pub widest_line: usize,

    // Don't want to hold an Arc<Symbols> here, we look it up in SymbolsRegistry every frame. This shard_idx is just to assert that we found the correct one (so `subfunction` indices will match).
    pub symbols_shard: Option<usize>,
}

// Information about one line of text in the disassembly listing.
pub struct DisassemblyLineInfo {
    pub kind: DisassemblyLineKind,

    //  7ffff7c91043 < +13>  ↓ ┆jne near _+100h
    //  ^^^^^^^^^^^^   ^^^   ^  ^^^^^^^^^^^^^^^
    // static_addr     |     | |     `text`
    //     relative_addr     | |
    //          jump_indicator |
    //         subfunction_level

    // Address of the current or next instruction. For Intro: 0. For Error: usize::MAX. Binary-searchable. Should be rendered only for DisassemblyLineKind::Instruction.
    pub static_addr: usize,

    pub relative_addr: isize,
    pub jump_indicator: char,
    pub jump_target: Option<usize>,
    pub is_statement: bool,

    // Line number for the current or previous LeafLineNumber or InlinedCallLineNumber.
    pub leaf_line: Option<LineInfo>,
    // Innermost inlined function containing this line. For InlinedCallLineNumber and InlinedCallFunctionName: the *parent* subfunction (if any). Level always >= 1.
    pub subfunction: Option<usize>,
    pub subfunction_level: u16, // `subfunction` level, 0 if None; indentation level
}
impl Default for DisassemblyLineInfo { fn default() -> Self { Self {kind: DisassemblyLineKind::Error, static_addr: 0, relative_addr: 0, jump_indicator: ' ', jump_target: None, is_statement: false, subfunction_level: 0, leaf_line: None, subfunction: None} } }

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum DisassemblyLineKind {
    Intro,
    InlinedCallLineNumber,
    InlinedFunctionName,
    LeafLineNumber,
    Instruction,
    Separator,
    Error,
}

impl Disassembly {
    pub fn new() -> Self { Self {text: StyledText::default(), lines: Vec::new(), error: None, max_abs_relative_addr: 0, indent_width: 1, widest_line: 0, symbols_shard: None} }

    pub fn static_addr_to_line(&self, static_addr: usize) -> Option<usize> {
        let idx = self.lines.partition_point(|l| l.static_addr <= static_addr);
        if idx > 0 && self.lines[idx-1].static_addr == static_addr && self.lines[idx-1].kind == DisassemblyLineKind::Instruction {
            Some(idx-1)
        } else {
            None
        }
    }

    // If pseudo_addr is in between instructions, round down to the previous instruction.
    // If pseudo_addr is out of range, return either first or last line (whichever is closed), with `found` = false.
    pub fn static_pseudo_addr_to_line(&self, static_pseudo_addr: usize) -> (usize, /*found*/ bool) {
        let idx = self.lines.partition_point(|l| l.static_addr <= static_pseudo_addr);
        if idx == 0 { return (0, false); }
        let l = &self.lines[idx-1];
        // (Would be better to compare to function addr ranges instead of the MAX_X86_INSTRUCTION_BYTES guesswork.)
        if l.kind == DisassemblyLineKind::Instruction && l.static_addr + MAX_X86_INSTRUCTION_BYTES > static_pseudo_addr {
            (idx-1, true)
        } else {
            (idx-1, false)
        }
    }

    pub fn with_error(mut self, e: Error, palette: &Palette) -> Self {
        assert!(self.error.is_none());
        styled_writeln!(self.text, palette.error, "{}", e);
        self.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Error, static_addr: usize::MAX, ..Default::default()});
        self.error = Some(e);
        self.finish()
    }

    pub fn finish(mut self) -> Self {
        assert_eq!(self.text.num_lines(), self.lines.len());
        for i in 0..self.lines.len() {
            self.widest_line = self.widest_line.max(self.lines[i].subfunction_level as usize * self.indent_width + str_width(self.text.get_line_str(i)));
            self.max_abs_relative_addr = self.max_abs_relative_addr.max(self.lines[i].relative_addr.abs() as usize);
        }
        self
    }

    // Memory listings have no source/inline lines. Restart before the last 14 bytes:
    // a partial x86 instruction can have been emitted as several invalid instructions.
    pub fn extend_memory(&mut self, range: Range<usize>, old_end: usize, code: &[u8], palette: &Palette) {
        assert!(self.error.is_none() && !self.lines.is_empty());
        let line = self.lines.partition_point(|l| l.static_addr <= old_end.saturating_sub(MAX_X86_INSTRUCTION_BYTES - 1)).saturating_sub(1);
        let restart = self.lines[line].static_addr;
        let mut tail = disassemble_memory(restart..range.end, &code[restart - range.start..], StyledText::default(), palette);
        for l in &mut tail.lines {
            l.relative_addr += (restart - range.start) as isize;
        }
        let spans = self.text.lines[line];
        self.text.chars.truncate(self.text.spans[spans].0);
        self.text.spans.truncate(spans + 1);
        self.text.lines.truncate(line + 1);
        self.lines.truncate(line);
        self.text.import_lines(&tail.text, 0..tail.lines.len());
        self.lines.extend(tail.lines);
        self.widest_line = self.widest_line.max(tail.widest_line);
        self.max_abs_relative_addr = self.lines.last().map_or(0, |l| l.relative_addr as usize);
    }
}

struct StyledFormatter<'a> {
    palette: &'a Palette,
    text: &'a mut StyledText,
}

impl<'a> FormatterOutput for StyledFormatter<'a> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        use FormatterTextKind::*;
        let s = match kind {
            Directive | Keyword => self.palette.disas_keyword,
            Prefix | Mnemonic => self.palette.disas_mnemonic,
            Register => self.palette.disas_register,
            Number => self.palette.disas_number,
            Function => self.palette.disas_function,
            _ => self.palette.disas_default,
        };

        self.text.chars.push_str(text);
        self.text.close_span(s);
    }
}

struct Resolver<'a> {
    symbols: Option<&'a Symbols>,
    current_function: core::ops::Range<usize>,
}

impl<'a> SymbolResolver for Resolver<'a> {
    fn symbol(&mut self, _: &Instruction, _operand: u32, _instruction_operand: Option<u32>, static_addr: u64, _address_size: u32) -> Option<SymbolResult<'a>> {
        let static_addr = static_addr as usize;
        if self.current_function.contains(&static_addr) {
            // Make jumps inside current function easier to read: "_+42h" instead of "__futex_abstimed_wait_cancelable64+42h".
            return Some(SymbolResult {address: self.current_function.start as u64, text: SymResTextInfo::new("_", FormatterTextKind::Function), flags: SymbolFlags::NONE, symbol_size: Some(MemorySize::UInt64)});
        }

        if let Some(symbols) = &self.symbols {
            if let Ok((f, _)) = symbols.addr_to_function(static_addr) {
                let name = f.demangle_name();
                let text = SymResString::String(name);
                return Some(SymbolResult {address: f.addr.addr().unwrap() as u64, text: SymResTextInfo::Text(SymResTextPart {text, color: FormatterTextKind::Function}), flags: SymbolFlags::NONE, symbol_size: Some(MemorySize::UInt64)});
            }
        }
        None
    }
}

pub fn disassemble_function(function_idx: usize, static_addr_ranges: Vec<Range<usize>>, symbols: &Symbols, intro: StyledText, palette: &Palette) -> Disassembly {
    disassemble_addr_ranges(Some((function_idx, symbols)), static_addr_ranges, None, intro, palette)
}

pub fn disassemble_memory(range: Range<usize>, code: &[u8], intro: StyledText, palette: &Palette) -> Disassembly {
    disassemble_addr_ranges(None, vec![range], Some(code), intro, palette)
}

fn disassemble_addr_ranges(function: Option<(usize, &Symbols)>, mut addr_ranges: Vec<Range<usize>>, memory_code: Option<&[u8]>, intro: StyledText, palette: &Palette) -> Disassembly {
    clean_up_ranges(&mut addr_ranges);

    let mut res = Disassembly {text: intro, lines: Vec::new(), error: None, max_abs_relative_addr: 0, indent_width: str_width(&palette.tree_indent.0), widest_line: 0, symbols_shard: None};
    let mut subfunc_idxs: Vec<Range<usize>> = Vec::new();
    let mut subfunctions: &[Subfunction] = &[];
    let mut seen_subfunction_identities: HashSet<u32> = HashSet::new();

    while res.lines.len() < res.text.num_lines() {
        res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Intro, static_addr: 0, ..Default::default()});
    }

    if let Some((function_idx, symbols)) = function {
        let function = &symbols.functions[function_idx];
        res.symbols_shard = Some(function.shard_idx());
        subfunc_idxs = (1..function.num_levels()).map(|i| symbols.subfunction_idxs_at_level(i, function)).collect();
        subfunctions = &symbols.shards[function.shard_idx()].subfunctions;
    }

    for (addr_range_idx, static_addr_range) in addr_ranges.iter().enumerate() {
        if static_addr_range.len() > 100_000_000 {
            return res.with_error(error!(Sanity, "{} MB to disassemble, suspiciously much", static_addr_range.len() / 1_000_000), palette);
        }

        let code: &[u8] = if let Some(code) = memory_code {
            assert_eq!(addr_ranges.len(), 1);
            code
        } else if let Some((_, symbols)) = function {
            // Read the machine code from file rather than memory so that it doesn't show our breakpoint instructions.
            match symbols.elves[0].addr_range_to_offset_range(static_addr_range.start, static_addr_range.end) {
                None => return res.with_error(error!(Dwarf, "function address range out of bounds of executable: {:x}-{:x}", static_addr_range.start, static_addr_range.end), palette),
                Some((start, end)) => &symbols.elves[0].data()[start..end],
            }
        } else {
            panic!("huh");
        };

        if addr_range_idx != 0 {
            styled_write!(res.text, palette.disas_default,  "──────────");
            res.text.close_line();
            res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Separator, static_addr: static_addr_range.start, ..Default::default()});
        }

        // Memory tabs use runtime branch targets. Unlike function-relative labels,
        // these remain stable when a tab grows and formerly external targets enter it.
        let resolver = Resolver {symbols: function.map(|(_, symbols)| symbols), current_function: if function.is_some() {static_addr_range.clone()} else {0..0}};
        // NasmFormatter wants to own the symbol resolver for some reason. (Probably it would be too inconvenient or inefficient to have lifetime argument all throughout the formatter implementation.)
        // We trust that the SymbolResolver reference isn't retained after the formatter is destroyed, so it should be ok to fudge the lifetime here.
        let resolver: Resolver<'static> = unsafe { std::mem::transmute(resolver) };

        let mut decoder = Decoder::with_ip(64, code, static_addr_range.start as u64, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::with_options(Some(Box::new(resolver)), None);

        let mut line_iter = if let Some((_, symbols)) = function {
            let mut line_iter = symbols.addr_to_line_iter(static_addr_range.start).peekable();
            line_iter.next_if(|line| line.addr() < static_addr_range.start);
            Some(line_iter)
        } else {
            None
        };

        let mut instruction = Instruction::default();
        let mut prev_static_addr = 0usize;
        let mut cur_leaf_line: Option<LineInfo> = None;

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if let Some(l) = res.lines.last() {
                assert!(instruction.ip() as usize >= l.static_addr); // can be == because the "-----[...]" separator above is assigned to address of the first instruction after it
            }
            let static_addr = instruction.ip() as usize;
            let mut subfunction_level = 0u16;
            let mut cur_subfunction: Option<usize> = None;
            let mut is_statement = false;

            if let Some((function_idx, symbols)) = function {
                let write_line_number = |line: LineInfo, kind: DisassemblyLineKind, res: &mut Disassembly, subfunction_level: u16, leaf_line: &mut Option<LineInfo>, subfunction: Option<usize>| {
                    let file = match line.file_idx() {
                        None => return,
                        Some(f) => f };
                    *leaf_line = Some(line.clone());
                    let file = &symbols.files[file];
                    let name = file.filename.as_os_str().to_string_lossy();
                    styled_write!(res.text, palette.disas_filename, "{}", name);
                    if line.line() != 0 {
                        styled_write!(res.text, palette.line_number, ":{}", line.line());
                        if line.column() != 0 {
                            styled_write!(res.text, palette.column_number, ":{}", line.column());
                        }
                    }
                    res.text.close_line();
                    res.lines.push(DisassemblyLineInfo {kind, static_addr, subfunction_level, leaf_line: leaf_line.clone(), subfunction, ..Default::default()});
                };

                // Add inlined function calls information: function names, call line numbers, and indentation.
                let function = &symbols.functions[function_idx];
                for r in subfunc_idxs.iter_mut() {
                    while r.start < r.end && subfunctions[r.start].addr_range.end <= static_addr {
                        r.start += 1;
                    }
                    if r.start == r.end || subfunctions[r.start].addr_range.start > static_addr {
                        break;
                    }
                    cur_subfunction = Some(r.start);
                    let subfunction = &subfunctions[r.start];
                    subfunction_level += 1;
                    if subfunction.addr_range.start > prev_static_addr {
                        let callee_name = if subfunction.callee_idx == usize::MAX {
                            "?".to_string()
                        } else {
                            symbols.functions[subfunction.callee_idx].demangle_name()
                        };

                        write_line_number(subfunction.call_line.clone(), DisassemblyLineKind::InlinedCallLineNumber, &mut res, subfunction_level, &mut cur_leaf_line, cur_subfunction.clone());

                        styled_write!(res.text, palette.default_dim, "{}", callee_name);

                        if !seen_subfunction_identities.insert(subfunction.identity) {
                            // Indicate that the inlined function has multiple address ranges.
                            styled_write!(res.text, palette.default_dim, " [cont]");
                        }
                        res.text.close_line();
                        res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::InlinedFunctionName, static_addr, subfunction_level, leaf_line: cur_leaf_line.clone(), subfunction: cur_subfunction.clone(), ..Default::default()});
                    }
                }

                // Add line number information.
                while let Some(line) = line_iter.as_mut().unwrap().next_if(|line| line.addr() <= static_addr) {
                    write_line_number(line, DisassemblyLineKind::LeafLineNumber, &mut res, subfunction_level, &mut cur_leaf_line, cur_subfunction.clone());

                    if line.addr() == static_addr && line.flags().contains(LineFlags::STATEMENT) {
                        is_statement = true;
                    }
                }
            }

            prev_static_addr = static_addr;

            let mut jump_target: Option<usize> = None;
            let jump_indicator = match instruction.flow_control() {
                FlowControl::Next => ' ',
                FlowControl::Return => '←',
                FlowControl::Call | FlowControl::IndirectCall => '→',
                FlowControl::Interrupt | FlowControl::XbeginXabortXend | FlowControl::Exception => '!',
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::ConditionalBranch => {
                    let target_known = instruction.flow_control() != FlowControl::IndirectBranch && match instruction.op0_kind() {
                        iced_x86::OpKind::NearBranch16 | iced_x86::OpKind::NearBranch32 | iced_x86::OpKind::NearBranch64 => true,
                        _ => false };
                    if !target_known {
                        '↕'
                    } else {
                        jump_target = Some(instruction.near_branch_target() as usize);
                        if instruction.near_branch_target() > instruction.ip() {
                            '↓'
                        } else {
                            '↑'
                        }
                    }
                }
            };

            // Finally write the actual asm instruction.
            formatter.format(&instruction, &mut StyledFormatter {palette, text: &mut res.text});

            res.text.close_line();
            res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Instruction, static_addr, relative_addr: static_addr as isize - static_addr_range.start as isize, subfunction_level, jump_indicator, jump_target, is_statement, leaf_line: cur_leaf_line.clone(), subfunction: cur_subfunction.clone()});
        }
    }
    res.finish()
}

pub fn instruction_stream_has_boundary(code: &[u8], range_start: usize, ip: usize) -> bool {
    if ip < range_start || ip >= range_start.saturating_add(code.len()) {
        return false;
    }
    let mut decoder = Decoder::with_ip(64, code, range_start as u64, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.ip() as usize > ip {
            return false;
        }
        if instruction.ip() as usize == ip {
            return true;
        }
    }
    false
}

/// Finds a unique candidate instruction stream at or before `ip`.
/// `ip` is assumed to be a real instruction pointer, so candidates are kept only
/// if decoding from them reaches `ip` as an instruction start.
///
/// This probes candidate stream starts near `probe_start`, up to one maximum x86
/// instruction length away. `probe_len` bounds the accepted probe window, but the
/// caller is expected to advance `probe_start` when it wants to test later starts.
pub fn find_unique_instruction_start_before_ip(code: &[u8], range_start: usize, probe_start: usize, probe_len: usize, ip: usize) -> Option<usize> {
    let range_end = range_start.saturating_add(code.len());
    if probe_start < range_start || probe_start >= range_end || ip < probe_start || ip >= range_end || probe_len == 0 {
        return None;
    }
    let last_probe_start = probe_start.saturating_add(probe_len).min(range_end - 1);
    let last_start = ip.min(last_probe_start);
    if last_start < probe_start {
        return None;
    }

    let mut found = None;
    let initial_last_start = probe_start.saturating_add(MAX_X86_INSTRUCTION_BYTES - 1).min(last_start);
    for start in probe_start..=initial_last_start {
        if instruction_stream_has_boundary(&code[start - range_start..], start, ip) {
            if found.is_some() {
                return None;
            }
            found = Some(start);
        }
    }
    found
}

pub fn find_best_instruction_start_before_addr(code: &[u8], range_start: usize, probe_start: usize, probe_len: usize, addr: usize, ip_anchor: Option<usize>) -> Option<usize> {
    let range_end = range_start.saturating_add(code.len());
    if probe_start < range_start || probe_start >= range_end || addr < probe_start || addr >= range_end {
        return None;
    }
    let ip_anchor = ip_anchor.filter(|ip| range_start <= *ip && *ip < range_end);
    if probe_len == 0 {
        return None;
    }
    let last_probe_start = probe_start.saturating_add(probe_len).min(range_end - 1);

    let first_start = addr.saturating_sub(MAX_X86_INSTRUCTION_BYTES - 1).max(probe_start);
    let last_start = addr.min(last_probe_start);
    if first_start > last_start {
        return None;
    }
    let mut best: Option<(usize, usize)> = None; // (decoded_until, instruction_start)

    for start in first_start..=last_start {
        let mut decoder = Decoder::with_ip(64, &code[start - range_start..], start as u64, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            continue;
        }
        let instruction_start = instruction.ip() as usize;
        let instruction_end = instruction_start.saturating_add(instruction.len());
        if instruction_start <= addr && addr < instruction_end {
            let mut decoded_until = instruction_end;
            let mut saw_ip_anchor = ip_anchor.map_or(true, |ip| instruction_start == ip);
            while decoder.can_decode() && decoded_until < range_end {
                let instruction = decoder.decode();
                if instruction.is_invalid() || instruction.len() == 0 {
                    break;
                }
                if ip_anchor == Some(instruction.ip() as usize) {
                    saw_ip_anchor = true;
                }
                decoded_until = instruction.ip().saturating_add(instruction.len() as u64) as usize;
            }
            // If we know nearby RIP, use it as a hard instruction-boundary anchor: real execution
            // can only stop at instruction starts, which disambiguates many valid-but-wrong x86 decodes.
            if !saw_ip_anchor {
                continue;
            }

            // Prefer the stream that remains valid the longest; if alternatives converge equally far,
            // use the earliest start so manual `g` can recover from landing inside a real instruction.
            if best.map_or(true, |(best_until, best_start)| decoded_until > best_until || decoded_until == best_until && instruction_start < best_start) {
                best = Some((decoded_until, instruction_start));
            }
        }
    }
    best.map(|(_, instruction_start)| instruction_start)
}

fn clean_up_ranges(ranges: &mut Vec<Range<usize>>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|r| r.start);
    let mut j = 0;
    for i in 1..ranges.len() {
        if ranges[i].start > ranges[j].end {
            // Normal case.
            j += 1;
            ranges[j] = ranges[i].clone();
        } else if ranges[i].end <= ranges[j].end {
            // This range is contained in another. Discard.
        } else {
            // This range overlaps another. Extend.
            ranges[j].end = ranges[i].end;
        }
    }
    ranges.truncate(j+1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_instruction_stream() {
        // Every suffix of these prefixes is valid: reaching RIP doesn't prove a start.
        let code = [0x66, 0x66, 0x90, 0xc3];
        assert_eq!(find_unique_instruction_start_before_ip(&code, 0x1000, 0x1000, code.len(), 0x1003), None);
        // A unique stream before a return address can recover the containing instruction.
        let code = [0x0f, 0x05, 0xc3];
        assert_eq!(find_unique_instruction_start_before_ip(&code, 0x1000, 0x1000, 1, 0x1002), Some(0x1000));
    }

    #[test]
    fn containing_instruction_and_anchor() {
        // syscall; ret. The second syscall byte alone is an incomplete add instruction.
        let code = [0x0f, 0x05, 0xc3];
        assert_eq!(find_best_instruction_start_before_addr(&code, 0x1000, 0x1000, code.len(), 0x1001, None), Some(0x1000));
        // Both "mov eax, 1" and a stream beginning at its immediate can decode.
        let code = [0xb8, 1, 0, 0, 0, 0xc3];
        assert_eq!(find_best_instruction_start_before_addr(&code, 0x1000, 0x1000, code.len(), 0x1001, Some(0x1000)), Some(0x1000));
        assert_eq!(find_best_instruction_start_before_addr(&code, 0x1000, 0x1000, code.len(), 0x1001, Some(0x1001)), Some(0x1001));
        // Rewritten JIT code: an old start at +2 now lies inside lea, before ret at +3.
        let replacement = [0x8d, 0x04, 0x7f, 0xc3];
        assert!(instruction_stream_has_boundary(&replacement, 0x1000, 0x1003));
        assert!(!instruction_stream_has_boundary(&replacement[2..], 0x1002, 0x1003));
    }

    #[test]
    fn incremental_memory_disassembly() {
        // Include a maximum-length instruction, invalid bytes, and branches crossing
        // the old window edge. Every possible split must match a single full decode.
        let code = [
            0xeb, 0x0f,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90,
            0x06, 0xb8, 1, 0, 0, 0, 0xeb, 0xe7, 0xc3,
        ];
        let palette = Palette::default();
        let range = 0x1000..0x1000 + code.len();
        let full = disassemble_memory(range.clone(), &code, StyledText::default(), &palette);
        for split in 1..code.len() {
            let mut incremental = disassemble_memory(range.start..range.start + split, &code[..split], StyledText::default(), &palette);
            incremental.extend_memory(range.clone(), range.start + split, &code, &palette);
            assert_eq!(incremental.text.chars, full.text.chars, "split: {}", split);
            let lines = |d: &Disassembly| d.lines.iter().map(|l| (l.static_addr, l.relative_addr, l.jump_target, l.jump_indicator)).collect::<Vec<_>>();
            assert_eq!(lines(&incremental), lines(&full), "split: {}", split);
            assert_eq!(incremental.text.lines, full.text.lines, "split: {}", split);
        }
    }
}
