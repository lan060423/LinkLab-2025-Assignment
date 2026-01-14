#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <string>
#include <algorithm>

/*
辅助函数：将数值以小端序写入字节数组
*/
void write_le(std::vector<uint8_t>& data, size_t offset, uint64_t value, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (offset + i < data.size()) {
            data[offset + i] = (value >> (i * 8)) & 0xff;
        }
    }
}

/*
辅助函数：判断前缀
*/
static bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

/*
核心逻辑：根据输入节的名字确定它所属的输出分类
*/
static std::string get_output_section_name(const std::string& name) {
    if (starts_with(name, ".text")) return ".text";
    if (starts_with(name, ".rodata")) return ".rodata";
    if (starts_with(name, ".data")) return ".data";
    if (starts_with(name, ".bss")) return ".bss";
    return ".data"; //默认归类为数据段
}

struct ResolvedSymbol {
    uint64_t vaddr;
    SymbolType type;
};

//记录输入节在输出节中的位置信息
struct SectionLocation {
    std::string out_sec_name;
    uint64_t offset_in_out_sec;
};

FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    FLEObject executable;
    executable.type = ".exe";
    executable.name = options.outputFile;

    //扫描并合并节：按类别分组
    //定义输出节的顺序，保证布局稳定
    std::vector<std::string> out_sec_order = {".text", ".rodata", ".data", ".bss"};
    std::map<std::string, std::vector<uint8_t>> out_sec_buffers;
    //key: {file_idx, input_sec_name} -> {output_sec_name, offset_in_buffer}
    std::map<std::pair<size_t, std::string>, SectionLocation> sec_map;

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [name, sec] : objects[i].sections) {
            std::string out_name = get_output_section_name(name);
            uint64_t current_offset = out_sec_buffers[out_name].size();
            
            sec_map[{i, name}] = {out_name, current_offset};
            out_sec_buffers[out_name].insert(
                out_sec_buffers[out_name].end(), 
                sec.data.begin(), 
                sec.data.end()
            );
        }
    }

    //规划内存布局：计算每个输出节的起始 VAddr
    uint64_t current_vaddr = 0x400000;
    std::map<std::string, uint64_t> out_sec_vaddrs;

    for (const auto& name : out_sec_order) {
        if (out_sec_buffers.count(name) && !out_sec_buffers[name].empty()) {
            out_sec_vaddrs[name] = current_vaddr;
            current_vaddr += out_sec_buffers[name].size();
        }
    }

    //符号决议：计算符号的绝对虚拟地址
    std::map<std::string, ResolvedSymbol> global_sym_table;
    std::vector<std::map<std::string, uint64_t>> local_sym_tables(objects.size());

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& sym : objects[i].symbols) {
            if (sym.type == SymbolType::UNDEFINED || sym.section.empty()) continue;

            auto loc = sec_map[{i, sym.section}];
            uint64_t sym_vaddr = out_sec_vaddrs[loc.out_sec_name] + loc.offset_in_out_sec + sym.offset;

            if (sym.type == SymbolType::LOCAL) {
                local_sym_tables[i][sym.name] = sym_vaddr;
            } else {
                if (global_sym_table.count(sym.name)) {
                    if (sym.type == SymbolType::GLOBAL && global_sym_table[sym.name].type == SymbolType::GLOBAL) {
                        throw std::runtime_error("Multiple definition of strong symbol: " + sym.name);
                    }
                    if (sym.type == SymbolType::GLOBAL) {
                        global_sym_table[sym.name] = {sym_vaddr, sym.type};
                    }
                } else {
                    global_sym_table[sym.name] = {sym_vaddr, sym.type};
                }
            }
        }
    }

    //重定位：在正确的输出buffer中修改数据
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [name, sec] : objects[i].sections) {
            auto loc = sec_map[{i, name}];
            uint64_t out_sec_base = out_sec_vaddrs[loc.out_sec_name];
            std::vector<uint8_t>& buffer = out_sec_buffers[loc.out_sec_name];

            for (const auto& reloc : sec.relocs) {
                uint64_t S = 0;
                if (local_sym_tables[i].count(reloc.symbol)) {
                    S = local_sym_tables[i][reloc.symbol];
                } else if (global_sym_table.count(reloc.symbol)) {
                    S = global_sym_table[reloc.symbol].vaddr;
                } else {
                    throw std::runtime_error("Undefined symbol: " + reloc.symbol);
                }

                uint64_t P = out_sec_base + loc.offset_in_out_sec + reloc.offset;
                int64_t A = reloc.addend;
                uint64_t val = 0;
                size_t sz = 0;

                switch (reloc.type) {
                    case RelocationType::R_X86_64_32:
                    case RelocationType::R_X86_64_32S: val = S + A; sz = 4; break;
                    case RelocationType::R_X86_64_64:  val = S + A; sz = 8; break;
                    case RelocationType::R_X86_64_PC32: val = S + A - P; sz = 4; break;
                    default: continue;
                }
                write_le(buffer, loc.offset_in_out_sec + reloc.offset, val, sz);
            }
        }
    }

    //组装输出FLEObject和Program Headers
    for (const auto& name : out_sec_order) {
        if (out_sec_buffers.count(name) && !out_sec_buffers[name].empty()) {
            FLESection out_sec;
            out_sec.name = name;
            out_sec.data = std::move(out_sec_buffers[name]);
            executable.sections[name] = out_sec;

            ProgramHeader phdr;
            phdr.name = name;
            phdr.vaddr = out_sec_vaddrs[name];
            phdr.size = executable.sections[name].data.size();
            //task5要求暂时统一设为RWX
            phdr.flags = (uint32_t)PHF::R | (uint32_t)PHF::W | (uint32_t)PHF::X;
            executable.phdrs.push_back(phdr);
        }
    }

    //设置入口点
    if (global_sym_table.count(options.entryPoint)) {
        executable.entry = global_sym_table[options.entryPoint].vaddr;
    } else if (!options.shared) {
        throw std::runtime_error("Undefined symbol: " + options.entryPoint);
    }

    return executable;
}
