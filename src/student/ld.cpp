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

static uint64_t align_up(uint64_t addr, uint64_t align = 4096) {
    return (addr + align - 1) / align * align;
}

/*
核心逻辑：根据输入节的名字确定它所属的输出分类
*/
static std::string get_output_section_name(const std::string& name) {
    if (starts_with(name, ".text")) return ".text";
    if (starts_with(name, ".rodata")) return ".rodata";
    if (starts_with(name, ".data")) return ".data";
    if (starts_with(name, ".bss")) return ".bss";
    return ".data"; 
}

struct ResolvedSymbol {
    uint64_t vaddr;
    SymbolType type;
};

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
    //强制顺序：.text -> .rodata -> .data -> .bss
    std::vector<std::string> out_sec_order = {".text", ".rodata", ".data", ".bss"};
    std::map<std::string, std::vector<uint8_t>> out_sec_buffers;
    std::map<std::string, uint64_t> out_sec_virtual_sizes; //记录内存中的实际大小
    std::map<std::pair<size_t, std::string>, SectionLocation> sec_map;

    //第一步：合并节，使用 shdrs 获取真实大小
    for (size_t i = 0; i < objects.size(); ++i) {
        //预先建立一个节名到大小的映射，从shdrs中获取
        std::map<std::string, uint64_t> actual_sizes;
        for (const auto& shdr : objects[i].shdrs) {
            actual_sizes[shdr.name] = shdr.size;
        }

        for (const auto& [name, sec] : objects[i].sections) {
            std::string out_name = get_output_section_name(name);
            uint64_t sz = 0;
            
            //如果 shdr 中有大小，优先使用 shdr 的大小
            if (actual_sizes.count(name)) {
                sz = actual_sizes[name];
            } else {
                sz = sec.data.size();
            }

            uint64_t current_offset = out_sec_virtual_sizes[out_name];
            sec_map[{i, name}] = {out_name, current_offset};

            if (out_name != ".bss" && !sec.data.empty()) {
                out_sec_buffers[out_name].insert(
                    out_sec_buffers[out_name].end(), 
                    sec.data.begin(), 
                    sec.data.end()
                );
            }
            out_sec_virtual_sizes[out_name] += sz;
        }
    }

    //规划内存布局：实施 4KB 对齐
    uint64_t current_vaddr = 0x400000;
    std::map<std::string, uint64_t> out_sec_vaddrs;

    for (const auto& name : out_sec_order) {
        if (out_sec_virtual_sizes.count(name) && out_sec_virtual_sizes[name] > 0) {
            //每个段的起始地址都对齐到4KB边界
            current_vaddr = align_up(current_vaddr);
            out_sec_vaddrs[name] = current_vaddr;
            current_vaddr += out_sec_virtual_sizes[name];
        }
    }

    //符号决议：计算绝对虚拟地址
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

    //重定位
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [name, sec] : objects[i].sections) {
            auto loc = sec_map[{i, name}];
            //如果重定位发生在.bss 节中，这是异常的（BSS通常无代码/数据）
            //绝大多数重定位发生在 .text 或 .data 中
            if (loc.out_sec_name == ".bss") continue; 

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

    //构建输出FLEObject和权限设置
    for (const auto& name : out_sec_order) {
        if (out_sec_virtual_sizes.count(name) && out_sec_virtual_sizes[name] > 0) {
            FLESection out_sec;
            out_sec.name = name;
            //只有非 BSS 段才复制数据到section.data
            if (name != ".bss") {
                out_sec.data = std::move(out_sec_buffers[name]);
            }
            executable.sections[name] = out_sec;

            ProgramHeader phdr;
            phdr.name = name;
            phdr.vaddr = out_sec_vaddrs[name];
            phdr.size = out_sec_virtual_sizes[name]; //记录内存中的大小

            //设置精细化的权限
            if (name == ".text") {
                phdr.flags = PHF::R | PHF::X;  //代码段：只读，可执行 (r-x)
            } else if (name == ".rodata") {
                phdr.flags = static_cast<uint32_t>(PHF::R);//只读数据：只读 (r--)，单个PHF枚举值需要显式强转为uint32_t
            } else if (name == ".data" || name == ".bss") {
                phdr.flags = PHF::R | PHF::W;  //读写数据：可读写，不可执行 (rw-)
            }
            executable.phdrs.push_back(phdr);
        }
    }

    if (global_sym_table.count(options.entryPoint)) {
        executable.entry = global_sym_table[options.entryPoint].vaddr;
    } else if (!options.shared) {
        throw std::runtime_error("Undefined symbol: " + options.entryPoint);
    }

    return executable;
}
