#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <cstring>

/*
辅助函数：将数值以小端序写入字节数组
size 为写入的字节数（4 或 8）
 */
void write_le(std::vector<uint8_t>& data, size_t offset, uint64_t value, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (offset + i < data.size()) {
            data[offset + i] = (value >> (i * 8)) & 0xff;
        }
    }
}

FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    FLEObject executable;
    executable.type = ".exe";
    executable.name = options.outputFile;

    const uint64_t BASE_ADDR = 0x400000;
    
    std::map<std::pair<size_t, std::string>, uint64_t> section_offsets;
    std::vector<uint8_t> merged_data;

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            section_offsets[{i, sec_name}] = merged_data.size();
            merged_data.insert(merged_data.end(), sec_data.data.begin(), sec_data.data.end());
        }
    }

    std::map<std::string, uint64_t> global_symbol_table;
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& sym : objects[i].symbols) {
            //只处理已定义的符号
            if (sym.type != SymbolType::UNDEFINED && !sym.section.empty()) {
                //确保引用的节在objects[i]中确实存在
                if (section_offsets.count({i, sym.section})) {
                    uint64_t sec_start = section_offsets[{i, sym.section}];
                    uint64_t sym_vaddr = BASE_ADDR + sec_start + sym.offset;
                    
                    global_symbol_table[sym.name] = sym_vaddr;
                }
            }
        }
    }

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            uint64_t sec_base_in_merged = section_offsets[{i, sec_name}];

            for (const auto& reloc : sec_data.relocs) {
                //查找目标符号地址S
                if (global_symbol_table.find(reloc.symbol) == global_symbol_table.end()) {
                    throw std::runtime_error("Undefined reference to symbol: " + reloc.symbol);
                }
                uint64_t S = global_symbol_table[reloc.symbol];
                
                //获取附加值A
                int64_t A = reloc.addend;
                
                //计算当前重定位位置的虚拟地址P
                uint64_t P = BASE_ADDR + sec_base_in_merged + reloc.offset;

                uint64_t result_val = 0;
                size_t write_size = 0;

                //根据类型执行不同的计算逻辑
                switch (reloc.type) {
                    case RelocationType::R_X86_64_32:
                    case RelocationType::R_X86_64_32S:
                        // 32位绝对地址：S + A
                        result_val = S + A;
                        write_size = 4;
                        break;

                    case RelocationType::R_X86_64_64:
                        // 64位绝对地址：S + A
                        result_val = S + A;
                        write_size = 8;
                        break;

                    case RelocationType::R_X86_64_PC32:
                        // 32位相对地址：S + A - P
                        // 注意：这里是有符号运算，S+A-P 可能为负
                        result_val = (uint64_t)((int64_t)S + A - (int64_t)P);
                        write_size = 4;
                        break;

                    default:
                        continue;
                }

                //写入合并后的缓冲区
                write_le(merged_data, sec_base_in_merged + reloc.offset, result_val, write_size);
            }
        }
    }
-
    FLESection load_section;
    load_section.name = ".load";
    load_section.data = std::move(merged_data);
    executable.sections[".load"] = load_section;

    ProgramHeader phdr;
    phdr.name = ".load";
    phdr.vaddr = BASE_ADDR;
    phdr.size = executable.sections[".load"].data.size();
    phdr.flags = (uint32_t)PHF::R | (uint32_t)PHF::W | (uint32_t)PHF::X;
    executable.phdrs.push_back(phdr);

    //入口点
    if (global_symbol_table.count(options.entryPoint)) {
        executable.entry = global_symbol_table[options.entryPoint];
    } else if (!options.shared) {
        throw std::runtime_error("Entry point '" + options.entryPoint + "' not found.");
    }

    return executable;
}
