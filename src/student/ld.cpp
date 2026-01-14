#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <cstring>

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

//记录已解析符号的信息
struct ResolvedSymbol {
    uint64_t vaddr;
    SymbolType type;
};

FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    FLEObject executable;
    executable.type = ".exe";
    executable.name = options.outputFile;

    const uint64_t BASE_ADDR = 0x400000;
    
    //记录每个节在合并后的全局buffer中的偏移
    std::map<std::pair<size_t, std::string>, uint64_t> section_offsets;
    std::vector<uint8_t> merged_data;

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            section_offsets[{i, sec_name}] = merged_data.size();
            merged_data.insert(merged_data.end(), sec_data.data.begin(), sec_data.data.end());
        }
    }

    //符号决议逻辑
    std::map<std::string, ResolvedSymbol> global_symbol_table;
    //local_symbols[file_index][symbol_name] = vaddr
    std::vector<std::map<std::string, uint64_t>> local_symbol_tables(objects.size());

    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& sym : objects[i].symbols) {
            //跳过未定义符号
            if (sym.type == SymbolType::UNDEFINED || sym.section.empty()) continue;

            uint64_t vaddr = BASE_ADDR + section_offsets[{i, sym.section}] + sym.offset;

            if (sym.type == SymbolType::LOCAL) {
                //局部符号：存入文件私有表，不参与全局冲突检查
                local_symbol_tables[i][sym.name] = vaddr;
            } 
            else if (sym.type == SymbolType::GLOBAL || sym.type == SymbolType::WEAK) {
                //全局符号决议规则
                if (global_symbol_table.count(sym.name)) {
                    SymbolType existing_type = global_symbol_table[sym.name].type;

                    if (sym.type == SymbolType::GLOBAL && existing_type == SymbolType::GLOBAL) {
                        //两个强符号冲突
                        throw std::runtime_error("Multiple definition of strong symbol: " + sym.name);
                    } 
                    else if (sym.type == SymbolType::GLOBAL && existing_type == SymbolType::WEAK) {
                        //强符号覆盖弱符号
                        global_symbol_table[sym.name] = {vaddr, sym.type};
                    }
                    //其他情况（弱遇强、弱遇弱）保持现有符号不变
                } else {
                    //新符号，直接加入
                    global_symbol_table[sym.name] = {vaddr, sym.type};
                }
            }
        }
    }

    //处理重定位并检查未定义符号
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            uint64_t sec_base_in_merged = section_offsets[{i, sec_name}];

            for (const auto& reloc : sec_data.relocs) {
                uint64_t S = 0;
                bool found = false;

                //优先查找本文件的局部符号
                if (local_symbol_tables[i].count(reloc.symbol)) {
                    S = local_symbol_tables[i][reloc.symbol];
                    found = true;
                } 
                //其次查找全局符号表
                else if (global_symbol_table.count(reloc.symbol)) {
                    S = global_symbol_table[reloc.symbol].vaddr;
                    found = true;
                }

                if (!found) {
                    throw std::runtime_error("Undefined symbol: " + reloc.symbol);
                }

                int64_t A = reloc.addend;
                uint64_t P = BASE_ADDR + sec_base_in_merged + reloc.offset;
                uint64_t result_val = 0;
                size_t write_size = 0;

                switch (reloc.type) {
                    case RelocationType::R_X86_64_32:
                    case RelocationType::R_X86_64_32S:
                        result_val = S + A;
                        write_size = 4;
                        break;
                    case RelocationType::R_X86_64_64:
                        result_val = S + A;
                        write_size = 8;
                        break;
                    case RelocationType::R_X86_64_PC32:
                        result_val = (uint64_t)((int64_t)S + A - (int64_t)P);
                        write_size = 4;
                        break;
                    default: continue;
                }
                write_le(merged_data, sec_base_in_merged + reloc.offset, result_val, write_size);
            }
        }
    }

    //构建输出结果
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

    //检查入口点
    if (global_symbol_table.count(options.entryPoint)) {
        executable.entry = global_symbol_table[options.entryPoint].vaddr;
    } else if (!options.shared) {
        throw std::runtime_error("Undefined symbol: " + options.entryPoint);
    }

    return executable;
}
