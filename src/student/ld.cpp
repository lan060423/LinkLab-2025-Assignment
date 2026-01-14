#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <cstring>

//辅助函数：将数值以小端序写入字节数组
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
    
    //记录每个文件中每个节在合并后的全局buffer中的偏移量
    std::map<std::pair<size_t, std::string>, uint64_t> section_offsets;
    std::vector<uint8_t> merged_data;

    //第一步：扫描所有目标文件，合并节内容，将所有输入文件的所有节按顺序拼接在一起
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            //记录该节在合并后的缓冲区中的起始位置
            section_offsets[{i, sec_name}] = merged_data.size();
            //将数据追加到缓冲区
            merged_data.insert(merged_data.end(), sec_data.data.begin(), sec_data.data.end());
        }
    }

    //第二步：收集所有定义的符号，建立全局符号表
    //key: 符号名,value: 最终虚拟地址
    std::map<std::string, uint64_t> global_symbol_table;
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& sym : objects[i].symbols) {
            //只处理已定义的符号（GLOBAL, LOCAL, WEAK）
            if (sym.type != SymbolType::UNDEFINED && !sym.section.empty()) {
                uint64_t sec_start = section_offsets[{i, sym.section}];
                uint64_t sym_vaddr = BASE_ADDR + sec_start + sym.offset;
                
                // 基础链接器暂不处理符号冲突，简单的“先到先得”或覆盖
                global_symbol_table[sym.name] = sym_vaddr;
            }
        }
    }

    //第三步：处理重定位
    //再次遍历所有节的重定位表，修改merged_data中的占位符
    for (size_t i = 0; i < objects.size(); ++i) {
        for (const auto& [sec_name, sec_data] : objects[i].sections) {
            uint64_t sec_base_in_merged = section_offsets[{i, sec_name}];

            for (const auto& reloc : sec_data.relocs) {
                //查找引用的符号地址
                if (global_symbol_table.find(reloc.symbol) == global_symbol_table.end()) {
                    throw std::runtime_error("Undefined reference to symbol: " + reloc.symbol);
                }

                uint64_t S = global_symbol_table[reloc.symbol]; //符号地址
                int64_t A = reloc.addend;                       //显式加数
                uint64_t P = BASE_ADDR + sec_base_in_merged + reloc.offset; //重定位处的虚拟地址
                
                uint64_t write_val = 0;
                size_t write_size = 0;

                //根据重定位类型计算值
                if (reloc.type == RelocationType::R_X86_64_32 || 
                    reloc.type == RelocationType::R_X86_64_32S) {
                    //32位绝对地址：S + A
                    write_val = S + A;
                    write_size = 4;
                } 
                else if (reloc.type == RelocationType::R_X86_64_64) {
                    //64位绝对地址：S + A
                    write_val = S + A;
                    write_size = 8;
                }
                else if (reloc.type == RelocationType::R_X86_64_PC32) {
                    //32位相对地址：S + A - P (task3重点，这里先放好逻辑)
                    write_val = S + A - P;
                    write_size = 4;
                }
                else {
                    //task2主要关注32和32S
                    continue; 
                }

                //将计算结果写回merged_data
                write_le(merged_data, sec_base_in_merged + reloc.offset, write_val, write_size);
            }
        }
    }

    //第四步：构建输出的FLEObject

    //创建一个大的合并节
    FLESection load_section;
    load_section.name = ".load";
    load_section.data = std::move(merged_data);
    executable.sections[".load"] = load_section;

    //创建程序头
    ProgramHeader phdr;
    phdr.name = ".load";
    phdr.vaddr = BASE_ADDR;
    phdr.size = executable.sections[".load"].data.size();
    //赋予所有权限：可读、可写、可执行
    phdr.flags = (uint32_t)PHF::R | (uint32_t)PHF::W | (uint32_t)PHF::X;
    executable.phdrs.push_back(phdr);

    //设置入口点
    if (global_symbol_table.count(options.entryPoint)) {
        executable.entry = global_symbol_table[options.entryPoint];
    } else {
        //如果找不到_start且不是生成共享库，则抛出错误
        if (!options.shared) {
            throw std::runtime_error("Entry point '" + options.entryPoint + "' not found.");
        }
    }

    return executable;
}
