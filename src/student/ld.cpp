#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <string>
#include <algorithm>
#include <set>

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
    if (align == 0) return addr;
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

/*
追踪符号状态
*/
struct SymbolStatus {
    std::set<std::string> defined;
    std::set<std::string> undefined;

    void add_object_symbols(const FLEObject& obj) {
        for (const auto& sym : obj.symbols) {
            if (sym.type != SymbolType::UNDEFINED && !sym.section.empty()) {
                defined.insert(sym.name);
                undefined.erase(sym.name);
            } else if (sym.type == SymbolType::UNDEFINED) {
                if (defined.find(sym.name) == defined.end()) {
                    undefined.insert(sym.name);
                }
            }
        }
        for (const auto& [name, sec] : obj.sections) {
            for (const auto& reloc : sec.relocs) {
                if (defined.find(reloc.symbol) == defined.end()) {
                    undefined.insert(reloc.symbol);
                }
            }
        }
    }
};

FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    std::vector<FLEObject> selected_objects;
    SymbolStatus status;
    std::set<std::string> included_member_names; 

    status.undefined.insert(options.entryPoint);

    //无条件包含所有命令行输入的.obj文件
    for (const auto& obj : objects) {
        if (obj.type == ".obj") {
            selected_objects.push_back(obj);
            status.add_object_symbols(obj);
        }
    }

    //迭代扫描.ar归档文件
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& input : objects) {
            if (input.type == ".ar") {
                for (const auto& member : input.members) {
                    if (included_member_names.count(member.name)) continue;

                    bool needed = false;
                    for (const auto& sym : member.symbols) {
                        if (sym.type != SymbolType::UNDEFINED && !sym.section.empty()) {
                            if (status.undefined.count(sym.name)) {
                                needed = true;
                                break;
                            }
                        }
                    }

                    if (needed) {
                        selected_objects.push_back(member);
                        status.add_object_symbols(member);
                        included_member_names.insert(member.name);
                        changed = true;
                    }
                }
            }
        }
    }

    FLEObject executable;
    //Bonus 1: 根据选项决定输出类型
    executable.type = options.shared ? ".so" : ".exe";
    executable.name = options.outputFile;

    std::vector<std::string> out_sec_order = {".text", ".rodata", ".data", ".bss"};
    std::map<std::string, std::vector<uint8_t>> out_sec_buffers;
    std::map<std::string, uint64_t> out_sec_virtual_sizes; 
    std::map<std::pair<size_t, std::string>, SectionLocation> sec_map;

    //合并节
    for (size_t i = 0; i < selected_objects.size(); ++i) {
        std::map<std::string, uint64_t> actual_sizes;
        for (const auto& shdr : selected_objects[i].shdrs) {
            actual_sizes[shdr.name] = shdr.size;
        }

        for (const auto& [name, sec] : selected_objects[i].sections) {
            std::string out_name = get_output_section_name(name);
            uint64_t sz = 0;
            if (actual_sizes.count(name)) sz = actual_sizes[name];
            else sz = sec.data.size();

            uint64_t current_offset = out_sec_virtual_sizes[out_name];
            sec_map[{i, name}] = {out_name, current_offset};

            if (out_name != ".bss" && !sec.data.empty()) {
                out_sec_buffers[out_name].insert(out_sec_buffers[out_name].end(), 
                                               sec.data.begin(), sec.data.end());
            }
            out_sec_virtual_sizes[out_name] += sz;
        }
    }

    //Bonus 1: 共享库通常以0x0为基址，可执行文件以0x400000为基址
    uint64_t current_vaddr = options.shared ? 0x0 : 0x400000;
    std::map<std::string, uint64_t> out_sec_vaddrs;

    for (const auto& name : out_sec_order) {
        if (out_sec_virtual_sizes.count(name) && out_sec_virtual_sizes[name] > 0) {
            current_vaddr = align_up(current_vaddr);
            out_sec_vaddrs[name] = current_vaddr;
            current_vaddr += out_sec_virtual_sizes[name];
        }
    }

    //符号决议
    std::map<std::string, ResolvedSymbol> global_sym_table;
    std::vector<std::map<std::string, uint64_t>> local_sym_tables(selected_objects.size());

    for (size_t i = 0; i < selected_objects.size(); ++i) {
        for (const auto& sym : selected_objects[i].symbols) {
            if (sym.type == SymbolType::UNDEFINED || sym.section.empty()) continue;

            auto loc = sec_map[{i, sym.section}];
            uint64_t base = out_sec_vaddrs.count(loc.out_sec_name) ? out_sec_vaddrs[loc.out_sec_name] : 0;
            uint64_t sym_vaddr = base + loc.offset_in_out_sec + sym.offset;

            if (sym.type == SymbolType::LOCAL) {
                local_sym_tables[i][sym.name] = sym_vaddr;
            } else {
                if (global_sym_table.count(sym.name)) {
                    if (sym.type == SymbolType::GLOBAL && global_sym_table[sym.name].type == SymbolType::GLOBAL) {
                        throw std::runtime_error("Multiple definition of strong symbol: " + sym.name);
                    }
                    if (sym.type == SymbolType::GLOBAL) global_sym_table[sym.name] = {sym_vaddr, sym.type};
                } else {
                    global_sym_table[sym.name] = {sym_vaddr, sym.type};
                }
            }
        }
    }

    //重定位
    for (size_t i = 0; i < selected_objects.size(); ++i) {
        for (const auto& [name, sec] : selected_objects[i].sections) {
            auto loc = sec_map[{i, name}];
            if (loc.out_sec_name == ".bss") continue; 
            std::vector<uint8_t>& buffer = out_sec_buffers[loc.out_sec_name];
            uint64_t out_sec_base = out_sec_vaddrs[loc.out_sec_name];

            for (const auto& reloc : sec.relocs) {
                uint64_t S = 0;
                bool is_internal = false;

                //尝试解析符号
                if (local_sym_tables[i].count(reloc.symbol)) {
                    S = local_sym_tables[i][reloc.symbol];
                    is_internal = true;
                } else if (global_sym_table.count(reloc.symbol)) {
                    S = global_sym_table[reloc.symbol].vaddr;
                    is_internal = true;
                }

                uint64_t P = out_sec_base + loc.offset_in_out_sec + reloc.offset;
                int64_t A = reloc.addend;

                if (is_internal) {
                    //内部符号：正常计算并回填
                    uint64_t val = 0; size_t sz = 0;
                    switch (reloc.type) {
                        case RelocationType::R_X86_64_32:
                        case RelocationType::R_X86_64_32S: val = S + A; sz = 4; break;
                        case RelocationType::R_X86_64_64:  val = S + A; sz = 8; break;
                        case RelocationType::R_X86_64_PC32: val = S + A - P; sz = 4; break;
                        default: continue;
                    }
                    write_le(buffer, loc.offset_in_out_sec + reloc.offset, val, sz);
                } else {
                    //外部符号
                    if (!options.shared) {
                        throw std::runtime_error("Undefined symbol: " + reloc.symbol);
                    } else {
                        //不修改 buffer，而是记录一个重定位请求
                        //P已经是相对于库基址的偏移，这是加载器需要的VAddr
                        Relocation dyn_rel;
                        dyn_rel.offset = P; 
                        dyn_rel.symbol = reloc.symbol;
                        dyn_rel.type = reloc.type;
                        dyn_rel.addend = reloc.addend;
                        executable.dyn_relocs.push_back(dyn_rel);
                    }
                }
            }
        }
    }

    //构建输出
    for (const auto& name : out_sec_order) {
        if (out_sec_virtual_sizes.count(name) && out_sec_virtual_sizes[name] > 0) {
            FLESection out_sec;
            out_sec.name = name;
            if (name != ".bss") out_sec.data = std::move(out_sec_buffers[name]);
            executable.sections[name] = out_sec;

            ProgramHeader phdr;
            phdr.name = name;
            phdr.vaddr = out_sec_vaddrs[name];
            phdr.size = out_sec_virtual_sizes[name];
            
            if (name == ".text") phdr.flags = static_cast<uint32_t>(PHF::R) | static_cast<uint32_t>(PHF::X);
            else if (name == ".rodata") phdr.flags = static_cast<uint32_t>(PHF::R);
            else phdr.flags = static_cast<uint32_t>(PHF::R) | static_cast<uint32_t>(PHF::W);
            
            executable.phdrs.push_back(phdr);
        }
    }

    //Bonus 1: 导出动态符号表 
    if (options.shared) {
        std::set<std::string> exported_names;
        for (size_t i = 0; i < selected_objects.size(); ++i) {
            for (const auto& sym : selected_objects[i].symbols) {
                //仅导出定义的全局/弱符号
                if ((sym.type == SymbolType::GLOBAL || sym.type == SymbolType::WEAK) &&
                    sym.type != SymbolType::UNDEFINED && !sym.section.empty()) {
                    
                    //检查是否是最终决议的那个符号
                    if (global_sym_table.count(sym.name)) {
                        auto loc = sec_map[{i, sym.section}];
                        uint64_t base = out_sec_vaddrs[loc.out_sec_name];
                        uint64_t sym_vaddr = base + loc.offset_in_out_sec + sym.offset;

                        if (sym_vaddr == global_sym_table[sym.name].vaddr) {
                            if (exported_names.find(sym.name) == exported_names.end()) {
                                Symbol export_sym = sym;
                                //修正段名和偏移，使其对应输出文件
                                export_sym.section = loc.out_sec_name;
                                export_sym.offset = loc.offset_in_out_sec + sym.offset;
                                executable.symbols.push_back(export_sym);
                                exported_names.insert(sym.name);
                            }
                        }
                    }
                }
            }
        }
    }

    if (global_sym_table.count(options.entryPoint)) executable.entry = global_sym_table[options.entryPoint].vaddr;
    else if (!options.shared) throw std::runtime_error("Undefined symbol: " + options.entryPoint);

    return executable;
}
