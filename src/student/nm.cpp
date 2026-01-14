#include "fle.hpp"
#include <iomanip>
#include <iostream>
#include <string>
#include <cctype>

//辅助函数：判断字符串是否以指定前缀开头
static bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && 
           str.compare(0, prefix.size(), prefix) == 0;
}

void FLE_nm(const FLEObject& obj)
{
    for (const auto& sym : obj.symbols) {
        //过滤：跳过未定义符号,文档指出在这个任务中不显示未定义符号
        if (sym.type == SymbolType::UNDEFINED) {
            continue;
        }
        
        //安全性检查：如果节名为空，通常也意味着未定义或异常
        if (sym.section.empty()) {
            continue;
        }

        char type_char = '?';
        bool is_code_section = false;

        //确定基础字符：根据节名称
        //注意处理带后缀的变体，如 .text.startup，所以使用 starts_with
        if (starts_with(sym.section, ".text")) {
            type_char = 'T';
            is_code_section = true;
        } else if (starts_with(sym.section, ".data")) {
            type_char = 'D';
        } else if (starts_with(sym.section, ".bss")) {
            type_char = 'B';
        } else if (starts_with(sym.section, ".rodata")) {
            type_char = 'R';
        } else {
            //对于其他未知段，通常默认为数据段处理
            type_char = 'D';
        }

        //处理符号类型
        if (sym.type == SymbolType::WEAK) {
            //代码段中的弱符号 -> 'W'
            //数据段/BSS中的弱符号 -> 'V'
            if (is_code_section) {
                type_char = 'W';
            } else {
                type_char = 'V';
            }
        } else if (sym.type == SymbolType::LOCAL) {
            type_char = std::tolower(type_char);
        } else if (sym.type == SymbolType::GLOBAL) {
            // type_char = std::toupper(type_char); 
        }

        //格式化输出
        std::cout << std::hex << std::setw(16) << std::setfill('0') << sym.offset
                  << " " << type_char << " " << sym.name << std::endl;
    }
}
