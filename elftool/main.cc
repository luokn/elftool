#include "elftool.h"

#include <iostream>
#include <string>

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <elf-file>\n";
        return 1;
    }
    ElfFile elf(argv[1]);
    if (elf) {
        std::cout << "Dynamic symbol table:\n";
        const auto &dynsym = elf.dynsym();
        const auto &dynstr = elf.dynstr();
        for (const auto &sym : dynsym) {
            std::cout << &dynstr[sym.st_name] << '\n';
        }

        std::cout << "Immediate relocation table:\n";
        const auto &rela_dyn = elf.rela_dyn();
        for (const auto &rela : rela_dyn) {
            std::cout << &dynstr[dynsym[ELF64_R_SYM(rela.r_info)].st_name] << '\n';
        }

        std::cout << "Lazy relocation table:\n";
        const auto &rela_plt = elf.rela_plt();
        for (const auto &rela : rela_plt) {
            std::cout << &dynstr[dynsym[ELF64_R_SYM(rela.r_info)].st_name] << '\n';
        }
    }
    return 0;
}
