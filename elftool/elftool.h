#pragma once

#include <cstdint>
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>

struct Elf32 {
    using Ehdr = Elf32_Ehdr;
    using Phdr = Elf32_Phdr;
    using Shdr = Elf32_Shdr;
    using Sym  = Elf32_Sym;
    using Rel  = Elf32_Rel;
    using Rela = Elf32_Rela;
};

struct Elf64 {
    using Ehdr = Elf64_Ehdr;
    using Phdr = Elf64_Phdr;
    using Shdr = Elf64_Shdr;
    using Sym  = Elf64_Sym;
    using Rel  = Elf64_Rel;
    using Rela = Elf64_Rela;
};

struct GNUHash {
    struct Header {
        uint32_t nbuckets, symbias, nmaskwords, gnushift;
    };

    std::span<Header, 1> header;
    std::span<uint64_t>  bloomwords;
    std::span<uint32_t>  buckets;
    std::span<uint32_t>  chains;
};

template <typename ElfType = Elf64> class ElfFile {
    using Ehdr = typename ElfType::Ehdr;
    using Phdr = typename ElfType::Phdr;
    using Shdr = typename ElfType::Shdr;
    using Sym  = typename ElfType::Sym;
    using Rel  = typename ElfType::Rel;
    using Rela = typename ElfType::Rela;

    static_assert(std::is_same_v<ElfType, Elf32> || std::is_same_v<ElfType, Elf64>, "ElfType must be Elf32 or Elf64");

  public:
    enum class State { OpenFailed, StatFailed, MmapFailed, NotElfFile, BadElfFile, OK };

  public:
    ElfFile(const std::string &path) : _fd(-1), _base(nullptr) {
        /* Open ELF file, read and write, path is path.c_str() */
        _fd = open(path.c_str(), O_RDWR);
        if (_fd < 0) {
            std::cerr << "open " << path << " failed: " << strerror(errno) << std::endl;
            _state = State::OpenFailed;
            return;
        }

        /* Get file size */
        struct stat st;
        if (fstat(_fd, &st) < 0) {
            // throw std::runtime_error("fstat " + path + " failed: " + strerror(errno));
            std::cerr << "fstat " << path << " failed: " << strerror(errno) << std::endl;
            _state = State::StatFailed;
            return;
        }

        /* Map elf file into memory, read and write, shared mapping, to be modified */
        _size = st.st_size;
        _base = reinterpret_cast<uint8_t *>(mmap(NULL, _size, PROT_READ | PROT_WRITE, MAP_SHARED, _fd, 0));
        if (_base == MAP_FAILED) {
            std::cerr << "mmap " << path << " failed: " << strerror(errno) << std::endl;
            _state = State::MmapFailed;
            return;
        }

        /* ELF file should start with 0x7f 'E' 'L' 'F' */
        if (strncmp(reinterpret_cast<const char *>(_base), ELFMAG, SELFMAG) != 0) {
            std::cerr << path << " is not an elf file" << std::endl;
            _state = State::NotElfFile;
            return;
        }

        /* Get segments and sections */
        Ehdr           *header = reinterpret_cast<Ehdr *>(_base);
        std::span<Phdr> segments(reinterpret_cast<Phdr *>(_base + header->e_phoff), header->e_phnum);
        std::span<Shdr> sections(reinterpret_cast<Shdr *>(_base + header->e_shoff), header->e_shnum);

        /* Build a map from section name to section header address */
        Shdr           *shstr_sh = &sections[header->e_shstrndx];
        std::span<char> shstr(reinterpret_cast<char *>(_base + shstr_sh->sh_offset), shstr_sh->sh_size);
        for (auto &section : sections) {
            _section_headers.emplace(&shstr[section.sh_name], &section);
        }

        /* Get section headers */
        Shdr *dynsym_sh   = _section_headers[".dynsym"];   /* dynamic symbol table */
        Shdr *dynstr_sh   = _section_headers[".dynstr"];   /* dynamic string table */
        Shdr *rela_dyn_sh = _section_headers[".rela.dyn"]; /* immediate relocation table */
        Shdr *rela_plt_sh = _section_headers[".rela.plt"]; /* lazy relocation table */
        Shdr *gun_hash_sh = _section_headers[".gnu.hash"]; /* gnu hash table */

        /* Check if all sections are found */
        if (dynsym_sh == nullptr || dynstr_sh == nullptr) {
            std::cerr << "no dynamic symbol table or dynamic string table" << std::endl;
            _state = State::BadElfFile;
            return;
        }
        if (rela_dyn_sh == nullptr || rela_plt_sh == nullptr) {
            std::cerr << "no immediate relocation table or lazy relocation table" << std::endl;
            _state = State::BadElfFile;
            return;
        }
        if (gun_hash_sh == nullptr) {
            std::cerr << "no gnu hash table" << std::endl;
            _state = State::BadElfFile;
            return;
        }

        /* Get span of dynamic symbol table and dynamic string table */
        std::span<Sym>  dynsym(reinterpret_cast<Sym *>(_base + dynsym_sh->sh_offset), dynsym_sh->sh_size / sizeof(Sym));
        std::span<char> dynstr(reinterpret_cast<char *>(_base + dynstr_sh->sh_offset), dynstr_sh->sh_size);

        /* Get span of immediate relocation table and lazy relocation table */
        std::span<Rela> rela_dyn(reinterpret_cast<Rela *>(_base + rela_dyn_sh->sh_offset), rela_dyn_sh->sh_size / sizeof(Rela));
        std::span<Rela> rela_plt(reinterpret_cast<Rela *>(_base + rela_plt_sh->sh_offset), rela_plt_sh->sh_size / sizeof(Rela));

        /* Load elf file successfully */
        _state = State::OK;

        /* ELF header, segments, sections */
        _segments = segments;
        _sections = sections;

        /* Dynamic symbol table, dynamic string table */
        _dynsym = dynsym.subspan(1); // skip the first symbol, which is NULL
        _dynstr = dynstr;

        /* Immediate relocation table, lazy relocation table */
        _rela_dyn = rela_dyn;
        _rela_plt = rela_plt;
    }

    ~ElfFile() {
        if (_base != nullptr && _base != MAP_FAILED) {
            munmap(_base, _size);
        }
        if (_fd > 0) {
            close(_fd);
        }
        _fd   = -1;
        _base = nullptr;
    }

  public:
    State state() const { return _state; }
    operator bool() const { return _state == State::OK; }
    bool operator!() const { return _state != State::OK; }

  public:
    std::span<Ehdr, 1> header() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return {reinterpret_cast<Ehdr *>(_base)};
    }
    std::span<Phdr> segments() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _segments;
    }
    std::span<Shdr> sections() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _sections;
    }
    std::span<Sym> dynsym() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _dynsym;
    }
    std::span<char> dynstr() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _dynstr;
    }
    std::span<Rela> rela_dyn() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _rela_dyn;
    }
    std::span<Rela> rela_plt() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }
        return _rela_plt;
    }
    GNUHash gun_hash() {
        if (_state != State::OK) {
            throw std::runtime_error("failed to load elf file");
        }

        Shdr *gun_hash_sh = _section_headers[".gnu.hash"];
        if (gun_hash_sh == nullptr) {
            throw std::runtime_error("no gnu hash table");
        }

        /* Header at start of section */
        uint8_t                      *addr = _base + gun_hash_sh->sh_offset;
        std::span<GNUHash::Header, 1> header(reinterpret_cast<GNUHash::Header *>(addr), 1);

        /* Bloom filter at end of header */
        addr += sizeof(GNUHash::Header);
        std::span<uint64_t> bloomwords(reinterpret_cast<uint64_t *>(addr), header[0].nmaskwords);

        /* Hash buckets at end of bloom filter */
        addr += sizeof(uint64_t) * header[0].nmaskwords;
        std::span<uint32_t> buckets(reinterpret_cast<uint32_t *>(addr), header[0].nbuckets);

        /* Hash chains at end of buckets */
        addr += sizeof(uint32_t) * header[0].nbuckets;
        std::span<uint32_t> chains(reinterpret_cast<uint32_t *>(addr), header[0].symbias);

        return {header, bloomwords, buckets, chains};
    }

  private:
    State _state;

    int      _fd;
    size_t   _size;
    uint8_t *_base;

    std::span<Phdr> _segments;
    std::span<Shdr> _sections;

    std::span<Sym>  _dynsym;
    std::span<char> _dynstr;

    std::span<Rela> _rela_dyn;
    std::span<Rela> _rela_plt;

    std::unordered_map<std::string_view, Shdr *> _section_headers;
};