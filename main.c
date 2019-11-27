#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

static int mem_stat(void);

#define TARGET_OBJ_NAME_SIZE_MAX	(32)
static const char target_obj_name[][TARGET_OBJ_NAME_SIZE_MAX] = {
	#include "target_obj.h"
};

static int error = 0;

static int is_target_obj_name(const char * obj_name)
{
	int target_obj_name_num = sizeof(target_obj_name) / TARGET_OBJ_NAME_SIZE_MAX;
	int i = 0;
	//printf("%s\n", obj_name);
	for(i=0;i<target_obj_name_num;i++){
		if(!strcmp(obj_name, target_obj_name[i])){
			return 1;
		}
	}
	return 0;
}

static int map_file_find_section(const char * buf, uint32_t ln)
{	
	int i = 0;
	const char mfs[5][256] = {
		"Archive member included to satisfy reference by file (symbol)\n",
		"Allocating common symbols\n",
		"Discarded input sections\n",
		"Memory Configuration\n",
		"Linker script and memory map\n"
	};

	//printf("sizeof(target_obj_name) = %ld, target_obj_name_num = %ld\n",sizeof(target_obj_name),sizeof(target_obj_name) / TARGET_OBJ_NAME_SIZE_MAX);

	for(i=0;i<5;i++){
		if(!strcmp(buf, mfs[i])){
			printf("[%d] %s", ln, mfs[i]);
			break;					
		}		
	}
	if(4 == i)
		return 1;
	else
		return 0;
}

static int get_line_len(uint8_t * line_buf)
{
	int i = 0;
	while(*(line_buf+i)){ 
		printf("[%d](%c) 0x%0x\n", i, *(line_buf + i), *(line_buf + i));
		i++; 
	}
	return i;
}

static void dump_buf(const char * buf, uint32_t size)
{
	int i = 0;
	printf("size %d\n", size);

	for(i=0;i<size;i++){
		printf("[%d] = [0x%0x](%c) \n", i, buf[i], buf[i]);
		//if(0 == (i % 8) && i != 0){
			//printf("\n");
		//}
	}
}

static int mem_analy(const char * buf, uint32_t ln);
static int mem_analy_flag = 0;

static int map_line_handler(const char * buf, uint32_t line_num)
{
	int ret = 0;
	ret = map_file_find_section(buf, line_num);
	if(ret){
		mem_analy_flag = 1;		
	}

	if(mem_analy_flag)
		mem_analy(buf, line_num);

	return 0;
}

static void log_arg(int argc, char * argv[])
{
	int i = 0;
	for(i=0;i<argc;i++){
		printf("arg[%d] [%s]\n", i, argv[i]);
	}
	printf("target_obj_name_num = %ld\n", sizeof(target_obj_name) / TARGET_OBJ_NAME_SIZE_MAX);
}

#define READ_BUF_SIZE	(1024*1)
static char read_buf[READ_BUF_SIZE] = {0};
static char last_line[READ_BUF_SIZE] = {0};

int main(int argc, char * argv[])
{
	int ret = 0;
	char * p_ret = NULL;
	//printf("Hello minnow\n");
	//log_arg(argc, argv);
	int line_num = 0;

	FILE *map_fl;

	int map_fd = open(argv[1], O_RDWR);
	if(map_fd < 0)
		return -1;
	//printf("map_fd %d\n", map_fd);
		
	map_fl = fdopen(map_fd, "r+");
	if(!map_fl){
		printf("map fopen err\n");
		return -1;
	}

	line_num = 0;
	while(1){
		p_ret = fgets(read_buf, READ_BUF_SIZE, map_fl);
		if(!p_ret){			
			//printf("fget map NULL total_line_num = %d\n", line_num);
			break;
		}
		line_num++;
		map_line_handler(read_buf, line_num);
		memset(read_buf, 0, READ_BUF_SIZE);
	}

	//printf("error = %d\n", error);
	printf("\n");
	mem_stat();

	fclose(map_fl);
	close(map_fd);	
	return 0;
}
#define SEC_TYPE_MAX_SIZE	(16)
#define OBJ_NAME_MAX_SIZE	(32)
static uint8_t last_line_flag = 0;
static int get_mem_size(const char * buf, const char * obj_name, uint32_t objn_len, uint32_t ln);
static int mem_analy(const char * buf, uint32_t ln)
{
	const char * pos = buf;
	char * stop_pos = NULL;
	char section_type[SEC_TYPE_MAX_SIZE] = {0};
	char obj_name[OBJ_NAME_MAX_SIZE] = {0};
	uint32_t obj_name_size = 0;

	pos = strchr(pos, '(');
	if(pos){
		stop_pos = strchr(pos+1, ')');
		if(stop_pos){
			obj_name_size = (stop_pos - pos) - 1;
			if(obj_name_size < OBJ_NAME_MAX_SIZE){
				memcpy(obj_name, pos+1, obj_name_size);			
				if(is_target_obj_name(obj_name)){
					//printf("\nobj_name(%ld)[%s] @%d\n", (stop_pos - pos), obj_name, ln);
					//printf("\n");
					get_mem_size(buf, obj_name, (stop_pos-pos), ln);					
				}
				memset(obj_name, 0, OBJ_NAME_MAX_SIZE);			
			}else{
				//printf("obj_name ERROR %ld, lnum = %d\n", (stop_pos - pos), ln);
				//error = 1;
			}
		}
	}

	if(strlen(buf) < READ_BUF_SIZE){
		memset(last_line, 0, READ_BUF_SIZE);
		memcpy(last_line, buf, strlen(buf));
		last_line_flag = 1;
	}

}
static int check_line_has_section_name(const char * buf, uint32_t ln)
{
	const char * pos = buf;
	char * stop_pos = NULL;
	int ret = 0;

	stop_pos = strstr(pos, "0x");
	pos = strchr(pos, '.');
	
	if(stop_pos){
		//printf("pos - buf = %ld, stop_pos - buf = %ld\n", pos-buf, stop_pos-buf);
		if(pos && (pos-buf) < (stop_pos-buf)){
			ret = 1;
		}
	}else{
		if(pos){
			ret = 1;
		}
	}

	return ret;
}

//char c1 = '.';// 0x2e
//printf("[%c] = 0x%0x\n", c1, c1);
//char c2 = ' ';// 0x20
//printf("[%c] = 0x%0x\n", c2, c2);

static int get_section_and_function_name(const char * line_buf, char * section_name, uint32_t * sn_len, char * function_name, uint32_t * fn_len)
{
	const char * pos = line_buf;
	char * stop_pos = NULL;
	char * tmp_pos = NULL;
	char * function_pos = NULL;
	char * function_stop_pos = NULL;
	uint32_t section_name_len = 0;
	uint32_t function_name_len = 0;
	
	pos = strchr(pos, '.');
	if(pos){
		stop_pos = strchr(pos + 1, '.');
		if(stop_pos){
/*
 case 1: .rodata.crc_table
 case 2: .debug_abbrev  0x00000000000955a5      0x253 services/multimedia/built-in.a(log2lin.o)
 case 3: .text.FDK_put  0x000000001c0fd638       0xfc services/multimedia/built-in.a(FDK_bitbuffer.o)
*/			
			tmp_pos = strstr(pos + 1, "0x");
			if(tmp_pos){
				if(tmp_pos < stop_pos){
					// case 2
					stop_pos = strchr(pos + 1, ' ');
					if(stop_pos){
						section_name_len = stop_pos - pos;
					}
					function_name_len = 0;
				}else{
					// case 3
					section_name_len = stop_pos - pos;
					function_pos = stop_pos + 1;
					function_stop_pos = strchr(function_pos, ' ');
					if(function_pos){
						function_name_len = function_stop_pos - function_pos;
					}else{
						printf("ERROR Not fount space for case 3 function_name\n");
					}					
				}
			}else{
				section_name_len = stop_pos - pos;
				// case 1
				function_pos = stop_pos + 1;
				function_stop_pos = strchr(function_pos, 0xa);
				if(function_pos){
					function_name_len = function_stop_pos - function_pos;
				}else{
					printf("ERROR Not fount 0xa for case 1 function_name\n");
					dump_buf(line_buf, strlen(line_buf));
				}	
			}		
		}else{			
			stop_pos = strchr(pos + 1, ' ');
			if(stop_pos){
				section_name_len = stop_pos - pos;
			}else{
				stop_pos = strchr(pos + 1, 0xa);
				if(stop_pos){
					section_name_len = stop_pos - pos;
					function_name_len = 0;
				}else{
					printf("ERROR Not fount 0xa\n");
				}
			}
		}
	}

	if(section_name_len){
		memcpy(section_name, pos, section_name_len);
		*sn_len = section_name_len;
		//printf("section_name [%s](%d)\n", section_name, section_name_len);
	}

	if(!memcmp(section_name, ".ARM", 4)){
		function_name_len = 0;
	}
	
	if(function_name_len){
		memcpy(function_name, function_pos, function_name_len);
		*fn_len = function_name_len;
		//printf("function_name [%s](%d)\n", function_name, function_name_len);
	}

	if((!memcmp(section_name, ".text", 5))   || 
	   (!memcmp(section_name, ".rodata", 7)) || 
	   (!memcmp(section_name, ".bss", 4))){
	   	//printf("debug %s\n", section_name);
	   	if(function_name_len == 0){
	   		//printf("funtion_name_len = 0, but in text or rodata or bss\n");
		}
	}	
}

#define ADDR_STR_SIZE_MAX		(36)
#define SIZE_STR_SIZE_MAX		(16)
#define SECTION_NAME_SIZE_MAX	(16)
#define FUNCTION_NAME_SIZE_MAC	(256)

typedef struct {
	char addr_str[ADDR_STR_SIZE_MAX];
	uint32_t addr_len;
	char size_str[SIZE_STR_SIZE_MAX];
	uint32_t size_len;
	char section_name[SECTION_NAME_SIZE_MAX];
	uint32_t section_name_size;
	char function_name[FUNCTION_NAME_SIZE_MAC];
	uint32_t function_name_size;
	char obj_name[OBJ_NAME_MAX_SIZE];
	uint32_t obj_name_len;
	uint32_t size;
} mem_t;

static uint32_t total_mem_num = 0;
#define MAX_MEM_NUM	(1024*10)
static mem_t mem[MAX_MEM_NUM] = {0};
static int mem_log(mem_t * t_mem);
static int mem_stat(void)
{
	//printf("total_num = %d\n", total_mem_num);
	int i = 0;
	mem_t * tmp_mem = NULL;

	uint32_t total_mem_use = 0;
	int section_mem_use = -1;
	char last_section_name[SECTION_NAME_SIZE_MAX] = {0};
	uint32_t is_new_section = 0;

#if 1
	for(i=0;i<total_mem_num;i++){
		tmp_mem = &mem[i];
		mem_log(tmp_mem);
	}
#endif
	
	printf("\n");

	for(i=0;i<total_mem_num;i++){
		tmp_mem = &mem[i];
		total_mem_use += tmp_mem->size;
		if(strcmp(tmp_mem->section_name, last_section_name)){
			is_new_section = 1;
		}else{
			is_new_section = 0;
		}
		if(is_new_section){
			if(section_mem_use != -1){
				printf("%-16s [%d]\n", last_section_name, section_mem_use);
				section_mem_use = 0;			
			}
			section_mem_use = 0;
			strcpy(last_section_name, tmp_mem->section_name);
		}
		section_mem_use += tmp_mem->size;
	}

	printf("%-16s [%d]\n", last_section_name, section_mem_use);
	printf("%-16s [%d]\n", "total", total_mem_use);
}
static int mem_log(mem_t * t_mem)
{
	printf("\n");
	if(t_mem->obj_name_len){
		printf("%-16s [%s](%d)\n", "obj_name", t_mem->obj_name, t_mem->obj_name_len);
	}	
	if(t_mem->section_name_size){
		printf("%-16s [%s](%d)\n", "section_name", t_mem->section_name, t_mem->section_name_size);
	}
	if(t_mem->function_name_size){
		printf("%-16s [%s](%d)\n", "function_name", t_mem->function_name, t_mem->function_name_size);
	}
	if(t_mem->addr_len){
		printf("%-16s [%s](%d)\n", "addr_str", t_mem->addr_str, t_mem->addr_len);
	}

	if(t_mem->size_len){
		printf("%-16s [%s](%d)\n", "size_str", t_mem->size_str, t_mem->size_len);
	}

	printf("%-16s 0x%0x(%d)\n", "size", t_mem->size, t_mem->size);
}

static const char fileter_section_name[][64] = {
".boot_struct",
".boot_text_flash",
".vector_table",
".reboot_param",
".boot_text_sram",
".boot_data_sram",
".boot_bss_sram",
".sram_text",
".sram_data",
".sram_bss",
".fast_text_sram",
".overlay_text_end", 
".overlay_data_end",
".userdata_pool",
".psram_text",
".psram_data",
".psram_bss",
".heap",
".text",
//".ARM.exidx",
".rodata",
//".custom.cmd.table",
//".thirdparty.event.table",
".data",
".bss",
".stack_dummy",
".system_info",
".build_info",
".code_start_addr",
".custom_parameter",
".userdata",
".factory",
//".ARM.attributes",
//".comment",
//".debug_line",
//".debug_info",
//".debug_abbrev",
//".debug_aranges",
//".debug_loc",
//".debug_ranges",
//".debug_str",
//".debug_frame",
//".stab",
//".stabstr",
};

static int mem_filter(char * addr_str, uint32_t addr_len, char * size_str, uint32_t size_len, char * sn, uint32_t sn_len, char *fn, uint32_t fn_len)
{
	int fileter_section_name_size = sizeof(fileter_section_name)/64;
	//printf("fileter_section_name_size = %d\n", fileter_section_name_size);
	int i = 0;
	int ret = 0;
	for(i=0;i<fileter_section_name_size;i++){
		if(!strcmp(sn, fileter_section_name[i])){
			ret = 1;
			break;
		}
	}

	return ret;
}
static uint32_t str_to_num(char * str);
static int mem_add(const char * obj_name, uint32_t objn_len, char * addr_str, uint32_t addr_len, char * size_str, uint32_t size_len, char * sn, uint32_t sn_len, char *fn, uint32_t fn_len)
{
	if(total_mem_num >= MAX_MEM_NUM){
		printf("ERROR MAX_MEM_NUM not enough\n");
		return -1;
	}

	mem_t * tmp_mem = &mem[total_mem_num];

	tmp_mem->obj_name_len = objn_len;
	memcpy(tmp_mem->obj_name, obj_name, tmp_mem->obj_name_len);
	tmp_mem->addr_len = addr_len;
	memcpy(tmp_mem->addr_str, addr_str, tmp_mem->addr_len);
	tmp_mem->size_len = size_len;
	memcpy(tmp_mem->size_str, size_str, tmp_mem->size_len);
	tmp_mem->section_name_size = sn_len;
	memcpy(tmp_mem->section_name, sn, tmp_mem->section_name_size);
	tmp_mem->function_name_size = fn_len;
	memcpy(tmp_mem->function_name, fn, tmp_mem->function_name_size);	

	tmp_mem->size = str_to_num(tmp_mem->size_str);

	//mem_log(tmp_mem);
	
	total_mem_num++;
	//printf("total_mem_num = %d\n", total_mem_num);
}

static int get_mem_size(const char * buf, const char * obj_name, uint32_t objn_len, uint32_t ln)
{
	const char * pos = buf;
	char * stop_pos = NULL;
	char addr_str[ADDR_STR_SIZE_MAX] = {0};
	uint32_t addr_str_size = 0;
	#define ADDR_STR_SIZE	(18)
	char size_str[SIZE_STR_SIZE_MAX] = {0};
	uint32_t size_str_len = 0;
	char section_name[SECTION_NAME_SIZE_MAX] = {0};
	uint32_t section_name_size = 0;
	char function_name[FUNCTION_NAME_SIZE_MAC] = {0};
	uint32_t function_name_size = 0;

	if(check_line_has_section_name(buf, ln)){
		get_section_and_function_name(buf, section_name, &section_name_size, function_name, &function_name_size);	
	}else{
		if(check_line_has_section_name(last_line, ln-1)){
			get_section_and_function_name(last_line, section_name, &section_name_size, function_name, &function_name_size);					
		}
	}

	pos = buf;
	pos = strstr(pos, "0x");
	if(pos){
		addr_str_size = ADDR_STR_SIZE;
		memcpy(addr_str, pos, ADDR_STR_SIZE);
		//printf("addr_str [%s]\n", addr_str);
		pos += ADDR_STR_SIZE;
		pos = strstr(pos, "0x");
		if(pos){
			stop_pos = strchr(pos, ' ');
			size_str_len = stop_pos - pos;
			memcpy(size_str, pos, size_str_len);
			//printf("size_str [%s]\n", size_str);
		}else{
			printf("ERROR get_mem_size Not fine size. line_num %d\n", ln);
			error = 2;
		}
	}else{
		printf("ERROR get mem size not fine addr str. line_num %d, obj_name %s\n", ln, obj_name);
		error = 3;
	}

	#if 0
	if(section_name_size){
		printf("section_name [%s](%d)\n", section_name, section_name_size);
	}
	if(function_name_size){
		printf("function_name [%s](%d)\n", function_name, function_name_size);
	}
	if(addr_str_size){
		printf("addr_str [%s](%d)\n", addr_str, addr_str_size);
	}
	if(size_str_len){
		printf("size_str [%s](%d)\n", size_str, size_str_len);
	}
	#endif

	if(mem_filter(addr_str, addr_str_size, size_str, size_str_len, section_name, section_name_size, function_name, function_name_size)){
		mem_add(obj_name, objn_len, addr_str, addr_str_size, size_str, size_str_len, section_name, section_name_size, function_name, function_name_size);
	}

	memset(addr_str, 0, ADDR_STR_SIZE_MAX);
	memset(size_str, 0, SIZE_STR_SIZE_MAX);
	memset(section_name, 0, SECTION_NAME_SIZE_MAX);
	memset(function_name, 0, FUNCTION_NAME_SIZE_MAC);
}

static uint32_t str_to_num(char * str)
{
	return strtol(str, NULL, 16);
}