// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ktime.h>
#include <linux/highmem.h>
#include <linux/sched/clock.h>
#include <linux/namei.h>
#include <linux/slab.h>


//#include <stdio.h> 
//#include <dirent.h> 
#include <linux/fs.h>
//#include <linux/base64.h> /* Not present in 5.10.35 */

#include "nvmev.h"
#include "kv_ftl.h"

/**
 * Code from Linux /lib/base64.c not present in 5.10.35
 */
static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode() - base64-encode some binary data
 * @src: the binary data to encode
 * @srclen: the length of @src in bytes
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes data using base64 encoding, i.e. the "Base 64 Encoding" specified
 * by RFC 4648, including the  '='-padding.
 *
 * Return: the length of the resulting base64-encoded string in bytes.
 */

static void __bin_to_hex(const char *data, int length, char *output) {
	int i;
	//NVMEV_INFO("Length: %d\n", length);
	
    for (i = 0; i < length; ++i) {
		//NVMEV_INFO("KEY BINARI: %02x, char: %c\n", data[i] & 0xFF, data[i]);
        sprintf(output + (i * 2), "%02x", data[i] & 0xFF);
		//NVMEV_INFO("KEY HEXA: %c%c\n", output[i*2], output[i*2+1]);
    }
    output[length * 2] = '\0'; 
	NVMEV_INFO("hex convert: %s\n", output);
}

static int __hex_to_bin(const char *input, int input_length, char *output, int output_length) {
    // Ensure the input has an even number of characters
    //NVMEV_INFO ("HOLA");
	if (input_length == 0) {
		NVMEV_INFO ("Length equals 0");
        return 0;
	}else if (input_length % 2 != 0) {
		NVMEV_INFO ("Hexadecimal string must have an even number of characters.");
        return 0;
    }
	
    if (output_length < input_length / 2) {
		NVMEV_INFO ("Output buffer is too small.");
		return 0;
    }

    for (int i = 0; i < input_length; i += 2) {
        char byteString[3] = {input[i], input[i + 1], '\0'};
        long byteValue;
        int ret = kstrtol(byteString, 16, &byteValue); // Pass the address of byteValue

        if (ret) {
            NVMEV_INFO("Conversion error: %d", ret);
            return 0;
        }

        // Ensure the value fits within a byte
        if (byteValue < 0 || byteValue > 255) {
            NVMEV_INFO("Hexadecimal value out of range: %ld", byteValue);
            return 0;
        }

        output[i / 2] = (char)byteValue;
    }

	//NVMEV_INFO("TO BINARY AGAIN: %s", output);
	return 1;
}

static void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		NVMEV_INFO("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			NVMEV_INFO(" ");
			if ((i+1) % 16 == 0) {
				NVMEV_INFO("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					NVMEV_INFO(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					NVMEV_INFO("   ");
				}
				NVMEV_INFO("|  %s \n", ascii);
			}
		}
	}
}

static const struct allocator_ops append_only_ops = {
	.init = append_only_allocator_init,
	.allocate = append_only_allocate,
	.kill = append_only_kill,
};

static const struct allocator_ops bitmap_ops = {
	.init = bitmap_allocator_init,
	.allocate = bitmap_allocate,
	.kill = bitmap_kill,
};

static inline unsigned long long __get_wallclock(void)
{
	return cpu_clock(nvmev_vdev->config.cpu_nr_dispatcher);
}

static size_t __cmd_io_size(struct nvme_rw_command *cmd)
{
	NVMEV_DEBUG("%d lba %llu length %d, %llx %llx\n", cmd->opcode, cmd->slba, cmd->length,
		    cmd->prp1, cmd->prp2);

	return (cmd->length + 1) << LBA_BITS;
}

static __u32 cmd_value_length(struct nvme_kv_command *cmd)
{
	return ((struct nvme_kv_common_command *)cmd)->value_size;
}

/* Return the time to complete */
static unsigned long long __schedule_io_units(int opcode, unsigned long lba, unsigned int length,
					      unsigned long long nsecs_start)
{
	unsigned int io_unit_size = 1 << nvmev_vdev->config.io_unit_shift;
	unsigned int io_unit =
		(lba >> (nvmev_vdev->config.io_unit_shift - LBA_BITS)) % nvmev_vdev->config.nr_io_units;
	int nr_io_units = min(nvmev_vdev->config.nr_io_units, DIV_ROUND_UP(length, io_unit_size));

	unsigned long long latest; /* Time of completion */
	unsigned int delay = 0;
	unsigned int latency = 0;
	unsigned int trailing = 0;

	if (opcode == nvme_cmd_kv_store ||
	    opcode == nvme_cmd_kv_batch) {
		delay = nvmev_vdev->config.write_delay;
		latency = nvmev_vdev->config.write_time;
		trailing = nvmev_vdev->config.write_trailing;
	} else if (opcode == nvme_cmd_kv_retrieve) {
		delay = nvmev_vdev->config.read_delay;
		latency = nvmev_vdev->config.read_time;
		trailing = nvmev_vdev->config.read_trailing;
	}

	latest = max(nsecs_start, nvmev_vdev->io_unit_stat[io_unit]) + delay;

	do {
		latest += latency;
		nvmev_vdev->io_unit_stat[io_unit] = latest;

		if (nr_io_units-- > 0) {
			nvmev_vdev->io_unit_stat[io_unit] += trailing;
		}

		length -= min(length, io_unit_size);
		if (++io_unit >= nvmev_vdev->config.nr_io_units)
			io_unit = 0;
	} while (length > 0);

	return latest;
}

static unsigned long long __schedule_flush(struct nvmev_request *req)
{
	unsigned long long latest = 0;
	int i;

	for (i = 0; i < nvmev_vdev->config.nr_io_units; i++) {
		latest = max(latest, nvmev_vdev->io_unit_stat[i]);
	}

	return latest;
}

/* KV-SSD Mapping Management */


/* 4 is for '/kv/', 16 is for the key and + 1 for the trailing 0 */
#define KV_BASE_PATH "/kv/"
#define KV_BASE_PATH_LEN 4
#define NVME_KV_MAX_KEY_LEN 16
#define NVME_KV_MAX_PRINTABLE_KEY_LEN (NVME_KV_MAX_KEY_LEN*2)
#define KV_PATH_LEN (KV_BASE_PATH_LEN+NVME_KV_MAX_PRINTABLE_KEY_LEN+1)

static void delete_filp(struct file *filp)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *parent_inode = filp->f_path.dentry->d_parent->d_inode;
	NVMEV_INFO("Deleting file %s\n", filp->f_path.dentry->d_iname);
	inode_lock(parent_inode);
	//vfs_unlink(parent_inode, filp->f_path.dentry, NULL);
	vfs_unlink(&nop_mnt_idmap, parent_inode, filp->f_path.dentry, NULL);
	inode_unlock(parent_inode);
}

#if 1
static int delete_file(const char *path)
{
	struct file *filp;
	filp = filp_open(path, O_RDWR, 0666);
	if (IS_ERR(filp))
		return PTR_ERR_OR_ZERO(filp);
	filp_close(filp, NULL);
	delete_filp(filp);
	return 0;
}
#else

struct dentry *kern_path_locked(const char *name, struct path *path)
{
	struct filename *filename = getname_kernel(name);
	struct dentry *res = __kern_path_locked(AT_FDCWD, filename, path);

	putname(filename);
	return res;
}

/* Code from https://elixir.bootlin.com/linux/v6.8/source/drivers/base/devtmpfs.c#L309 */
//static int handle_remove(const char *nodename)
static int delete_file(const char *nodename)
{
	struct path parent;
	struct dentry *dentry;
	int deleted = 0;
	int err;

	dentry = kern_path_locked(nodename, &parent);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (d_really_is_positive(dentry)) {
		struct kstat stat;
		struct path p = {.mnt = parent.mnt, .dentry = dentry};
		err = vfs_getattr(&p, &stat, STATX_TYPE | STATX_MODE,
				  AT_STATX_SYNC_AS_STAT);
		if (!err /*&& dev_mynode(dev, d_inode(dentry), &stat)*/) {
			struct iattr newattrs;
			/*
			 * before unlinking this node, reset permissions
			 * of possible references like hardlinks
			 */
			newattrs.ia_uid = GLOBAL_ROOT_UID;
			newattrs.ia_gid = GLOBAL_ROOT_GID;
			newattrs.ia_mode = stat.mode & ~0777;
			newattrs.ia_valid =
				ATTR_UID|ATTR_GID|ATTR_MODE;
			inode_lock(d_inode(dentry));
			notify_change(&nop_mnt_idmap, dentry, &newattrs, NULL);
			inode_unlock(d_inode(dentry));
			err = vfs_unlink(&nop_mnt_idmap, d_inode(parent.dentry),
					 dentry, NULL);
			if (!err || err == -ENOENT)
				deleted = 1;
		}
	} else {
		err = -ENOENT;
	}
	dput(dentry);
	inode_unlock(d_inode(parent.dentry));

	path_put(&parent);
#if 0
	if (deleted && strchr(nodename, '/'))
		delete_path(nodename);
#endif
	return err;
}
#endif

static int file_exists(const char *path) {
	struct file *filp;
	NVMEV_INFO("PATH: %s", path);
	filp = filp_open(path, O_RDONLY, 0666);
	if (IS_ERR(filp)) {
		NVMEV_INFO("File does not exist");
		NVMEV_INFO("file_exists error code is: %ld\n", PTR_ERR(filp));
		return 1;
	}
	else {
		filp_close(filp, NULL);
		return 0;
	}
}

struct kds {
	__u16 key_length;
	char key[16];
	__u16 rsvd;
} __packed;

struct kv_readdir_data {
	struct dir_context	ctx;
	union {
		void		*private;
		char		*dirent;
	};
	char 				*kv_path;
	unsigned int		found;
	unsigned int		number_of_keys;
	unsigned int		used;
	unsigned int		dirent_count;
	unsigned int		file_attr;
	void *buffer_of_keys;
	size_t buffer_of_keys_len;
	size_t current_position;
	size_t key_len;
	struct unicode_map	*um;
};


static bool __dir_print_actor(struct dir_context *ctx, const char *name, int namlen,
		       loff_t offset, u64 ino, unsigned int d_type)
{
	struct kv_readdir_data *buf;
	struct kds kds;

	buf = container_of(ctx, struct kv_readdir_data, ctx);
	buf->dirent_count++;
	if (!strcmp(name, buf->kv_path + 4))  {
		buf->found = 1;
	}
	if (strlen(name) == 0) {
		return 0;
	}
	int key_length = (int)strlen(name)/2;
	//NVMEV_INFO("KEY NAME: %s", name);

	if (strcmp(name, ".") && strcmp(name, "..") && buf->found) {
		kds.key_length = (unsigned int)key_length;
		if (name != NULL) {

			int ret = __hex_to_bin(name, (int)strlen(name), (void*)&kds.key, key_length);
			//NVMEV_INFO("KEY BINARY: %s", kds.key);
			++buf->number_of_keys;
			if (ret == 0) {
				NVMEV_INFO("ERROR doing the transformation from hexadecimal to binary");
				return 0;
			}
		}

		/* The Key data structure should be a multiple of 4 bytes (u32) so we add 3 (sizeof(u32)-1) and integer divide by sizeof(u32) to round up */
		size_t kds_size = ((sizeof(kds.key_length) + kds.key_length + (sizeof(u32) - 1)) / sizeof(u32)) * sizeof(u32);

		NVMEV_INFO("ACTOR: Count: %d Name: %s\n", buf->dirent_count, name);
		if ((buf->current_position + kds_size) <= buf->buffer_of_keys_len) {
			//NVMEV_INFO("KDS SIZE %zu\n", kds_size);
			memcpy(buf->buffer_of_keys + buf->current_position, &kds, kds_size);
			buf->current_position += kds_size;
			return 1;
		} else {
			--buf->number_of_keys;
			NVMEV_INFO("The key does not fit in the buffer");
			return 0;
		}
		
	}
	return 1;
}

/* KV-SSD IO */

/*
 * 1. find mapping_entry
 * if kv_store
 *   if mapping_entry exist -> write to mem_offset
 *   else -> allocate mem_offset and write
 * else if kv_retrieve
 *   if mapping_entry exist -> read from mem_offset
 *   else -> key doesn't exist!
 */
static unsigned int __do_perform_kv_io(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
				       unsigned int *status)
{
	size_t offset;
	loff_t file_offset = 0;
	size_t length, remaining;
	int prp_offs = 0;
	int prp2_offs = 0;
	u64 paddr;
	u64 *paddr_list = NULL;
	size_t mem_offs = 0;
	size_t new_offset = 0;

	struct dir_context ctx;
	struct kv_readdir_data readdir_data;
	memset(&readdir_data, 0, sizeof(struct kv_readdir_data));

	int ret = 0;
	struct file *kv_file = NULL;
	char kv_path[KV_PATH_LEN];
	char *path_key_ptr = kv_path + strlen(KV_BASE_PATH);
	int no_offset = 0;

	memset(kv_path, 0, KV_PATH_LEN);
	sprintf(kv_path, KV_BASE_PATH);

	length = cmd_value_length(&cmd);
	//NVMEV_INFO("LENGTH: %zu\n", length);	

	//ret = base64_encode(cmd.kv_common.key, cmd.kv_common.key_len, path_key_ptr);
	//NVMEV_INFO("KEY ABANS DE HEX: %s\n", cmd.kv_common.key);
	//NVMEV_INFO("PRIMER CARCATER DE LA KEY: %c\n", cmd.kv_common.key[3]);

	//NVMEV_INFO("KEY LENGTH: %u\n", cmd.kv_list.cdw11);

	if(cmd.kv_delete.key_length > 16 || cmd.kv_delete.key_length <= 0) {
			NVMEV_DEBUG("ERROR: key size is not valid");
			*status = KV_ERR_INVALID_KEY_SIZE;
			return 0;
	}

	if ((cmd.common.opcode == nvme_cmd_kv_store) || 
	    (cmd.common.opcode == nvme_cmd_kv_retrieve) ||
		(cmd.common.opcode == nvme_cmd_kv_exist) ||
		(cmd.common.opcode == nvme_cmd_kv_delete) ||
		(cmd.common.opcode == nvme_cmd_kv_list))
	{
		/* We use store as type here, but all the commands have the key_length at the same location */
		//NVMEV_INFO("Key first: %d\n",cmd.kv_store.key_length);
		NVMEV_INFO("Key: %s %s Key binary: %#08llx %#08llx Key Hex: %s length: %d\n",
				   (const char *)&cmd.kv_common.key_lsb, (const char *)&cmd.kv_common.key_msb,
				   cmd.kv_common.key_lsb, cmd.kv_common.key_msb, path_key_ptr, cmd.kv_store.key_length);
		u64 key_start = (((u64)cpu_to_be32(le32_to_cpu(cmd.kv_common.key1))) << 32) | cpu_to_be32(le32_to_cpu(cmd.kv_common.key0));
		u64 key_end = (((u64)cpu_to_be32(le32_to_cpu(cmd.kv_common.key3))) << 32) | cpu_to_be32(le32_to_cpu(cmd.kv_common.key2));
		key_start = cmd.kv_common.key_lsb;
		key_end = cmd.kv_common.key_msb;
		//cmd.kv_common.key0 = swap_endianness_uint32(cmd.kv_common.key0);
		//cmd.kv_common.key1 = swap_endianness_uint32(cmd.kv_common.key1);
		//cmd.kv_common.key2 = swap_endianness_uint32(cmd.kv_common.key2);
		//cmd.kv_common.key3 = swap_endianness_uint32(cmd.kv_common.key3);
		//__bin_to_hex((const char*)&cmd.kv_common.key_lsb, min(cmd.kv_store.key_length, sizeof(cmd.kv_common.key_lsb)), path_key_ptr);
		__bin_to_hex((const char*)&key_start, min(cmd.kv_store.key_length, sizeof(cmd.kv_common.key_lsb)), path_key_ptr);
		if (cmd.kv_store.key_length > sizeof(cmd.kv_common.key_lsb)) {
			//__bin_to_hex((const char*)&cmd.kv_common.key_msb, cmd.kv_store.key_length - sizeof(cmd.kv_common.key_lsb), path_key_ptr + sizeof(cmd.kv_common.key_lsb)*2);
			__bin_to_hex((const char*)&key_end, cmd.kv_store.key_length - sizeof(cmd.kv_common.key_lsb), path_key_ptr + sizeof(cmd.kv_common.key_lsb)*2);
		}

		NVMEV_INFO("Key path: %s\n", kv_path);
	}

	if (ret < 0) {
		NVMEV_ERROR("Base64 conversion failed\n");
		strcpy(path_key_ptr, "error");
	} else if (ret > NVME_KV_MAX_PRINTABLE_KEY_LEN) {
		NVMEV_ERROR("Base64 overwrite ! We wrote %d characters\n", ret);
	}

	NVMEV_INFO("Key: %s %s Key binary: %#08llx %#08llx Key Hex: %s length: %d\n",
			   (const char *)&cmd.kv_common.key_lsb, (const char *)&cmd.kv_common.key_msb, cmd.kv_common.key_lsb, cmd.kv_common.key_msb, path_key_ptr, ret);

	NVMEV_INFO("OPCODE: %u\n", cmd.common.opcode);
	NVMEV_INFO("KEY LENGTH: %u\n", cmd.kv_store.key_length);
	if (cmd.common.opcode == nvme_cmd_kv_store) {


		NVMEV_INFO("DOES FILE EXIST %d\n",file_exists(kv_path));
		if (file_exists(kv_path)) { // entry doesn't exist -> is insert
			NVMEV_INFO("INFO: OPTION = %#x\n", cmd.kv_store.cdw11);
			if (cmd.kv_store.bit8) {
				NVMEV_DEBUG("NO kv_store insert %s %lu because Bit 8 set to 1\n", path_key_ptr, offset);		//controller shall not store the value if the key does not exist
				*status = KV_ERR_KEY_NOT_EXIST;
				return 0;
			}
			else {
				kv_file = filp_open(kv_path, O_RDWR | O_CREAT, 0666);
				NVMEV_DEBUG("kv_store insert %s %lu\n", path_key_ptr, offset);
			}
		} else {
			//update
			NVMEV_INFO("INFO: OPTION = %#0x\n", cmd.kv_store.cdw11);
			NVMEV_INFO("IS AN UPDATE");
			if (cmd.kv_store.bit9) {
				NVMEV_DEBUG("NO kv_store update %s %lu because Bit 9 set to 1\n", path_key_ptr, offset);		//controller shall not store the value if the key does exist
				*status = KV_ERR_KEY_EXISTS;
				return 0;
			}
			else {
				NVMEV_DEBUG("kv_delete %s exist - length %ld, offset %lu\n",
							path_key_ptr, length, offset);
				delete_file(kv_path);
				//create and insert file
				kv_file = filp_open(kv_path, O_RDWR | O_CREAT, 0666);
				NVMEV_DEBUG("kv_store update %s %lu\n", path_key_ptr, offset);
			}
		}
		
	} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		if(cmd.kv_retrieve.host_buffer_size <= 0) {
			*status = KV_ERR_INVALID_BUFFER_SIZE;
			return 0;
		}
		kv_file = filp_open(kv_path, O_RDONLY, 0666);
		if (IS_ERR(kv_file)) {
			NVMEV_INFO("File %s does not exist\n", kv_path);
			*status = KV_ERR_KEY_NOT_EXIST;
			return 0;
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_exist) {
		 if (file_exists(kv_path)) {
			NVMEV_INFO("Could not open file %s\n", kv_path);
			NVMEV_INFO("File %s does NOT exist\n", kv_path);
			*status = KV_ERR_KEY_NOT_EXIST;
			return 0;
		} else {
			NVMEV_INFO("File %s does exist\n", kv_path);
			return 0;
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_delete) {
		if (file_exists(kv_path)) {
			NVMEV_INFO("Could not open file %s\n", kv_path);
			NVMEV_INFO("File %s does NOT exist\n", kv_path);
			*status = KV_ERR_KEY_NOT_EXIST;
			return 0;
		} else {
			NVMEV_INFO("File %s does exist, deleting...\n", kv_path);
			delete_file(kv_path);
			return 0;
		}
	} else if (cmd.common.opcode == nvme_cmd_kv_list) {
		NVMEV_INFO("\t--- NVME KV LIST ---\n");
		struct file *fp = NULL;
		char *buf, *path;
		fp = filp_open("/kv", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY, 0);
		if (fp == NULL) {
			*status = KV_ERR_INVALID_NAMESPACE_OR_FORMAT;
			NVMEV_INFO("ERROR opening the directory");
			return 0;		
		}
		NVMEV_INFO("Directory successfully open");

		buf = __getname();
		if (!buf) {
			*status = NVME_SC_INTERNAL;
			filp_close(fp, NULL);
			NVMEV_INFO("ERROR allocating memory");
			return 0;
		}
		memset(buf, 0, PATH_MAX);

		path = kv_path;
		readdir_data.kv_path = path;
		readdir_data.found = 0;
		NVMEV_INFO("KEY LENGTH1: %d", cmd.kv_list.key_length);
		readdir_data.buffer_of_keys_len = cmd.kv_list.host_buffer_size;
		readdir_data.key_len = cmd.kv_list.key_length;
		readdir_data.current_position = 4;
		readdir_data.number_of_keys = 0;
		readdir_data.buffer_of_keys = kmalloc(readdir_data.buffer_of_keys_len, GFP_KERNEL);
		if (!readdir_data.buffer_of_keys) {
			NVMEV_INFO("ERROR allocating memory");
			return 0;
		}
		memset(readdir_data.buffer_of_keys, 0, readdir_data.buffer_of_keys_len);
		if (file_exists(kv_path)) {
			readdir_data.found = 1;
			//readdir_data.ctx.actor = __dir_print_actor_not_exist;
		} 
		readdir_data.ctx.actor = __dir_print_actor;
		ret = iterate_dir(fp, &readdir_data.ctx);
		memcpy(readdir_data.buffer_of_keys, &readdir_data.number_of_keys, sizeof(u32));
		__putname(buf);
		filp_close(fp, NULL);
		//return 0;
	} else {
		NVMEV_ERROR("Cmd type %d, for a key but not store or retrieve. return 0\n",
			    cmd.common.opcode);
		/*TO DO: program an error bc 0 is success*/
		return 0;
	}

	remaining = length;
	NVMEV_INFO("REMAINING: %zu\n", remaining);	
	while (remaining) {	
		size_t io_size;
		void *vaddr;
		mem_offs = 0;
		prp_offs++;
		if (prp_offs == 1) {
			paddr = kv_io_cmd_value_prp(cmd, 1);
		} else if (prp_offs == 2) {
			paddr = kv_io_cmd_value_prp(cmd, 2);
			if (remaining > PAGE_SIZE) {
				paddr_list = kmap_atomic_pfn(PRP_PFN(paddr)) +
					     (paddr & PAGE_OFFSET_MASK);
				paddr = paddr_list[prp2_offs++];
			}
		} else {
			paddr = paddr_list[prp2_offs++];
		}
		vaddr = kmap_atomic_pfn(PRP_PFN(paddr));
		io_size = min_t(size_t, remaining, PAGE_SIZE);
		if (paddr & PAGE_OFFSET_MASK) { // 일반 block io면 언제 여기에 해당?
			mem_offs = paddr & PAGE_OFFSET_MASK;
			if (io_size + mem_offs > PAGE_SIZE)
				io_size = PAGE_SIZE - mem_offs;
		}
		if (cmd.common.opcode == nvme_cmd_kv_store) {
			if (!kv_file || IS_ERR(kv_file)) {
				NVMEV_ERROR("Could not write to file %s\n", kv_path);
			} else {
				NVMEV_INFO("Writing data with size: %zu to file: %s\n", io_size, kv_path);
				NVMEV_INFO("Data:\n");
				DumpHex(vaddr + mem_offs, io_size);
				ret = kernel_write(kv_file, vaddr + mem_offs, io_size, &file_offset);
				if (ret < 0) {
					NVMEV_ERROR("Could not write KV value to file %s\n", kv_path);
				}
			}
		} else if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
			if (!kv_file || IS_ERR(kv_file)) {
				NVMEV_ERROR("Could not read file %s\n", kv_path);
			} else {
				NVMEV_INFO("Reading data with size: %zu to file: %s\n", io_size, kv_path);
				ret = kernel_read(kv_file, vaddr + mem_offs, io_size, &file_offset);
				*status += io_size;
				if (ret < 0) {
					NVMEV_ERROR("Could not read KV value from file %s\n", kv_path);
				}
			}
		} else if (cmd.common.opcode == nvme_cmd_kv_list) {
			/*NVMEV_INFO("Vaddr: %#010llx, mem_offs: %zu, buffer: %#010llx, offset: %zu, io_size: %zu\n",
						(u64)vaddr, mem_offs, (u64)readdir_data.buffer_of_keys, offset, io_size);*/
			memcpy(vaddr + mem_offs, readdir_data.buffer_of_keys + offset, io_size);
		} else {
			NVMEV_ERROR("Wrong KV Command passed to NVMeVirt!!\n");
		}

		kunmap_atomic(vaddr);

		remaining -= io_size;
		offset += io_size;
	}

	if (kv_file && !IS_ERR(kv_file) && cmd.common.opcode != nvme_cmd_kv_retrieve) {
		filp_close(kv_file, NULL);
	}

	if (paddr_list != NULL)
		kunmap_atomic(paddr_list);

	if (readdir_data.buffer_of_keys)
		kfree(readdir_data.buffer_of_keys);

	if (cmd.common.opcode == nvme_cmd_kv_retrieve) {
		NVMEV_INFO("HOLA\n");
		NVMEV_INFO("length: %zu\n", length);
		//*status = length;
		return length;
	}

	return 0;
}

static unsigned int __do_perform_kv_batched_io(struct kv_ftl *kv_ftl, int opcode, char *key,
					       int key_len, char *value, int val_len)
{
	NVMEV_ERROR("__do_perform_kv_batched_io CODE WAS REMOVED\n");

	return 0;
}

static unsigned int __do_perform_kv_batch(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
					  unsigned int *status)
{
	NVMEV_ERROR("__do_perform_kv_batch CODE WAS REMOVED\n");

	return 0;
}

static unsigned int kv_iter_open(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd, unsigned int *status)
{
	NVMEV_ERROR("kv_iter_open CODE WAS REMOVED\n");

	return 0;
}

static unsigned int kv_iter_close(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd, unsigned int *status)
{
	NVMEV_ERROR("kv_iter_close() CODE WAS REMOVED\n");

	return 0;
}

static unsigned int kv_iter_read(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
				 unsigned int *status)
{
	NVMEV_ERROR("kv_iter_read() CODE WAS REMOVED\n");

	return 0;
}

static unsigned int __do_perform_kv_iter_io(struct kv_ftl *kv_ftl, struct nvme_kv_command cmd,
					    unsigned int *status)
{
	NVMEV_ERROR("__do_perform_kv_iter_io() CODE WAS REMOVED\n");

	return 0;
}

bool kv_proc_nvme_io_cmd(struct nvmev_ns *ns, struct nvmev_request *req, struct nvmev_result *ret)
{
	struct nvme_command *cmd = req->cmd;

	switch (cmd->common.opcode) {
	case nvme_cmd_kv_store:
	case nvme_cmd_kv_delete:
		//ret->nsecs_target = __schedule_flush(req);
	case nvme_cmd_kv_retrieve:
	case nvme_cmd_kv_batch:
	case nvme_cmd_kv_list:
	case nvme_cmd_kv_exist:
		ret->nsecs_target = __schedule_io_units(
			cmd->common.opcode, 0, cmd_value_length((struct nvme_kv_command *)cmd),
			__get_wallclock());
		NVMEV_INFO("%d, %llu, %llu\n", cmd_value_length((struct nvme_kv_command *)cmd),
			   __get_wallclock(), ret->nsecs_target);
		break;
	default:
		NVMEV_ERROR("%s: command not implemented: %s (0x%x)\n", __func__,
				nvme_opcode_string(cmd->common.opcode), cmd->common.opcode);
		break;
	}

	return true;
}

bool kv_identify_nvme_io_cmd(struct nvmev_ns *ns, struct nvme_command cmd)
{
	return is_kv_cmd(cmd.common.opcode);
}

unsigned int kv_perform_nvme_io_cmd(struct nvmev_ns *ns, struct nvme_command *cmd, uint32_t *status)
{
	struct kv_ftl *kv_ftl = (struct kv_ftl *)ns->ftls;
	struct nvme_kv_command *kv_cmd = (struct nvme_kv_command *)cmd;

	if (is_kv_batch_cmd(cmd->common.opcode))
		return __do_perform_kv_batch(kv_ftl, *kv_cmd, status);
	else if (is_kv_iter_cmd(cmd->common.opcode))
		return __do_perform_kv_iter_io(kv_ftl, *kv_cmd, status);
	else
		return __do_perform_kv_io(kv_ftl, *kv_cmd, status);
}

void kv_init_namespace(struct nvmev_ns *ns, uint32_t id, uint64_t size, void *mapped_addr,
		       uint32_t cpu_nr_dispatcher)
{
	struct kv_ftl *kv_ftl;
	int i;

	kv_ftl = kmalloc(sizeof(struct kv_ftl), GFP_KERNEL);

	NVMEV_INFO("KV mapping table: %#010lx-%#010x\n",
		   nvmev_vdev->config.storage_start + nvmev_vdev->config.storage_size,
		   KV_MAPPING_TABLE_SIZE);

	kv_ftl->kv_mapping_table =
		memremap(nvmev_vdev->config.storage_start + nvmev_vdev->config.storage_size,
			 KV_MAPPING_TABLE_SIZE, MEMREMAP_WB);

	if (kv_ftl->kv_mapping_table == NULL)
		NVMEV_ERROR("Failed to map kv mapping table.\n");
	else
		memset(kv_ftl->kv_mapping_table, 0x0, KV_MAPPING_TABLE_SIZE);

	if (ALLOCATOR_TYPE == ALLOCATOR_TYPE_BITMAP) {
		kv_ftl->allocator_ops = bitmap_ops;
	} else if (ALLOCATOR_TYPE == ALLOCATOR_TYPE_APPEND_ONLY) {
		kv_ftl->allocator_ops = append_only_ops;
	} else {
		kv_ftl->allocator_ops = append_only_ops;
	}

	if (!kv_ftl->allocator_ops.init(nvmev_vdev->config.storage_size)) {
		NVMEV_ERROR("Allocator init failed\n");
	}

	kv_ftl->hash_slots = KV_MAPPING_TABLE_SIZE / KV_MAPPING_ENTRY_SIZE;
	NVMEV_INFO("Hash slots: %ld\n", kv_ftl->hash_slots);

	for (i = 0; i < kv_ftl->hash_slots; i++) {
		kv_ftl->kv_mapping_table[i].mem_offset = -1;
		kv_ftl->kv_mapping_table[i].next_slot = -1;
		kv_ftl->kv_mapping_table[i].length = -1;
	}

	for (i = 0; i < 16; i++)
		kv_ftl->iter_handle[i] = NULL;

	ns->id = id;
	ns->csi = NVME_CSI_NVM; // Not specifying to KV. Need to support NVM commands too.
	ns->ftls = (void *)kv_ftl;
	ns->size = size;
	ns->mapped = mapped_addr;
	/*register io command handler*/
	ns->proc_io_cmd = kv_proc_nvme_io_cmd;
	/*register CSS specific io command functions*/
	ns->identify_io_cmd = kv_identify_nvme_io_cmd;
	ns->perform_io_cmd = kv_perform_nvme_io_cmd;

	return;
}

void kv_remove_namespace(struct nvmev_ns *ns)
{
	kfree(ns->ftls);
	ns->ftls = NULL;
}
