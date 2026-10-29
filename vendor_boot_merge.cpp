/*
	Copyright (C) 2026 OrangeFox Recovery Project

	This file is part of the OrangeFox Recovery Project.

	OrangeFox is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	OrangeFox is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with OrangeFox.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "vendor_boot_merge.hpp"

#include <fcntl.h>
#include <linux/fs.h>
#include <lz4.h>
#include <lz4hc.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace vbm {
namespace {

constexpr char kVendorBootMagic[8] = {'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'};
constexpr uint32_t kHeaderV4Size = 2128;
constexpr uint32_t kTableEntrySize = 108;
constexpr uint32_t kRamdiskNameSize = 32;
constexpr uint32_t kBoardIdWords = 16;
constexpr uint32_t kTypePlatform = 1;
constexpr uint32_t kTypeRecovery = 2;
constexpr size_t kCopyBufferSize = 1024 * 1024;

// Legacy lz4 stream ("lz4 -l"), the format used by Android ramdisks: a 4-byte
// magic followed by blocks of "4-byte little-endian compressed size + data",
// each block decompressing to at most 8 MiB.
constexpr uint32_t kLz4LegacyMagic = 0x184C2102;
constexpr int kLz4LegacyBlockSize = 8 * 1024 * 1024;
constexpr int kLz4CompressionLevel = 12;

// Files/directories that the OrangeFox build removes from the stock PLATFORM
// ramdisk (see tools/build-system-compatible-vendor-boot.sh). The recovery
// ramdisk fragment ships its own copies, so keeping the ROM ones would only
// waste space and can shadow the OrangeFox versions depending on merge order.
constexpr const char* kPrunedPaths[] = {
	"miui.factoryreset.rc",
	"system/bin/adbd",
	"system/bin/fastbootd",
	"system/bin/logcat",
	"system/bin/logd",
	"system/bin/recovery",
	"system/bin/servicemanager",
	"system/bin/sh",
	"system/bin/toolbox",
	"system/bin/toybox",
	"system/bin/update_engine_sideload",
	"system/bin/hw/android.hardware.boot-service.mtk_recovery",
	"system/bin/hw/android.hardware.health-service.example_recovery",
	"system/etc/init/android.hardware.boot-service.mtk_recovery.rc",
	"system/etc/init/android.hardware.health-service.example_recovery.rc",
	"system/etc/init/recovery-persist.rc",
	"system/etc/init/recovery-refresh.rc",
	"system/etc/init/servicemanager.recovery.rc",
	"system/etc/recovery.fstab",
	"system/etc/security/otacerts.zip",
	"system/etc/vintf/manifest/android.hardware.boot-service.mtk.xml",
	"system/etc/vintf/manifest/android.hardware.health-service.example.xml",
	"system/lib64/librecovery_ui.so",
};

struct Header {
	uint32_t header_version = 0;
	uint32_t page_size = 0;
	uint32_t kernel_addr = 0;
	uint32_t ramdisk_addr = 0;
	uint32_t vendor_ramdisk_size = 0;
	char cmdline[2048] = {};
	uint32_t tags_addr = 0;
	char name[16] = {};
	uint32_t header_size = 0;
	uint32_t dtb_size = 0;
	uint64_t dtb_addr = 0;
	uint32_t table_size = 0;
	uint32_t table_entries = 0;
	uint32_t table_entry_size = 0;
	uint32_t bootconfig_size = 0;
};

struct Table_Entry {
	uint32_t size = 0;
	uint32_t offset = 0;
	uint32_t type = 0;
	char name[kRamdiskNameSize] = {};
	uint32_t board_id[kBoardIdWords] = {};
};

struct Image {
	std::string path;
	int fd = -1;
	uint64_t image_size = 0;
	Header header;
	std::vector<Table_Entry> entries;

	~Image() {
		if (fd >= 0) close(fd);
	}

	bool Open(const std::string& new_path, std::string& error);
	bool Read(uint64_t offset, void* buffer, size_t length, std::string& error) const;

	uint32_t Header_Pages() const {
		return (header.header_size + header.page_size - 1) / header.page_size;
	}
	uint32_t Ramdisk_Pages() const {
		return (header.vendor_ramdisk_size + header.page_size - 1) / header.page_size;
	}
	uint32_t Dtb_Pages() const {
		return (header.dtb_size + header.page_size - 1) / header.page_size;
	}
	uint64_t Ramdisk_Base() const {
		return static_cast<uint64_t>(header.page_size) * Header_Pages();
	}
	uint64_t Dtb_Offset() const {
		return Ramdisk_Base() + static_cast<uint64_t>(header.page_size) * Ramdisk_Pages();
	}
	uint64_t Table_Offset() const {
		return Dtb_Offset() + static_cast<uint64_t>(header.page_size) * Dtb_Pages();
	}
	uint64_t Bootconfig_Offset() const {
		uint32_t table_pages = (header.table_size + header.page_size - 1) / header.page_size;
		return Table_Offset() + static_cast<uint64_t>(header.page_size) * table_pages;
	}
};

uint32_t Get_U32(const uint8_t* data) {
	uint32_t value;
	memcpy(&value, data, sizeof(value));
	return value;
}

uint64_t Get_U64(const uint8_t* data) {
	uint64_t value;
	memcpy(&value, data, sizeof(value));
	return value;
}

void Put_U32(uint8_t* data, uint32_t value) {
	memcpy(data, &value, sizeof(value));
}

void Put_U64(uint8_t* data, uint64_t value) {
	memcpy(data, &value, sizeof(value));
}

bool Parse_Header(const uint8_t* data, size_t length, Header& header, std::string& error) {
	if (length < kHeaderV4Size) {
		error = "vendor_boot header is too small";
		return false;
	}
	if (memcmp(data, kVendorBootMagic, sizeof(kVendorBootMagic)) != 0) {
		error = "not a vendor_boot image";
		return false;
	}
	header.header_version = Get_U32(data + 8);
	if (header.header_version != 4) {
		error = "vendor_boot header version " + std::to_string(header.header_version) + " is not supported";
		return false;
	}
	header.page_size = Get_U32(data + 12);
	if (header.page_size < 512 || header.page_size > 65536 ||
	    (header.page_size & (header.page_size - 1)) != 0) {
		error = "invalid vendor_boot page size";
		return false;
	}
	header.kernel_addr = Get_U32(data + 16);
	header.ramdisk_addr = Get_U32(data + 20);
	header.vendor_ramdisk_size = Get_U32(data + 24);
	memcpy(header.cmdline, data + 28, sizeof(header.cmdline));
	header.cmdline[sizeof(header.cmdline) - 1] = '\0';
	header.tags_addr = Get_U32(data + 2076);
	memcpy(header.name, data + 2080, sizeof(header.name));
	header.name[sizeof(header.name) - 1] = '\0';
	header.header_size = Get_U32(data + 2096);
	header.dtb_size = Get_U32(data + 2100);
	header.dtb_addr = Get_U64(data + 2104);
	header.table_size = Get_U32(data + 2112);
	header.table_entries = Get_U32(data + 2116);
	header.table_entry_size = Get_U32(data + 2120);
	header.bootconfig_size = Get_U32(data + 2124);

	if (header.header_size < kHeaderV4Size) {
		error = "invalid vendor_boot header size";
		return false;
	}
	if (header.table_entry_size < kTableEntrySize) {
		error = "invalid vendor_boot ramdisk table entry size";
		return false;
	}
	if (header.table_entries == 0) {
		error = "vendor_boot image has an empty ramdisk table";
		return false;
	}
	if (header.table_size < header.table_entries * header.table_entry_size) {
		error = "truncated vendor_boot ramdisk table";
		return false;
	}
	return true;
}

bool Image::Open(const std::string& new_path, std::string& error) {
	path = new_path;
	fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		error = "cannot open " + path + ": " + strerror(errno);
		return false;
	}
	image_size = Get_Image_Size(path);
	if (image_size == 0) {
		error = "cannot determine the size of " + path;
		return false;
	}

	std::vector<uint8_t> page_data(4096);
	if (image_size < page_data.size()) {
		error = path + " is too small to be a vendor_boot image";
		return false;
	}
	if (!Read(0, page_data.data(), page_data.size(), error))
		return false;
	if (!Parse_Header(page_data.data(), page_data.size(), header, error))
		return false;

	uint64_t table_offset = Table_Offset();
	if (table_offset + header.table_size > image_size) {
		error = "vendor_boot ramdisk table is outside of " + path;
		return false;
	}
	for (uint32_t i = 0; i < header.table_entries; ++i) {
		uint8_t entry_data[kTableEntrySize];
		if (!Read(table_offset + static_cast<uint64_t>(i) * header.table_entry_size,
		          entry_data, sizeof(entry_data), error))
			return false;
		Table_Entry entry;
		entry.size = Get_U32(entry_data);
		entry.offset = Get_U32(entry_data + 4);
		entry.type = Get_U32(entry_data + 8);
		memcpy(entry.name, entry_data + 12, kRamdiskNameSize);
		for (uint32_t word = 0; word < kBoardIdWords; ++word)
			entry.board_id[word] = Get_U32(entry_data + 12 + kRamdiskNameSize + word * 4);

		uint64_t blob_offset = Ramdisk_Base() + entry.offset;
		if (blob_offset + entry.size > image_size) {
			error = "vendor_boot ramdisk entry is outside of " + path;
			return false;
		}
		entries.push_back(entry);
	}

	if (header.dtb_size > 0 && Dtb_Offset() + header.dtb_size > image_size) {
		error = "vendor_boot dtb is outside of " + path;
		return false;
	}
	if (header.bootconfig_size > 0 &&
	    Bootconfig_Offset() + header.bootconfig_size > image_size) {
		error = "vendor_boot bootconfig is outside of " + path;
		return false;
	}
	return true;
}

bool Image::Read(uint64_t offset, void* buffer, size_t length, std::string& error) const {
	uint8_t* output = static_cast<uint8_t*>(buffer);
	size_t done = 0;
	while (done < length) {
		ssize_t result = pread(fd, output + done, length - done, offset + done);
		if (result < 0) {
			if (errno == EINTR) continue;
			error = "failed to read from " + path + ": " + strerror(errno);
			return false;
		}
		if (result == 0) {
			error = "unexpected end of " + path;
			return false;
		}
		done += static_cast<size_t>(result);
	}
	return true;
}

const Table_Entry* Find_Recovery_Entry(const Image& image) {
	for (const auto& entry : image.entries) {
		if (strncmp(entry.name, "recovery", kRamdiskNameSize) == 0)
			return &entry;
	}
	for (const auto& entry : image.entries) {
		if (entry.type == kTypeRecovery)
			return &entry;
	}
	return nullptr;
}

bool Has_Lz4_Legacy_Magic(const Image& image, const Table_Entry& entry) {
	if (entry.size < 8)
		return false;
	uint8_t magic[4];
	std::string ignored;
	if (!image.Read(image.Ramdisk_Base() + entry.offset, magic, sizeof(magic), ignored))
		return false;
	return Get_U32(magic) == kLz4LegacyMagic;
}

bool Copy_Data(int source_fd, const std::string& source_path, uint64_t source_offset,
               uint64_t length, int destination_fd, std::string& error) {
	std::vector<uint8_t> buffer(kCopyBufferSize);
	uint64_t copied = 0;
	while (copied < length) {
		size_t chunk = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - copied));
		size_t read_done = 0;
		while (read_done < chunk) {
			ssize_t result = pread(source_fd, buffer.data() + read_done, chunk - read_done,
			                       source_offset + copied + read_done);
			if (result < 0) {
				if (errno == EINTR) continue;
				error = "failed to read from " + source_path + ": " + strerror(errno);
				return false;
			}
			if (result == 0) {
				error = "unexpected end of " + source_path;
				return false;
			}
			read_done += static_cast<size_t>(result);
		}
		size_t write_done = 0;
		while (write_done < chunk) {
			ssize_t result = write(destination_fd, buffer.data() + write_done, chunk - write_done);
			if (result < 0) {
				if (errno == EINTR) continue;
				error = "failed to write the merged image: " + std::string(strerror(errno));
				return false;
			}
			write_done += static_cast<size_t>(result);
		}
		copied += chunk;
	}
	return true;
}

bool Write_Zeroes(int fd, uint64_t length, std::string& error) {
	std::vector<uint8_t> zeroes(4096, 0);
	while (length > 0) {
		size_t chunk = static_cast<size_t>(std::min<uint64_t>(zeroes.size(), length));
		size_t done = 0;
		while (done < chunk) {
			ssize_t result = write(fd, zeroes.data() + done, chunk - done);
			if (result < 0) {
				if (errno == EINTR) continue;
				error = "failed to pad the merged image: " + std::string(strerror(errno));
				return false;
			}
			done += static_cast<size_t>(result);
		}
		length -= chunk;
	}
	return true;
}

bool Pad_To_Page(int fd, uint32_t page_size, std::string& error) {
	off_t position = lseek(fd, 0, SEEK_END);
	if (position < 0) {
		error = "failed to query the merged image size: " + std::string(strerror(errno));
		return false;
	}
	uint32_t remainder = static_cast<uint32_t>(position) % page_size;
	if (remainder == 0)
		return true;
	return Write_Zeroes(fd, page_size - remainder, error);
}

bool Write_All(int fd, const void* data, size_t length, std::string& error) {
	const uint8_t* bytes = static_cast<const uint8_t*>(data);
	size_t done = 0;
	while (done < length) {
		ssize_t result = write(fd, bytes + done, length - done);
		if (result < 0) {
			if (errno == EINTR) continue;
			error = "failed to write the merged image: " + std::string(strerror(errno));
			return false;
		}
		done += static_cast<size_t>(result);
	}
	return true;
}

bool Parse_Cpio_Hex(const uint8_t* data, uint32_t& value) {
	value = 0;
	for (int i = 0; i < 8; ++i) {
		uint8_t c = data[i];
		uint32_t digit;
		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			digit = c - 'A' + 10;
		else
			return false;
		value = (value << 4) | digit;
	}
	return true;
}

std::string Normalize_Cpio_Path(std::string name) {
	while (name.rfind("./", 0) == 0)
		name.erase(0, 2);
	while (!name.empty() && name[0] == '/')
		name.erase(0, 1);
	return name;
}

bool Is_Pruned_Cpio_Path(const std::string& name) {
	if (name == "res" || name.compare(0, 4, "res/") == 0)
		return true;
	for (const char* path : kPrunedPaths) {
		if (name == path)
			return true;
	}
	return false;
}

// Copies a newc/crc cpio archive while dropping the files that the OrangeFox
// build also removes from the stock PLATFORM ramdisk. Entries are copied
// verbatim, so permissions, symlinks, inode numbers and SELinux xattrs are all
// preserved and there is no need to regenerate cpio headers.
bool Prune_Cpio(const std::vector<uint8_t>& input, std::vector<uint8_t>& output,
                std::string& error) {
	output.clear();
	size_t position = 0;
	bool saw_trailer = false;
	while (position + 110 <= input.size()) {
		const uint8_t* header = input.data() + position;
		if (memcmp(header, "070701", 6) != 0 && memcmp(header, "070702", 6) != 0) {
			error = "invalid cpio header magic";
			return false;
		}

		uint32_t namesize = 0;
		uint32_t filesize = 0;
		if (!Parse_Cpio_Hex(header + 94, namesize) ||
		    !Parse_Cpio_Hex(header + 54, filesize)) {
			error = "invalid cpio header field";
			return false;
		}
		if (namesize == 0) {
			error = "invalid cpio file name size";
			return false;
		}

		uint64_t name_end = static_cast<uint64_t>(position) + 110 + namesize;
		uint64_t data_start = (name_end + 3) & ~static_cast<uint64_t>(3);
		uint64_t entry_end =
		    (data_start + filesize + 3) & ~static_cast<uint64_t>(3);
		if (entry_end > input.size()) {
			error = "truncated cpio entry";
			return false;
		}

		size_t name_length = strnlen(reinterpret_cast<const char*>(header + 110),
		                             namesize);
		std::string name = Normalize_Cpio_Path(
		    std::string(reinterpret_cast<const char*>(header + 110), name_length));

		if (!Is_Pruned_Cpio_Path(name)) {
			output.insert(output.end(), input.begin() + position,
			              input.begin() + entry_end);
		}

		position = static_cast<size_t>(entry_end);
		if (name == "TRAILER!!!") {
			saw_trailer = true;
			break;
		}
	}

	if (!saw_trailer) {
		error = "cpio archive has no trailer";
		return false;
	}
	return true;
}

bool Decompress_Lz4_Legacy(const Image& source, const Table_Entry& entry,
                           std::vector<uint8_t>& output, std::string& error) {
	output.clear();
	if (entry.size < sizeof(uint32_t)) {
		error = "lz4 ramdisk of " + source.path + " is too small";
		return false;
	}

	uint8_t magic[4];
	if (!source.Read(source.Ramdisk_Base() + entry.offset, magic, sizeof(magic), error))
		return false;
	if (Get_U32(magic) != kLz4LegacyMagic) {
		error = "ramdisk of " + source.path + " is not a legacy lz4 stream";
		return false;
	}

	std::vector<char> compressed(
	    static_cast<size_t>(LZ4_compressBound(kLz4LegacyBlockSize)));
	std::vector<char> uncompressed(static_cast<size_t>(kLz4LegacyBlockSize));
	uint64_t position = sizeof(uint32_t);
	while (position < entry.size) {
		if (entry.size - position < sizeof(uint32_t)) {
			error = "truncated lz4 block header in " + source.path;
			return false;
		}
		uint8_t size_data[4];
		if (!source.Read(source.Ramdisk_Base() + entry.offset + position,
		                 size_data, sizeof(size_data), error))
			return false;
		uint32_t block_size = Get_U32(size_data);
		position += sizeof(uint32_t);
		if (block_size == 0)
			break;
		if (block_size > entry.size - position) {
			error = "truncated lz4 block in " + source.path;
			return false;
		}
		if (block_size > compressed.size()) {
			error = "unsupported lz4 block size in " + source.path;
			return false;
		}
		if (!source.Read(source.Ramdisk_Base() + entry.offset + position,
		                 compressed.data(), block_size, error))
			return false;
		position += block_size;

		int unpacked = LZ4_decompress_safe(compressed.data(), uncompressed.data(),
		                                   static_cast<int>(block_size),
		                                   kLz4LegacyBlockSize);
		if (unpacked < 0) {
			error = "cannot decompress the lz4 ramdisk of " + source.path;
			return false;
		}
		if (output.size() > SIZE_MAX - static_cast<size_t>(unpacked)) {
			error = "decompressed lz4 ramdisk is too large";
			return false;
		}
		output.insert(output.end(), uncompressed.data(),
		              uncompressed.data() + unpacked);
	}
	return true;
}

bool Compress_Lz4_Legacy(const std::vector<uint8_t>& input,
                         std::vector<uint8_t>& output, std::string& error) {
	output.clear();
	output.reserve(input.size() / 2 + 64);

	uint8_t magic[4];
	Put_U32(magic, kLz4LegacyMagic);
	output.insert(output.end(), magic, magic + sizeof(magic));

	std::vector<char> compressed(
	    static_cast<size_t>(LZ4_compressBound(kLz4LegacyBlockSize)));
	size_t position = 0;
	while (position < input.size()) {
		size_t chunk = std::min<size_t>(kLz4LegacyBlockSize,
		                                input.size() - position);
		int packed = LZ4_compress_HC(
		    reinterpret_cast<const char*>(input.data() + position),
		    compressed.data(), static_cast<int>(chunk),
		    static_cast<int>(compressed.size()), kLz4CompressionLevel);
		if (packed <= 0) {
			error = "cannot recompress the pruned platform ramdisk";
			return false;
		}
		uint8_t packed_size[4];
		Put_U32(packed_size, static_cast<uint32_t>(packed));
		output.insert(output.end(), packed_size, packed_size + sizeof(packed_size));
		output.insert(output.end(), compressed.data(),
		              compressed.data() + static_cast<size_t>(packed));
		position += chunk;
	}
	return true;
}

// Decompresses a PLATFORM ramdisk, drops the files that OrangeFox ships in its
// own RECOVERY fragment, and compresses the result again. Recompressing at the
// same high level as the build is what keeps the merged image inside the
// vendor_boot partition even when the ROM used a fast lz4 level.
bool Build_Pruned_Platform(const Image& source, const Table_Entry& entry,
                           std::vector<uint8_t>& output, std::string& error) {
	std::vector<uint8_t> cpio;
	if (!Decompress_Lz4_Legacy(source, entry, cpio, error))
		return false;
	std::vector<uint8_t> pruned;
	if (!Prune_Cpio(cpio, pruned, error))
		return false;
	// The uncompressed source is no longer needed; release it before
	// compressing so recovery does not have to keep two large buffers.
	std::vector<uint8_t>().swap(cpio);
	return Compress_Lz4_Legacy(pruned, output, error);
}

struct Output_Entry {
	const Image* image = nullptr;
	Table_Entry entry;
	uint64_t source_offset = 0;
	bool use_blob = false;
	std::vector<uint8_t> blob;
};

bool Write_Header(int fd, const Header& header, uint32_t page_size, std::string& error) {
	uint32_t header_pages = (header.header_size + page_size - 1) / page_size;
	std::vector<uint8_t> data(static_cast<size_t>(header_pages) * page_size, 0);
	memcpy(data.data(), kVendorBootMagic, sizeof(kVendorBootMagic));
	Put_U32(data.data() + 8, header.header_version);
	Put_U32(data.data() + 12, header.page_size);
	Put_U32(data.data() + 16, header.kernel_addr);
	Put_U32(data.data() + 20, header.ramdisk_addr);
	Put_U32(data.data() + 24, header.vendor_ramdisk_size);
	memcpy(data.data() + 28, header.cmdline, sizeof(header.cmdline));
	Put_U32(data.data() + 2076, header.tags_addr);
	memcpy(data.data() + 2080, header.name, sizeof(header.name));
	Put_U32(data.data() + 2096, header.header_size);
	Put_U32(data.data() + 2100, header.dtb_size);
	Put_U64(data.data() + 2104, header.dtb_addr);
	Put_U32(data.data() + 2112, header.table_size);
	Put_U32(data.data() + 2116, header.table_entries);
	Put_U32(data.data() + 2120, header.table_entry_size);
	Put_U32(data.data() + 2124, header.bootconfig_size);

	size_t written = 0;
	while (written < data.size()) {
		ssize_t result = pwrite(fd, data.data() + written, data.size() - written,
		                        static_cast<off_t>(written));
		if (result < 0) {
			if (errno == EINTR) continue;
			error = "failed to write the merged header: " + std::string(strerror(errno));
			return false;
		}
		written += static_cast<size_t>(result);
	}
	return true;
}

}  // namespace

uint64_t Get_Image_Size(const std::string& path) {
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	uint64_t size = 0;
	uint64_t device_size = 0;
	if (ioctl(fd, BLKGETSIZE64, &device_size) == 0 && device_size > 0) {
		size = device_size;
	} else {
		struct stat info {};
		if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size > 0)
			size = static_cast<uint64_t>(info.st_size);
	}
	close(fd);
	return size;
}

bool Same_Image(const std::string& first, const std::string& second) {
	int first_fd = open(first.c_str(), O_RDONLY | O_CLOEXEC);
	if (first_fd < 0)
		return false;
	int second_fd = open(second.c_str(), O_RDONLY | O_CLOEXEC);
	if (second_fd < 0) {
		close(first_fd);
		return false;
	}

	uint64_t first_size = Get_Image_Size(first);
	uint64_t second_size = Get_Image_Size(second);
	bool same = first_size > 0 && first_size == second_size;

	std::vector<uint8_t> first_buffer(kCopyBufferSize);
	std::vector<uint8_t> second_buffer(kCopyBufferSize);
	uint64_t compared = 0;
	while (same && compared < first_size) {
		size_t chunk = static_cast<size_t>(std::min<uint64_t>(kCopyBufferSize, first_size - compared));
		size_t read_done = 0;
		while (read_done < chunk) {
			ssize_t result = pread(first_fd, first_buffer.data() + read_done, chunk - read_done,
			                       compared + read_done);
			if (result < 0 && errno == EINTR) continue;
			if (result <= 0) { same = false; break; }
			read_done += static_cast<size_t>(result);
		}
		read_done = 0;
		while (same && read_done < chunk) {
			ssize_t result = pread(second_fd, second_buffer.data() + read_done, chunk - read_done,
			                       compared + read_done);
			if (result < 0 && errno == EINTR) continue;
			if (result <= 0) { same = false; break; }
			read_done += static_cast<size_t>(result);
		}
		if (same && memcmp(first_buffer.data(), second_buffer.data(), chunk) != 0)
			same = false;
		compared += chunk;
	}

	close(first_fd);
	close(second_fd);
	return same;
}

bool Is_Vendor_Boot_V4(const std::string& path) {
	std::string error;
	Image image;
	return image.Open(path, error);
}

bool Merge_Vendor_Boot(const std::string& stock_image,
                       const std::string& orangefox_image,
                       const std::string& output_image,
                       uint64_t pad_to_size,
                       std::string& error) {
	Image stock;
	if (!stock.Open(stock_image, error))
		return false;
	Image orangefox;
	if (!orangefox.Open(orangefox_image, error))
		return false;

	const Table_Entry* recovery = Find_Recovery_Entry(orangefox);
	if (recovery == nullptr) {
		error = "the OrangeFox image has no RECOVERY ramdisk fragment";
		return false;
	}
	if (orangefox.header.dtb_size == 0) {
		error = "the OrangeFox image has no DTB";
		return false;
	}

	std::vector<Output_Entry> output_entries;
	for (const auto& entry : stock.entries) {
		if (entry.type == kTypeRecovery)
			continue;
		Output_Entry output;
		output.image = &stock;
		output.entry = entry;
		// Offsets in the table are relative to the start of the ramdisk area,
		// so they are rebuilt while the merged blobs are written.
		output.source_offset = stock.Ramdisk_Base() + entry.offset;
		if (entry.type == kTypePlatform && Has_Lz4_Legacy_Magic(stock, entry)) {
			std::string prune_error;
			std::vector<uint8_t> blob;
			// Older/third-party images might have a platform ramdisk that is
			// not valid cpio; copy it verbatim in that case.
			if (Build_Pruned_Platform(stock, entry, blob, prune_error) &&
			    blob.size() <= UINT32_MAX) {
				output.entry.size = static_cast<uint32_t>(blob.size());
				output.blob = std::move(blob);
				output.use_blob = true;
			}
		}
		output_entries.push_back(std::move(output));
	}
	Output_Entry recovery_output;
	recovery_output.image = &orangefox;
	recovery_output.entry = *recovery;
	recovery_output.source_offset =
	    orangefox.Ramdisk_Base() + recovery->offset;
	output_entries.push_back(std::move(recovery_output));

	if (output_entries.size() > UINT32_MAX / kTableEntrySize) {
		error = "too many vendor ramdisk entries";
		return false;
	}

	Header header = stock.header;
	header.dtb_size = orangefox.header.dtb_size;
	if (header.dtb_addr == 0)
		header.dtb_addr = orangefox.header.dtb_addr;
	header.table_entries = static_cast<uint32_t>(output_entries.size());
	header.table_entry_size = kTableEntrySize;
	header.table_size = header.table_entries * kTableEntrySize;
	header.bootconfig_size = stock.header.bootconfig_size;

	int output_fd = open(output_image.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (output_fd < 0) {
		error = "cannot create " + output_image + ": " + strerror(errno);
		return false;
	}

	// The header is written last, once the merged blob sizes are known, so
	// reserve its space here.
	uint64_t header_pages = (header.header_size + header.page_size - 1) / header.page_size;
	uint64_t header_size = static_cast<uint64_t>(header_pages) * header.page_size;
	bool ok = ftruncate(output_fd, static_cast<off_t>(header_size)) == 0 &&
	          lseek(output_fd, static_cast<off_t>(header_size), SEEK_SET) >= 0;
	if (!ok)
		error = "failed to reserve the merged header: " + std::string(strerror(errno));

	uint64_t ramdisk_size = 0;
	for (auto& entry : output_entries) {
		if (!ok)
			break;
		if (ramdisk_size > UINT32_MAX) {
			error = "invalid merged vendor ramdisk size";
			ok = false;
			break;
		}
		entry.entry.offset = static_cast<uint32_t>(ramdisk_size);
		Table_Entry source_entry = entry.entry;
		uint64_t written = 0;
		if (entry.use_blob) {
			written = entry.blob.size();
			ok = Write_All(output_fd, entry.blob.data(), entry.blob.size(), error);
			if (ok)
				entry.entry.size = static_cast<uint32_t>(written);
		} else {
			ok = Copy_Data(entry.image->fd, entry.image->path, entry.source_offset,
			               source_entry.size, output_fd, error);
			written = source_entry.size;
		}
		ramdisk_size += written;
	}
	if (ok && (ramdisk_size == 0 || ramdisk_size > UINT32_MAX)) {
		error = "invalid merged vendor ramdisk size";
		ok = false;
	}
	if (ok) {
		header.vendor_ramdisk_size = static_cast<uint32_t>(ramdisk_size);
		ok = Pad_To_Page(output_fd, header.page_size, error);
	}
	if (ok)
		ok = Copy_Data(orangefox.fd, orangefox.path, orangefox.Dtb_Offset(),
		               orangefox.header.dtb_size, output_fd, error);
	if (ok)
		ok = Pad_To_Page(output_fd, header.page_size, error);
	if (ok) {
		for (const auto& entry : output_entries) {
			uint8_t entry_data[kTableEntrySize] = {};
			Put_U32(entry_data, entry.entry.size);
			Put_U32(entry_data + 4, entry.entry.offset);
			Put_U32(entry_data + 8, entry.entry.type);
			memcpy(entry_data + 12, entry.entry.name, kRamdiskNameSize);
			for (uint32_t word = 0; word < kBoardIdWords; ++word)
				Put_U32(entry_data + 12 + kRamdiskNameSize + word * 4, entry.entry.board_id[word]);
			size_t written = 0;
			while (written < sizeof(entry_data)) {
				ssize_t result = write(output_fd, entry_data + written, sizeof(entry_data) - written);
				if (result < 0) {
					if (errno == EINTR) continue;
					error = "failed to write the merged ramdisk table: " + std::string(strerror(errno));
					ok = false;
					break;
				}
				written += static_cast<size_t>(result);
			}
			if (!ok)
				break;
		}
	}
	if (ok)
		ok = Pad_To_Page(output_fd, header.page_size, error);
	if (ok && header.bootconfig_size > 0) {
		ok = Copy_Data(stock.fd, stock.path, stock.Bootconfig_Offset(),
		               header.bootconfig_size, output_fd, error);
		if (ok)
			ok = Pad_To_Page(output_fd, header.page_size, error);
	}
	if (ok)
		ok = Write_Header(output_fd, header, header.page_size, error);

	if (ok && pad_to_size > 0) {
		off_t position = lseek(output_fd, 0, SEEK_END);
		if (position < 0 || static_cast<uint64_t>(position) > pad_to_size) {
			error = "the merged image needs " +
			        std::to_string(position < 0 ? 0 : position) +
			        " bytes but the vendor_boot partition only has " +
			        std::to_string(pad_to_size);
			ok = false;
		} else if (ftruncate(output_fd, static_cast<off_t>(pad_to_size)) != 0) {
			error = "failed to pad the merged image: " + std::string(strerror(errno));
			ok = false;
		}
	}

	if (ok && fsync(output_fd) != 0) {
		error = "failed to flush the merged image: " + std::string(strerror(errno));
		ok = false;
	}
	if (close(output_fd) != 0 && ok) {
		error = "failed to close the merged image: " + std::string(strerror(errno));
		ok = false;
	}
	if (!ok)
		unlink(output_image.c_str());
	return ok;
}

}  // namespace vbm
