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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace vbm {
namespace {

constexpr char kVendorBootMagic[8] = {'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'};
constexpr uint32_t kHeaderV4Size = 2128;
constexpr uint32_t kTableEntrySize = 108;
constexpr uint32_t kRamdiskNameSize = 32;
constexpr uint32_t kBoardIdWords = 16;
constexpr uint32_t kTypeRecovery = 2;
constexpr size_t kCopyBufferSize = 1024 * 1024;

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

struct Output_Entry {
	const Image* image;
	Table_Entry entry;
	uint64_t source_offset;
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
		ssize_t result = write(fd, data.data() + written, data.size() - written);
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
	uint64_t total_ramdisk_size = 0;
	auto add_entry = [&output_entries, &total_ramdisk_size](const Image* image,
	                                                       Table_Entry entry) {
		// Offsets in the table are relative to the start of the ramdisk area,
		// so they have to be rebuilt for the merged layout.
		uint64_t source_offset = image->Ramdisk_Base() + entry.offset;
		entry.offset = static_cast<uint32_t>(total_ramdisk_size);
		output_entries.push_back({image, entry, source_offset});
		total_ramdisk_size += entry.size;
	};
	for (const auto& entry : stock.entries) {
		if (entry.type == kTypeRecovery)
			continue;
		add_entry(&stock, entry);
	}
	add_entry(&orangefox, *recovery);

	if (total_ramdisk_size == 0 || total_ramdisk_size > UINT32_MAX) {
		error = "invalid merged vendor ramdisk size";
		return false;
	}
	if (output_entries.size() > UINT32_MAX / kTableEntrySize) {
		error = "too many vendor ramdisk entries";
		return false;
	}

	Header header = stock.header;
	header.vendor_ramdisk_size = static_cast<uint32_t>(total_ramdisk_size);
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

	bool ok = Write_Header(output_fd, header, header.page_size, error);
	if (ok) {
		for (const auto& entry : output_entries) {
			ok = Copy_Data(entry.image->fd, entry.image->path,
			               entry.source_offset,
			               entry.entry.size, output_fd, error);
			if (!ok)
				break;
		}
	}
	if (ok)
		ok = Pad_To_Page(output_fd, header.page_size, error);
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

	if (ok && pad_to_size > 0) {
		off_t position = lseek(output_fd, 0, SEEK_END);
		if (position < 0 || static_cast<uint64_t>(position) > pad_to_size) {
			error = "the merged image does not fit in " + std::to_string(pad_to_size) + " bytes";
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
