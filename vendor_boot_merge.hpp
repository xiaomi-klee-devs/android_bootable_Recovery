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

#ifndef VENDOR_BOOT_MERGE_HPP
#define VENDOR_BOOT_MERGE_HPP

#include <cstdint>
#include <string>

// Utilities to rebuild a vendor_boot v4 image by combining the PLATFORM
// ramdisk of a stock ROM image with the RECOVERY ramdisk fragment and the DTB
// of an OrangeFox image. Used by "Flash current OrangeFox" so that recovery
// always runs against the kernel modules and DTB matching the installed ROM.
namespace vbm {

// Returns the size of a block device in bytes, or the size of a regular file.
// Returns 0 when the size cannot be determined.
uint64_t Get_Image_Size(const std::string& path);

// True when both paths hold the same bytes. Used to detect that the live
// vendor_boot partition still holds the image that was cached at boot, in
// which case there is nothing to merge.
bool Same_Image(const std::string& first, const std::string& second);

// True when "path" starts with a vendor_boot v4 header.
bool Is_Vendor_Boot_V4(const std::string& path);

// Builds "output_image" from:
//   - every non-RECOVERY ramdisk entry (and the header fields) of stock_image;
//     lz4 PLATFORM ramdisks are unpacked, stripped of the files that OrangeFox
//     ships in its own RECOVERY fragment, and compressed again
//   - the RECOVERY ramdisk entry of orangefox_image
//   - the DTB of orangefox_image
// The result is padded with zeroes up to pad_to_size bytes (pass 0 to skip),
// which also wipes any stale AVB footer left over on the partition.
bool Merge_Vendor_Boot(const std::string& stock_image,
                       const std::string& orangefox_image,
                       const std::string& output_image,
                       uint64_t pad_to_size,
                       std::string& error);

}  // namespace vbm

#endif  // VENDOR_BOOT_MERGE_HPP
