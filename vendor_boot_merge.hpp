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

// Rebuilds vendor_boot v4 images by combining a stock ROM PLATFORM ramdisk with
// an OrangeFox RECOVERY ramdisk and DTB.
namespace vbm {

uint64_t Get_Image_Size(const std::string& path);

bool Same_Image(const std::string& first, const std::string& second);

bool Is_Vendor_Boot_V4(const std::string& path);

// Pads to pad_to_size bytes (0 to skip), wiping any stale AVB footer.
bool Merge_Vendor_Boot(const std::string& stock_image,
                       const std::string& orangefox_image,
                       const std::string& output_image,
                       uint64_t pad_to_size,
                       std::string& error);

bool Extract_Recovery_Ramdisk(const std::string& image,
                              const std::string& output_path,
                              std::string& error);

bool Extract_Dtb(const std::string& image, const std::string& output_path,
                 std::string& error);

bool Same_Recovery_Ramdisk(const std::string& image,
                           const std::string& recovery_ramdisk);

bool Same_Dtb(const std::string& image, const std::string& dtb_file);

// Replaces the RECOVERY ramdisk and DTB in base_image.
bool Inject_Recovery_Ramdisk(const std::string& base_image,
                             const std::string& recovery_ramdisk,
                             const std::string& dtb_file,
                             const std::string& output_image,
                             uint64_t pad_to_size,
                             std::string& error);

}  // namespace vbm

#endif  // VENDOR_BOOT_MERGE_HPP
