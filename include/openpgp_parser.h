// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * This file is part of cbom-generator.
 *
 * cbom-generator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * For commercial licensing options, contact: sales@cipheriq.io
 */

#ifndef OPENPGP_PARSER_H
#define OPENPGP_PARSER_H

#include "cbom_types.h"
#include <stdbool.h>
#include <time.h>

/**
 * Check if a file contains OpenPGP key data
 * @param filepath Path to the file to check
 * @return true if file contains OpenPGP key data, false otherwise
 */
bool is_openpgp_key_file(const char *filepath);

/**
 * Parse an OpenPGP key file and create a crypto asset
 * @param filepath Path to the OpenPGP key file
 * @return Pointer to created crypto_asset_t or NULL on failure
 */
crypto_asset_t* parse_openpgp_key(const char *filepath);

/**
 * Check if file extension suggests it might be an OpenPGP key
 * @param filepath Path to check
 * @return true if extension suggests OpenPGP key file
 */
bool has_openpgp_extension(const char *filepath);

#endif // OPENPGP_PARSER_H
