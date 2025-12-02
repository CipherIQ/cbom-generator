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

#ifndef ERROR_REMEDIATION_H
#define ERROR_REMEDIATION_H

#include "certificate_scanner.h"
#include <stdbool.h>

// Get remediation suggestion for a certificate failure reason
const char* error_get_remediation_suggestion(cert_failure_reason_t reason);

// Get impact level ("critical", "high", "medium", "low")
const char* error_get_impact_level(cert_failure_reason_t reason);

// Get detailed error explanation
const char* error_get_details(cert_failure_reason_t reason);

// Check if error is actionable by the user
bool error_is_actionable(cert_failure_reason_t reason);

// Get user-friendly category name
const char* error_get_category_name(cert_failure_reason_t reason);

// Extract failure reason from error message text
cert_failure_reason_t error_extract_failure_reason_from_message(const char* message);

// Check if error is from certificate scanner (should have remediation)
bool error_is_certificate_scanner_error(const char* component);

#endif // ERROR_REMEDIATION_H
