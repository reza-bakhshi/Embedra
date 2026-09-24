# SPDX-FileCopyrightText: 2026 Embedra contributors
# SPDX-License-Identifier: Apache-2.0
idf_component_register(SRCS "app_main.c"
    PRIV_REQUIRES esp_timer log
    INCLUDE_DIRS ".")
