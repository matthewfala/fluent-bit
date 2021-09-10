/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_AWS_IMDS
#define FLB_AWS_IMDS

#define FLB_AWS_IMDS_VERSION_EVALUATE                     0
#define FLB_AWS_IMDS_VERSION_1                            1
#define FLB_AWS_IMDS_VERSION_2                            2

/* IMDS config values */
struct flb_aws_imds_config {
    int use_imds_version;  // FLB_AWS_IMDS_VERSION_EVALUATE for automatic detection
};

/* Default config values */
const struct flb_aws_imds_config flb_aws_imds_config_default;

/* Metadata service context struct */
struct flb_aws_imds {
    /* AWS Client to perform mockable requests to IMDS */
    struct flb_aws_client *ec2_imds_client;

    /*
     * IMDSv2 requires a token which must be present in metadata requests
     * This plugin does not refresh the token
     */
    flb_sds_t imds_v2_token;
    size_t imds_v2_token_len;

    /* 
     * Plugin can use EC2 metadata v1 or v2; default is FLB_AWS_IMDS_VERSION_EVALUATE
     * which is evaluated to FLB_AWS_IMDS_VERSION_1 or FLB_AWS_IMDS_VERSION_2 when
     * the IMDS is used.
     */
    int imds_version;

    /* EC2 Metadata fields to populate
     */
    flb_sds_t vpc_id;
    size_t vpc_id_len;
};

/* 
 * Create IMDS context
 * Returns NULL on error
 * Note: Setting the FLB_IO_ASYNC flag is the job of the client.
 */
struct flb_aws_imds *flb_aws_imds_create(struct flb_config *config,
                       struct flb_aws_imds_config *imds_config,
                       struct flb_aws_client *ec2_imds_client);

/*
 * Destroy IMDS context
 * The client is responsable for destroying
 * the "ec2_imds_client" struct.
 */
void flb_aws_imds_destroy(struct flb_aws_imds *ctx);

/* 
 * Get IMDS metadata.
 */
int flb_aws_imds_request(struct flb_aws_imds *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len);

/* 
 * Get IMDS metadata by key
 * Expects metadata to be in a json object format.
 * Returns NULL if key not found.
 * If key is NULL, returns the full metadata value.
 */
int flb_aws_imds_request_by_key(struct flb_aws_imds *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len, char *key);

#endif
