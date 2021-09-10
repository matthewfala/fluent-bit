/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/aws/flb_aws_imds.h>


#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL                  21600



#define FLB_FILTER_AWS_IMDS_HOST                          "169.254.169.254"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH                 "/latest/api/token"

#define FLB_AWS_IMDS_ROLE_PATH                            "/latest/meta-data/iam/security-credentials/"
#define FLB_AWS_IMDS_ROLE_PATH_LEN                        43


#define FLB_FILTER_AWS_IMDS_INSTANCE_ID_PATH              "/latest/meta-data/instance-id/"
#define FLB_FILTER_AWS_IMDS_AZ_PATH                       "/latest/meta-data/placement/availability-zone/"
#define FLB_FILTER_AWS_IMDS_INSTANCE_TYPE_PATH            "/latest/meta-data/instance-type/"
#define FLB_FILTER_AWS_IMDS_PRIVATE_IP_PATH               "/latest/meta-data/local-ipv4/"
#define FLB_FILTER_AWS_IMDS_VPC_ID_PATH_PREFIX            "/latest/meta-data/network/interfaces/macs/"
#define FLB_FILTER_AWS_IMDS_AMI_ID_PATH                   "/latest/meta-data/ami-id/"
#define FLB_FILTER_AWS_IMDS_ACCOUNT_ID_PATH               "/latest/dynamic/instance-identity/document/"
#define FLB_FILTER_AWS_IMDS_HOSTNAME_PATH                 "/latest/meta-data/hostname/"
#define FLB_FILTER_AWS_IMDS_MAC_PATH                      "/latest/meta-data/mac/"

#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY              "az"
#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN          2
#define FLB_FILTER_AWS_INSTANCE_ID_KEY                    "ec2_instance_id"
#define FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN                15
#define FLB_FILTER_AWS_INSTANCE_TYPE_KEY                  "ec2_instance_type"
#define FLB_FILTER_AWS_INSTANCE_TYPE_KEY_LEN              17
#define FLB_FILTER_AWS_PRIVATE_IP_KEY                     "private_ip"
#define FLB_FILTER_AWS_PRIVATE_IP_KEY_LEN                 10
#define FLB_FILTER_AWS_VPC_ID_KEY                         "vpc_id"
#define FLB_FILTER_AWS_VPC_ID_KEY_LEN                     6
#define FLB_FILTER_AWS_AMI_ID_KEY                         "ami_id"
#define FLB_FILTER_AWS_AMI_ID_KEY_LEN                     6
#define FLB_FILTER_AWS_ACCOUNT_ID_KEY                     "account_id"
#define FLB_FILTER_AWS_ACCOUNT_ID_KEY_LEN                 10
#define FLB_FILTER_AWS_HOSTNAME_KEY                       "hostname"
#define FLB_FILTER_AWS_HOSTNAME_KEY_LEN                   8

/* Request headers */
const static struct flb_aws_header imds_v2_token_ttl_header = {
    .key = "X-aws-ec2-metadata-token-ttl-seconds",
    .key_len = 36,
    .val = "21600", // 6 hours (ie maximum ttl)
    .val_len = 5,
};

/* Request header templates */
const static struct flb_aws_header imds_v2_token_token_header_template = {
    .key = "X-aws-ec2-metadata-token",
    .key_len = 24,
    .val = "",      // Replace with token value
    .val_len = 0,   // Replace with token length
};


/* Metadata Service Context Struct */
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

// typedef struct flb_aws_imds_config_s flb_aws_imds_config;

// Declarations
/* Obtain the IMDS version */
static int get_imds_version(struct flb_aws_imds *ctx, struct flb_aws_client *client);

/* 
 * Create IMDS Context
 * Returns NULL on error
 * Note: Setting the FLB_IO_ASYNC flag is the job of the client.
 */
struct flb_aws_imds *flb_aws_imds_create(struct flb_config *config,
                       struct flb_aws_imds_config *imds_config, // FLB_AWS_IMDS_VERSION_EVALUATE for automatic detection
                       struct flb_aws_client *ec2_imds_client)
{
    struct flb_aws_imds *ctx = NULL;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_aws_imds));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* 
     * Set IMDS version to whatever is specified in config
     * Version may be evaluated later if set to FLB_AWS_IMDS_VERSION_EVALUATE
     */
    ctx->imds_version = imds_config->use_imds_version;
    ctx->imds_v2_token = flb_sds_create_len("INVALID_TOKEN", 13);

    /* Detect IMDS support */
    struct flb_upstream *ec2_upstream = flb_upstream_create(config,
                                            FLB_FILTER_AWS_IMDS_HOST,
                                            80,
                                            FLB_IO_TCP,
                                            NULL);

    if (!ec2_upstream) {
        flb_debug("[imds] unable to connect to EC2 IMDS on address %s",
                  FLB_FILTER_AWS_IMDS_HOST);

        flb_free(ctx);
        return NULL;
    }
    flb_upstream_destroy(ec2_upstream);
    
    /* Connect client */
    ctx->ec2_imds_client = ec2_imds_client;

    /* Remove async flag from upstream */
    // ctx->client->flags &= ~(FLB_IO_ASYNC); // TODO: Remove, if not needed. Async setting is the job of caller.
    return ctx;
}

/*
 * Destroy IMDS Context
 * The client is responsable for destroying
 * the "ec2_imds_client" struct
 */
void flb_aws_imds_destroy(struct flb_aws_imds *ctx) {
    if (ctx->imds_v2_token) {
        flb_sds_destroy(ctx->imds_v2_token);
    }

    if (ctx->vpc_id) {
        flb_sds_destroy(ctx->vpc_id);
    }

    flb_free(ctx);
}

/* 
 * Get IMDS metadata.
 */
int flb_imds_request(struct flb_aws_imds *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len)
{
    return flb_aws_imds_get_metadata_by_key(ctx, metadata_path, metadata,
                               metadata_len, NULL);
}

/* 
 * Get IMDS metadata by key if the result is a json object.
 * If key is NULL, just return the value it gets.
 */
int flb_aws_imds_get_metadata_by_key(struct flb_aws_imds *ctx, char *metadata_path,
                               flb_sds_t *metadata, size_t *metadata_len,
                               char *key)
{
    flb_sds_t tmp;
    struct flb_upstream_conn *u_conn;
    
    struct flb_http_client *c = NULL;

    struct flb_aws_client *ec2_imds_client = ctx->ec2_imds_client;
    struct flb_aws_header token_header = imds_v2_token_token_header_template;

    /* Get IMDS version */
    int imds_version = get_imds_version(ctx, ec2_imds_client);

    /* Abort on version detection failure */
    if (imds_version == FLB_AWS_IMDS_VERSION_EVALUATE) {
        // TODO: exit gracefully allowing for retrys
    }

    if (imds_version == FLB_AWS_IMDS_VERSION_2) {
        token_header.val = ctx->imds_v2_token;
        token_header.val_len = ctx->imds_v2_token_len;
        flb_debug("[imds] using IMDSv2");
    } else {
        flb_debug("[imds] using IMDSv1");
    }

    c = ec2_imds_client->client_vtable->request(ec2_imds_client, FLB_HTTP_GET,
                                       metadata_path, NULL, 0,
                                       &token_header,
                                       (imds_version == FLB_AWS_IMDS_VERSION_1) ? 0 : 1);
    if (!c) {
        return -1;
    }

    /* TODO: Detect invalid token */
    if (imds_version == FLB_AWS_IMDS_VERSION_2 && "Placeholder") {
        /* TODO: Refresh token and retry request */
        

    }

    if (c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_debug("[imds] metadata request failure response\n%s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
        return -1;
    }

    if (key != NULL) {
        /* get the value of the key from payload json string */
        tmp = flb_json_get_val(c->resp.payload,
                               c->resp.payload_size, key);
        if (!tmp) {
            tmp = flb_sds_create_len("NULL", 4);
            flb_error("[imds] %s is undefined in EC2 instance", key);
        }
    } else {
        tmp = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
    }

    if (!tmp) {
        flb_errno();
        flb_http_client_destroy(c);
        return -1;
    }

    *metadata = tmp;
    *metadata_len = key == NULL ? c->resp.payload_size : strlen(tmp);

    flb_http_client_destroy(c);
    return 0;
}

/* Obtain the IMDS version */
static int get_imds_version(struct flb_aws_imds *ctx, struct flb_aws_client *client) {
    if (ctx->imds_version != FLB_AWS_IMDS_VERSION_EVALUATE) {
        return ctx->imds_version;
    }

    // TODO: Evaluate version

}

/* get VPC metadata, it called IMDS twice.
 * First is for getting the Mac ID and combine into the path for VPC.
 * Second call is using the VPC path to get the VPC id
 */
static int get_vpc_metadata(struct flb_aws_imds *ctx)
{
    int ret;
    flb_sds_t mac_id = NULL;
    size_t len = 0;

    /* get EC2 instance Mac id first before getting VPC id */
    ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_MAC_PATH, &mac_id, &len);

    if (ret < 0) {
        flb_sds_destroy(mac_id);
        return -1;
    }

    /* the VPC full path should be like:
     *latest/meta-data/network/interfaces/macs/{mac_id}/vpc-id/"
     */
    flb_sds_t vpc_path = flb_sds_create_size(70);
    vpc_path = flb_sds_printf(&vpc_path, "%s/%s/%s/",
                              "/latest/meta-data/network/interfaces/macs",
                              mac_id, "vpc-id");
    ret = get_metadata(ctx, vpc_path, &ctx->vpc_id, &ctx->vpc_id_len);

    flb_sds_destroy(mac_id);
    flb_sds_destroy(vpc_path);

    return ret;
}

/*
 * Get an IMDSv2 token
 * Token preserved in imds context
 */
static int get_ec2_token(struct flb_aws_imds *ctx)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_client *ec2_imds_client = ctx->ec2_imds_client;

    c = ec2_imds_client->client_vtable->request(ec2_imds_client, FLB_HTTP_PUT,
                                       FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH, NULL, 0,
                                       &imds_v2_token_ttl_header, 1);

    if (!c) {
        return -1;
    }

    if (c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_error("[imds] IMDSv2 token retrieval failure response\n%s",
                      c->resp.payload);
        }

        flb_http_client_destroy(c);
        return -1;
    }

    /* Preserve token information in ctx */
    if (c->resp.payload_size > 0) {

        ctx->imds_v2_token = flb_sds_create_len(c->resp.payload,
                                                c->resp.payload_size);
        if (!ctx->imds_v2_token) {
            flb_errno();
            flb_http_client_destroy(c);
            return -1;
        }
        ctx->imds_v2_token_len = c->resp.payload_size;

        flb_http_client_destroy(c);
        return 0;
    }

    flb_debug("[imds] IMDS metadata response was empty");
    flb_http_client_destroy(c);
    return -1;
}
