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

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER           "X-aws-ec2-metadata-token-ttl-seconds"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN       36

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL       "21600" // 6 hours (ie maximum ttl)
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN   5

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL                  21600

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER               "X-aws-ec2-metadata-token"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN           24

#define FLB_FILTER_AWS_IMDS_HOST                          "169.254.169.254"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH                 "/latest/api/token"

#define FLB_AWS_IMDS_ROLE_PATH                            "/latest/meta-data/iam/security-credentials/"
#define FLB_AWS_IMDS_ROLE_PATH_LEN                        43

#define FLB_AWS_IMDS_VERSION_EVALUATE                     0
#define FLB_AWS_IMDS_VERSION_1                            1
#define FLB_AWS_IMDS_VERSION_2                            2


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

/* Metadata Service Context Struct */
struct flb_aws_imds {
    /* upstream connection to ec2 IMDS */
    struct flb_upstream *ec2_upstream;

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

/* Default config values */
const struct flb_aws_imds_config_s {
    int use_imds_version;
} flb_aws_imds_config_default = {
    FLB_AWS_IMDS_VERSION_EVALUATE
};
typedef struct flb_aws_imds_config_s flb_aws_imds_config;

// Declarations
/* Obtain the IMDS version */
static int get_imds_version(struct flb_aws_imds *ctx, struct flb_http_client *client);

/* 
 * Create IMDS Context
 * Returns NULL on error
 */
struct flb_aws_imds *flb_aws_imds_create(struct flb_config *config,
                       flb_aws_imds_config *imds_config)
{
    int use_v2;
    int ret;
    struct flb_aws_imds *ctx = NULL;
    const char *tmp = NULL;

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
    
    /* Connect to upstream */
    ctx->ec2_upstream = flb_upstream_create(config,
                                            FLB_FILTER_AWS_IMDS_HOST,
                                            80,
                                            FLB_IO_TCP,
                                            NULL);

    if (!ctx->ec2_upstream) {
        flb_debug("[imds] unable to connect to EC2 IMDS upstream");
        flb_free(ctx);
        return NULL;
    }

    /* Remove async flag from upstream */
    ctx->ec2_upstream->flags &= ~(FLB_IO_ASYNC);
    return ctx;
}

/* Destroy IMDS Context */
void flb_aws_imds_destroy(struct flb_aws_imds *ctx) {
    if (ctx->ec2_upstream) {
        flb_upstream_destroy(ctx->ec2_upstream);
    }

    if (ctx->imds_v2_token) {
        flb_sds_destroy(ctx->imds_v2_token);
    }

    if (ctx->vpc_id) {
        flb_sds_destroy(ctx->vpc_id);
    }
}

/*
 * Get an IMDSv2 token
 * Token installed in imds context
 */
static int get_ec2_token(struct flb_aws_imds *ctx)
{
    int ret;
    size_t b_sent;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *client;
    
    client = imds_http_client_create(ctx, FLB_HTTP_PUT, FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH);
    if (client == NULL) {
        return -1;
    };
    u_conn = client->u_conn;

    flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN);

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_debug("[imds] IMDSv2 token request http_do=%i, HTTP Status: %i", ret, client->resp.status);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_error("[imds] IMDSv2 token retrieval failure response\n%s", client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    ctx->imds_v2_token = flb_sds_create_len(client->resp.payload,
                                            client->resp.payload_size);
    if (!ctx->imds_v2_token) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    ctx->imds_v2_token_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}

/* Get the metadata by key if the result is a json object.
 * If key is NULL, just return the value it gets.
 */
int flb_aws_imds_get_metadata_by_key(struct flb_aws_imds *ctx, char *metadata_path,
                               flb_sds_t *metadata, size_t *metadata_len,
                               char *key)
{
    int ret;
    size_t b_sent;
    flb_sds_t tmp;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *client;

    client = imds_http_client_create(ctx, FLB_HTTP_GET, metadata_path);
    if (client == NULL) {
        return -1;
    }
    u_conn = client->u_conn;

    /* Get IMDS version */
    int imds_version = get_imds_version(ctx, client);

    if (imds_version == FLB_AWS_IMDS_VERSION_2) {
        flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER,
                            FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN,
                            ctx->imds_v2_token,
                            ctx->imds_v2_token_len);
        flb_debug("[imds] using IMDSv2");
    }
    else {
        flb_debug("[imds] using IMDSv1");
    }

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_debug("[imds] metadata request http_do=%i, HTTP Status: %i",
              ret, client->resp.status);

    /* TODO: Detect invalid token */

    /* TODO: Refresh token an retry request */

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_debug("[imds] metadata request failure response\n%s",
                          client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    if (key != NULL) {
        /* get the value of the key from payload json string */
        tmp = flb_json_get_val(client->resp.payload,
                               client->resp.payload_size, key);
        if (!tmp) {
            tmp = flb_sds_create_len("NULL", 4);
            flb_error("[imds] %s is undefined in EC2 instance", key);
        }
    } else {
        tmp = flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    }

    if (!tmp) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    *metadata = tmp;
    *metadata_len = key == NULL ? client->resp.payload_size : strlen(tmp);

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}

/* Obtain the IMDS version */
static int get_imds_version(struct flb_aws_imds *ctx, struct flb_http_client *client) {
    if (ctx->imds_version != FLB_AWS_IMDS_VERSION_EVALUATE) {
        return ctx->imds_version;
    }

    // TODO: Evaluate version

}

int flb_aws_imds_get_metadata(struct flb_aws_imds *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len)
{
    return flb_aws_imds_get_metadata_by_key(ctx, metadata_path, metadata,
                               metadata_len, NULL);
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

static struct flb_http_client *imds_http_client_create(struct flb_aws_imds *ctx,
                                                       int method, char *metadata_path) {
    struct flb_http_client *client;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(ctx->ec2_upstream);
    if (!u_conn) {
        flb_error("[imds] unable to connect to EC2 IMDS upstream");
        return NULL;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn,
                             method, metadata_path,
                             NULL, 0,
                             FLB_FILTER_AWS_IMDS_HOST, 80,
                             NULL, 0);

    if (!client) {
        flb_error("[imds] failed to create http client");
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    return client;
}
