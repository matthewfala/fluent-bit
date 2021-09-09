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

/* Default config values */
struct flb_aws_imds_config {
    int use_imds_version;
};

/* Default config values */
const struct flb_aws_imds_config flb_aws_imds_config_default = {
    FLB_AWS_IMDS_VERSION_EVALUATE
};

#endif
