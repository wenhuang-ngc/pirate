/*
 * This work was authored by Two Six Labs, LLC and is sponsored by a subcontract
 * agreement with Galois, Inc.  This material is based upon work supported by
 * the Defense Advanced Research Projects Agency (DARPA) under Contract No.
 * HR0011-19-C-0103.
 *
 * The Government has unlimited rights to use, modify, reproduce, release,
 * perform, display, or disclose computer software or computer software
 * documentation marked with this legend. Any reproduction of technical data,
 * computer software, or portions thereof marked with this legend must also
 * reproduce this marking.
 *
 * Copyright 2020 Two Six Labs, LLC.  All rights reserved.
 */

#include <errno.h>
#include <string>
#include "primitives.h"
#include "channel_test.hpp"

namespace GAPS {

using ::testing::WithParamInterface;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(ChannelDeviceTest, Configuration) {
    const int channel = ChannelTest::TEST_CHANNEL;
    const int flags = O_RDONLY;

    // Default configuration
    pirate_channel_param_t param;
    pirate_device_param_t *dev_param = &param.device;
    int rv = pirate_init_channel_param(DEVICE, channel, flags, &param);
    ASSERT_EQ(0, rv);
    ASSERT_EQ(0, errno);
    ASSERT_STREQ("", dev_param->path);
    ASSERT_EQ(0, dev_param->iov_len);

    // Apply configuration
    const char *test_path = "/tmp/test_path";
    const int iov_len = 42;
    strncpy(dev_param->path, test_path, sizeof(dev_param->path) - 1);
    dev_param->iov_len = iov_len;

    rv = pirate_set_channel_param(DEVICE, channel, flags, &param);
    ASSERT_EQ(0, rv);
    ASSERT_EQ(0, errno);

    pirate_channel_param_t param_get;
    pirate_device_param_t *dev_param_get = &param_get.device;
    memset(dev_param_get, 0, sizeof(*dev_param_get));

    channel_t ch =  pirate_get_channel_param(channel, flags, &param_get);
    ASSERT_EQ(DEVICE, ch);
    ASSERT_EQ(0, errno);
    ASSERT_STREQ(test_path, dev_param_get->path);
    ASSERT_EQ(iov_len, dev_param_get->iov_len);
}

TEST(ChannelDeviceTest, ConfigurationParser) {
    const int ch_num = ChannelTest::TEST_CHANNEL;
    const int flags = O_RDONLY;
    pirate_channel_param_t param;
    const pirate_device_param_t *device_param = &param.device;
    channel_t channel;

    char opt[128];
    const char *name = "device";
    const char *path = "/tmp/test_device";
    const uint32_t iov_len = 42;

    memset(&param, 0, sizeof(param));
    snprintf(opt, sizeof(opt) - 1, "%s", name);
    channel = pirate_parse_channel_param(ch_num, flags, opt, &param);
    ASSERT_EQ(INVALID, channel);
    ASSERT_EQ(EINVAL, errno);
    errno = 0;

    memset(&param, 0, sizeof(param));
    snprintf(opt, sizeof(opt) - 1, "%s,%s", name, path);
    channel = pirate_parse_channel_param(ch_num, flags, opt, &param);
    ASSERT_EQ(DEVICE, channel);
    ASSERT_EQ(0, errno);
    ASSERT_STREQ(path, device_param->path);
    ASSERT_EQ(0, device_param->iov_len);

    memset(&param, 0, sizeof(param));
    snprintf(opt, sizeof(opt) - 1, "%s,%s,%u", name, path, iov_len);
    channel = pirate_parse_channel_param(ch_num, flags, opt, &param);
    ASSERT_EQ(DEVICE, channel);
    ASSERT_EQ(0, errno);
    ASSERT_STREQ(path, device_param->path);
    ASSERT_EQ(iov_len, device_param->iov_len);
}

class DeviceTest : public ChannelTest, public WithParamInterface<int>
{
public:
    void ChannelInit() {
        int rv = pirate_init_channel_param(DEVICE, Writer.channel, O_WRONLY,
                                        &param);
        ASSERT_EQ(0, rv);
        ASSERT_EQ(0, errno);
        snprintf(param.device.path, PIRATE_DEVICE_LEN_NAME, "/tmp/gaps_dev");
        param.device.iov_len = GetParam();

        if (mkfifo(param.device.path, 0660) == -1) {
            ASSERT_EQ(EEXIST, errno);
            errno = 0;
        }

        rv = pirate_set_channel_param(DEVICE, Writer.channel, O_WRONLY, &param);
        ASSERT_EQ(0, rv);
        ASSERT_EQ(0, errno);

        rv = pirate_set_channel_param(DEVICE, Reader.channel, O_RDONLY, &param);
        ASSERT_EQ(0, rv);
        ASSERT_EQ(0, errno);
    }
};

TEST_P(DeviceTest, Run)
{
    Run();
}

// Test with IO vector sizes 0 and 16, passed as parameters
INSTANTIATE_TEST_SUITE_P(DeviceFunctionalTest, DeviceTest, 
    Values(0, ChannelTest::TEST_IOV_LEN));

} // namespace