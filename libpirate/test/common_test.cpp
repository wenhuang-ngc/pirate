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

#include <cstring>
#include <errno.h>
#include <gtest/gtest.h>
#include "libpirate.h"
#include "channel_test.hpp"

// Channel-type agnostic tests
namespace GAPS {

TEST(CommonChannel, InvalidOpen)
{
    int rv;

    // Invalid channel number - negative
    rv = pirate_open(-1, O_WRONLY);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EBADF, errno);
    errno = 0;

    // Invalid channel number - exceeds bound
    rv = pirate_open(PIRATE_NUM_CHANNELS, O_WRONLY);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EBADF, errno);
    errno = 0;

    // Invalid flags
    rv = pirate_open(ChannelTest::TEST_CHANNEL, O_RDWR);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EINVAL, errno);
    errno = 0;
}

TEST(CommonChannel, InvalidCLose)
{
    int rv;

    // Invalid channel number - negative
    rv = pirate_close(-1, O_WRONLY);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EBADF, errno);
    errno = 0;

    // Invalid channel number - exceeds bound
    rv = pirate_close(PIRATE_NUM_CHANNELS, O_WRONLY);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EBADF, errno);
    errno = 0;

    // Invalid flags
    rv = pirate_close(ChannelTest::TEST_CHANNEL, O_RDWR);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(EINVAL, errno);
    errno = 0;

    // Close unopened channel
    rv = pirate_close(ChannelTest::TEST_CHANNEL, O_WRONLY);
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(ENODEV, errno);
    errno = 0;
}


TEST(CommonChannel, InvalidReadWrite)
{
    int rv;
    uint8_t buf[16] = { 0 };

    // Read unopened channel
    rv = pirate_read(ChannelTest::TEST_CHANNEL, buf, sizeof(buf));
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(ENODEV, errno);
    errno = 0;

    // Write unopened channel
    rv = pirate_write(ChannelTest::TEST_CHANNEL, buf, sizeof(buf));
    ASSERT_EQ(-1, rv);
    ASSERT_EQ(ENODEV, errno);
    errno = 0;
}

} // namespace
