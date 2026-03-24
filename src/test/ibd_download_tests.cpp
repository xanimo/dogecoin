// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for IBD-adaptive parallel block download limits

#include "chainparams.h"
#include "net.h"
#include "net_processing.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

// These functions are defined in net_processing.cpp and exposed for testing.
extern int GetMaxBlocksInTransitPerPeer();
extern unsigned int GetBlockDownloadWindow();

BOOST_FIXTURE_TEST_SUITE(ibd_download_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(ibd_constants_are_valid)
{
    // IBD limits must be strictly greater than normal limits
    BOOST_CHECK(MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD > MAX_BLOCKS_IN_TRANSIT_PER_PEER);
    BOOST_CHECK(BLOCK_DOWNLOAD_WINDOW_IBD > BLOCK_DOWNLOAD_WINDOW);

    // Verify the expected values
    BOOST_CHECK_EQUAL(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 16);
    BOOST_CHECK_EQUAL(MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD, 128);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_WINDOW, 1024u);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_WINDOW_IBD, 8192u);
}

BOOST_AUTO_TEST_CASE(ibd_returns_correct_limits)
{
    // IsInitialBlockDownload() uses a process-wide static latch: once it
    // returns false it can never return true again.  Because boost test
    // suites share a single process, an earlier suite may have already
    // latched it.  We therefore verify the helpers are *consistent* with
    // whatever the current IBD state happens to be.
    if (IsInitialBlockDownload()) {
        BOOST_CHECK_EQUAL(GetMaxBlocksInTransitPerPeer(), MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD);
        BOOST_CHECK_EQUAL(GetBlockDownloadWindow(), BLOCK_DOWNLOAD_WINDOW_IBD);
    } else {
        BOOST_CHECK_EQUAL(GetMaxBlocksInTransitPerPeer(), MAX_BLOCKS_IN_TRANSIT_PER_PEER);
        BOOST_CHECK_EQUAL(GetBlockDownloadWindow(), BLOCK_DOWNLOAD_WINDOW);
    }
}

BOOST_AUTO_TEST_SUITE_END()
