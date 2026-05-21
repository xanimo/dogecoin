// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"  // for BenchRunner
#include "key.h"    // for ECC_Start, ECC_Stop
#include "util.h"   // for SetupEnvironment, g_logger
#include "logging.h"
#include "random.h"

int
main(int argc, char** argv)
{
    RandomInit();
    ECC_Start();
    SetupEnvironment();
    g_logger->m_print_to_file = false; // don't want to write to debug.log file

    benchmark::BenchRunner::RunAll();

    ECC_Stop();
}
