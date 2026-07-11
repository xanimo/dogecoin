// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// protocol.cpp's CMessageHeader::IsValid funnels through LogPrintStr (never on
// the CAddress deserialize path, but ASan/coverage roots it). Silence it.
#include <string>
int LogPrintStr(const std::string& /*str*/) { return 0; }
