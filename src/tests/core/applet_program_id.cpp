// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include "core/file_sys/nca_metadata.h"
#include "core/file_sys/registered_cache.h"
#include "core/file_sys/vfs/vfs_vector.h"
#include "core/hle/service/am/process_creation.h"

TEST_CASE("Guest browser selects installed replacements instead of firmware stubs", "[applet]") {
    using Service::AM::AppletProgramId;
    using Service::AM::ResolveGuestAppletProgramId;
    FileSys::ManualContentProvider storage;
    const auto add = [&](AppletProgramId id, FileSys::ContentRecordType type) {
        storage.AddEntry(FileSys::TitleType::SystemProgram, type, static_cast<u64>(id),
                         std::make_shared<FileSys::VectorVfsFile>());
    };
    for (const auto id :
         {AppletProgramId::Web, AppletProgramId::WebAuth, AppletProgramId::LoginShare}) {
        add(id, FileSys::ContentRecordType::Program);
        REQUIRE(ResolveGuestAppletProgramId(id, storage) == id);
    }
    add(AppletProgramId::OpenWeb, FileSys::ContentRecordType::Data);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::Web, storage) == AppletProgramId::Web);
    add(AppletProgramId::OpenWeb, FileSys::ContentRecordType::Program);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::Web, storage) == AppletProgramId::OpenWeb);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::WebAuth, storage) ==
            AppletProgramId::OpenWeb);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::LoginShare, storage) ==
            AppletProgramId::LoginShare);
    add(AppletProgramId::SystemWeb, FileSys::ContentRecordType::Program);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::LoginShare, storage) ==
            AppletProgramId::SystemWeb);
    REQUIRE(ResolveGuestAppletProgramId(AppletProgramId::OfflineWeb, storage) ==
            AppletProgramId::OfflineWeb);
    REQUIRE(ResolveGuestAppletProgramId(static_cast<AppletProgramId>(0), storage) ==
            static_cast<AppletProgramId>(0));
}
