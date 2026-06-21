set(sls_core_files
	common.cpp
	common.hpp
	conf.cpp
	conf.hpp
	constants.hpp
	AsyncHttpClient.cpp
	AsyncHttpClient.hpp
	auth_reject_cache.cpp
	auth_reject_cache.hpp
	sls_sid.cpp
	sls_sid.hpp
	README.md
	SLSArray.cpp
	SLSArray.hpp
	SLSAudioGapFiller.cpp
	SLSAudioGapFiller.hpp
	SLSBitrateLimit.cpp
	SLSBitrateLimit.hpp
	SLSClient.cpp
	SLSClient.hpp
	SLSEpollThread.cpp
	SLSEpollThread.hpp
	SLSGroup.cpp
	SLSGroup.hpp
	SLSListenerCore.cpp
	SLSListenerAuth.cpp
	SLSListenerConfig.cpp
	SLSListenerHandler.cpp
	SLSListener.hpp
	SLSLock.hpp
	SLSLog.cpp
	SLSLog.hpp
	SLSLogCategory.hpp
	SLSLogRateLimiter.cpp
	SLSLogRateLimiter.hpp
	SLSSessionTracker.cpp
	SLSSessionTracker.hpp
	SLSSummaryLogger.cpp
	SLSSummaryLogger.hpp
	SLSManager.cpp
	SLSManager.hpp
	SLSMapData.cpp
	SLSMapData.hpp
	SLSMapPublisher.cpp
	SLSMapPublisher.hpp
	SLSMapRelay.cpp
	SLSMapRelay.hpp
	SLSPlayer.cpp
	SLSPlayer.hpp
	SLSPublisher.cpp
	SLSPublisher.hpp
	SLSPuller.cpp
	SLSPuller.hpp
	SLSPullerManager.cpp
	SLSPullerManager.hpp
	SLSPusher.cpp
	SLSPusher.hpp
	SLSPusherManager.cpp
	SLSPusherManager.hpp
	SLSPushUrlValidator.cpp
	SLSPushUrlValidator.hpp
	SLSRecycleArray.cpp
	SLSRecycleArray.hpp
	SLSRelay.cpp
	SLSRelay.hpp
	SLSRelayManager.cpp
	SLSRelayManager.hpp
	SLSRole.cpp
	SLSRole.hpp
	SLSRoleList.cpp
	SLSRoleList.hpp
	SLSSrt.cpp
	SLSSrt.hpp
	SLSSyncClock.cpp
	SLSSyncClock.hpp
	SLSThread.cpp
	SLSThread.hpp
	TCPRole.cpp
	TCPRole.hpp
	TSFileTimeReader.cpp
	TSFileTimeReader.hpp
	util.cpp
	util.hpp
)

add_library(sls_core STATIC ${sls_core_files})
target_link_libraries(sls_core
	spdlog
	nlohmann_json::nlohmann_json
	httplib
	BS_thread_pool
	Threads::Threads
	CxxUrl
)
# libstdc++fs is needed only when building against libstdc++ (Linux);
# libc++ on macOS provides std::filesystem in the main library.
if(NOT APPLE AND NOT WIN32)
	target_link_libraries(sls_core stdc++fs)
endif()
# On macOS, cpp-httplib's TLS system-cert loader uses CoreFoundation +
# Security to read the user/admin trust store.
if(APPLE)
	target_link_libraries(sls_core
		"-framework CoreFoundation"
		"-framework Security"
	)
endif()
target_include_directories(sls_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
