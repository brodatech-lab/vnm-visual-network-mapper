# ---------------------------------------------------------------------------
# Native 2D GUI target (Dear ImGui docking).
#
# Status: pending. The GUI milestone will vendor Dear ImGui + GLFW through
# FetchContent and render the TopologyLayout produced by vnm_core.
#
# This file intentionally does not fail the build while the backend is being
# developed; configure with -DVNM_BUILD_GUI=ON to see this notice.
# ---------------------------------------------------------------------------
message(STATUS "VNM: GUI target requested but not implemented yet (core-first milestone).")
message(STATUS "VNM: the Dear ImGui + GLFW integration is the next milestone.")
