const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Cross-compilation options
    const build_all_targets = b.option(bool, "all-targets", "Build for all supported platforms") orelse false;

    // Add zig-tls dependency
    const tls = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });
    const tls_module = tls.module("tls");

    // Add zig-bump dependency for version management
    const bump = b.dependency("bump", .{
        .target = target,
        .optimize = optimize,
    });
    const bump_exe = bump.artifact("bump");
    b.installArtifact(bump_exe);

    if (build_all_targets) {
        // Build for all supported targets
        const targets = [_]std.Build.ResolvedTarget{
            // Linux x86_64
            b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .gnu,
            }),
            // Linux ARM64
            b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .linux,
                .abi = .gnu,
            }),
            // macOS x86_64
            b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .macos,
            }),
            // macOS ARM64 (Apple Silicon)
            b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .macos,
            }),
            // Windows x86_64
            b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .gnu,
            }),
            // Windows ARM64
            b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .windows,
                .abi = .gnu,
            }),
            // FreeBSD x86_64
            b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .freebsd,
            }),
            // FreeBSD ARM64
            b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .freebsd,
            }),
            // OpenBSD x86_64
            b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .openbsd,
            }),
        };

        for (targets) |t| {
            buildForTarget(b, t, optimize, tls_module);
        }
    } else {
        // Build for specified or native target
        buildForTarget(b, target, optimize, tls_module);
    }

    // Create the root module for native target
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("tls", tls_module);

    const exe = b.addExecutable(.{
        .name = "smtp-server",
        .root_module = root_module,
    });

    // Platform-specific linking
    linkPlatformLibraries(exe, target);

    b.installArtifact(exe);

    // User management CLI tool
    const user_cli_module = b.createModule(.{
        .root_source_file = b.path("src/user_cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const user_cli = b.addExecutable(.{
        .name = "user-cli",
        .root_module = user_cli_module,
    });
    user_cli.linkLibC();
    user_cli.linkSystemLibrary("sqlite3");
    b.installArtifact(user_cli);

    // GDPR compliance CLI tool
    const gdpr_cli_module = b.createModule(.{
        .root_source_file = b.path("src/gdpr_cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const gdpr_cli = b.addExecutable(.{
        .name = "gdpr-cli",
        .root_module = gdpr_cli_module,
    });
    gdpr_cli.linkLibC();
    gdpr_cli.linkSystemLibrary("sqlite3");
    b.installArtifact(gdpr_cli);

    // Search CLI tool
    const search_cli_module = b.createModule(.{
        .root_source_file = b.path("src/search_cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const search_cli = b.addExecutable(.{
        .name = "search-cli",
        .root_module = search_cli_module,
    });
    search_cli.linkLibC();
    search_cli.linkSystemLibrary("sqlite3");
    b.installArtifact(search_cli);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the SMTP server");
    run_step.dependOn(&run_cmd.step);

    // Create test step
    const test_step = b.step("test", "Run unit tests");

    // Add tests for each module
    const test_files = [_][]const u8{
        "src/security_test.zig",
        "src/errors_test.zig",
        "src/config_test.zig",
    };

    // RFC compliance tests
    const rfc_compliance_tests = [_][]const u8{
        "tests/rfc5321_compliance_test.zig",
        "tests/rfc5322_compliance_test.zig",
    };

    for (test_files) |test_file| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
        });
        test_module.addImport("tls", tls_module);

        const unit_tests = b.addTest(.{
            .root_module = test_module,
        });

        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }

    // RFC compliance tests
    const rfc_test_step = b.step("test-rfc", "Run RFC compliance tests");
    for (rfc_compliance_tests) |test_file| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
        });

        const compliance_tests = b.addTest(.{
            .root_module = test_module,
        });

        const run_compliance_tests = b.addRunArtifact(compliance_tests);
        rfc_test_step.dependOn(&run_compliance_tests.step);
    }

    // End-to-end tests
    const e2e_step = b.step("test-e2e", "Run end-to-end tests");
    const e2e_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const e2e_tests = b.addTest(.{
        .root_module = e2e_module,
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);
    e2e_step.dependOn(&run_e2e_tests.step);

    // Fuzzing tests
    const fuzz_step = b.step("test-fuzz", "Run fuzzing tests");
    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("tests/fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_module,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // All tests step
    const test_all_step = b.step("test-all", "Run all tests (unit + rfc + e2e + fuzz)");
    test_all_step.dependOn(test_step);
    test_all_step.dependOn(rfc_test_step);
    test_all_step.dependOn(e2e_step);
    test_all_step.dependOn(fuzz_step);

    // Cross-platform build step
    const cross_step = b.step("cross", "Build for all supported platforms");
    if (build_all_targets) {
        cross_step.dependOn(b.getInstallStep());
    }

    // Version management steps using zig-bump
    addVersionManagementSteps(b, bump_exe);
}

/// Add version management build steps
fn addVersionManagementSteps(b: *std.Build, bump_exe: *std.Build.Step.Compile) void {
    // Install zig-bump step
    const install_bump_step = b.step("install-bump", "Install zig-bump for version management");
    install_bump_step.dependOn(&b.addInstallArtifact(bump_exe, .{}).step);

    // Bump patch version
    const bump_patch = b.addRunArtifact(bump_exe);
    bump_patch.addArg("patch");
    const bump_patch_step = b.step("bump-patch", "Bump patch version (0.0.1 -> 0.0.2)");
    bump_patch_step.dependOn(install_bump_step);
    bump_patch_step.dependOn(&bump_patch.step);

    // Bump minor version
    const bump_minor = b.addRunArtifact(bump_exe);
    bump_minor.addArg("minor");
    const bump_minor_step = b.step("bump-minor", "Bump minor version (0.0.1 -> 0.1.0)");
    bump_minor_step.dependOn(install_bump_step);
    bump_minor_step.dependOn(&bump_minor.step);

    // Bump major version
    const bump_major = b.addRunArtifact(bump_exe);
    bump_major.addArg("major");
    const bump_major_step = b.step("bump-major", "Bump major version (0.0.1 -> 1.0.0)");
    bump_major_step.dependOn(install_bump_step);
    bump_major_step.dependOn(&bump_major.step);

    // Interactive bump
    const bump_interactive = b.addRunArtifact(bump_exe);
    const bump_interactive_step = b.step("bump", "Interactively select version to bump");
    bump_interactive_step.dependOn(install_bump_step);
    bump_interactive_step.dependOn(&bump_interactive.step);

    // Dry-run versions (for testing)
    const bump_patch_dry = b.addRunArtifact(bump_exe);
    bump_patch_dry.addArgs(&[_][]const u8{ "patch", "--dry-run" });
    const bump_patch_dry_step = b.step("bump-patch-dry", "Preview patch version bump");
    bump_patch_dry_step.dependOn(install_bump_step);
    bump_patch_dry_step.dependOn(&bump_patch_dry.step);

    const bump_minor_dry = b.addRunArtifact(bump_exe);
    bump_minor_dry.addArgs(&[_][]const u8{ "minor", "--dry-run" });
    const bump_minor_dry_step = b.step("bump-minor-dry", "Preview minor version bump");
    bump_minor_dry_step.dependOn(install_bump_step);
    bump_minor_dry_step.dependOn(&bump_minor_dry.step);

    const bump_major_dry = b.addRunArtifact(bump_exe);
    bump_major_dry.addArgs(&[_][]const u8{ "major", "--dry-run" });
    const bump_major_dry_step = b.step("bump-major-dry", "Preview major version bump");
    bump_major_dry_step.dependOn(install_bump_step);
    bump_major_dry_step.dependOn(&bump_major_dry.step);
}

/// Build executable for a specific target platform
fn buildForTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tls_module: *std.Build.Module,
) void {
    const target_query = target.query;
    const triple = b.fmt("{s}-{s}", .{
        @tagName(target_query.cpu_arch orelse .x86_64),
        @tagName(target_query.os_tag orelse .linux),
    });

    // Create module for this target
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("tls", tls_module);

    const exe = b.addExecutable(.{
        .name = b.fmt("smtp-server-{s}", .{triple}),
        .root_module = root_module,
    });

    // Platform-specific linking
    linkPlatformLibraries(exe, target);

    // Install to platform-specific directory
    const install = b.addInstallArtifact(exe, .{
        .dest_dir = .{
            .override = .{
                .custom = b.fmt("bin/{s}", .{triple}),
            },
        },
    });
    b.getInstallStep().dependOn(&install.step);
}

/// Link platform-specific libraries
fn linkPlatformLibraries(exe: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    const target_query = target.query;
    const os_tag = target_query.os_tag orelse .linux;

    // Link libc on all platforms
    exe.linkLibC();

    switch (os_tag) {
        .linux, .freebsd, .openbsd, .macos => {
            // Unix platforms: SQLite3
            exe.linkSystemLibrary("sqlite3");
        },
        .windows => {
            // Windows: SQLite3 (must be available in system)
            exe.linkSystemLibrary("sqlite3");
            // Windows-specific libraries
            exe.linkSystemLibrary("ws2_32"); // Winsock2
            exe.linkSystemLibrary("advapi32"); // Service management
        },
        else => {
            // Other platforms: best effort
            exe.linkSystemLibrary("sqlite3");
        },
    }
}
