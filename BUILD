load("@gazelle//:def.bzl", "gazelle")
load("@rules_go//go:def.bzl", "go_binary", "go_library")

gazelle(name = "gazelle")

go_library(
    name = "aws-in-a-box_lib",
    srcs = [
        "main.go",
        "main_unix.go",
        "main_windows.go",
        "version.go",
    ],
    importpath = "aws-in-a-box",
    visibility = ["//visibility:private"],
    x_defs = {
        "aws-in-a-box.BazelSuffix": " (Bazel)",
    },
    deps = [
        "//arn",
        "//http",
        "//server",
        "//services/dynamodb",
        "//services/kinesis",
        "//services/kms",
        "//services/s3",
        "//services/sqs",
    ] + select({
        "@rules_go//go/platform:aix": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:android": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:darwin": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:dragonfly": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:freebsd": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:illumos": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:ios": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:linux": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:netbsd": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:openbsd": [
            "@org_golang_x_sys//unix",
        ],
        "@rules_go//go/platform:solaris": [
            "@org_golang_x_sys//unix",
        ],
        "//conditions:default": [],
    }),
)

go_binary(
    name = "aws-in-a-box",
    embed = [":aws-in-a-box_lib"],
    visibility = ["//visibility:public"],
)
