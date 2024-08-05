load("@gazelle//:def.bzl", "gazelle")
load("@rules_go//go:def.bzl", "go_binary", "go_library")

gazelle(name = "gazelle")

go_library(
    name = "aws-in-a-box_lib",
    srcs = [
        "main.go",
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
        "@org_golang_x_sys//unix",
    ],
)

go_binary(
    name = "aws-in-a-box",
    embed = [":aws-in-a-box_lib"],
    visibility = ["//visibility:public"],
)
