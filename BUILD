load("@rules_go//go:def.bzl", "go_binary", "go_library")
load("@gazelle//:def.bzl", "gazelle")

gazelle(name = "gazelle")

go_library(
    name = "aws-in-a-box_lib",
    srcs = ["main.go"],
    importpath = "aws-in-a-box",
    visibility = ["//visibility:private"],
    deps = [
        "//arn",
        "//http",
        "//server",
        "//services/dynamodb",
        "//services/kinesis",
        "//services/kms",
        "//services/s3",
        "//services/sqs",
    ],
)

go_binary(
    name = "aws-in-a-box",
    embed = [":aws-in-a-box_lib"],
    visibility = ["//visibility:public"],
)
