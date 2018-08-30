# Description:
#   Auto-imported from github.com/danderson/nat/nattester

package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

go_binary(
    name = "nattester",
    srcs = ["nattester.go"],
    deps = [
        "//third_party/golang/nat",
        "//third_party/golang/nat/stun",
    ],
)
