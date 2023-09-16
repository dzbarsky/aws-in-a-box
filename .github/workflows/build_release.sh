set -eux

for GOOS in "windows" "linux" "darwin"; do
    for GOARCH in "amd64" "arm64"; do
        GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 go build -ldflags "-w" -trimpath -o "./aws-in-a-box-$GOOS-$GOARCH"
    done
done

# Set by GH actions, see
# https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
TAG=${GITHUB_REF_NAME}
# The prefix is chosen to match what GitHub generates for source archives
PREFIX="aws-in-a-box-${TAG:1}"
ARCHIVE="aws-in-a-box-$TAG.tar.gz"
git archive --format=tar --prefix="${PREFIX}/" "${TAG}" | gzip > "$ARCHIVE"
