echo "package main\n\nconst Version = \"$VERSION\"" > version.go
git add .
git commit -m "Update version file to $VERSION"
git tag -a $VERSION -m "$VERSION"
git push origin master $VERSION
