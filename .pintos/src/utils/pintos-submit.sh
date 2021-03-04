archive=~/CSE130-Lab3.tar
echo "Creating $archive.gz"
rm $archive* 2>/dev/null
cd ../../..
BASE=`pwd`

tar cvf $archive \
	`diff -u -r pintos .pintos | lsdiff | sed '/\.git/d' | sed 's/$BASE//' | sed '/nbproject/d'` 2>/dev/null

tar rvf $archive \
	`diff -r .pintos pintos | grep Only | sed '/\.git/d' | sed 's/: /\//' | sed '/\/\.pintos/d' | sed 's/Only in //' | sed 's/$BASE//' | sed '/^>/d'`

gzip $archive

echo ""
echo "Don't forget to upload $archive to Canvas! "
echo ""
