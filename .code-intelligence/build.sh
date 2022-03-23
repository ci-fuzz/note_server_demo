set -e
mkdir -p fuzzbuild
cd fuzzbuild
cmake -DLOG_SILENT=ON ..
make