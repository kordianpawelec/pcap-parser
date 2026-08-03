
for f in *.h *.c; do           
  echo "===== $f ====="
  cat "$f"
  echo
done > all_source.txt

