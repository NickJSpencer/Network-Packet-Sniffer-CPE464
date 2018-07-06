#!/bin/sh

# Nick's Patented Beautiful little test script!

for testInput in ./Files/*.pcap; do
   #Strip off file extension
   name=${testInput%.pcap}

   #Run the test
   ./trace $testInput > $name.test

   echo $name "file running"

   #Diff the results
   diff -w -B $name.test $name.out
done
