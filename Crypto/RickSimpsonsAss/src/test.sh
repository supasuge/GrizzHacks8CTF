#!/bin/bash
TEST_DIR={:-tests
if [ ! -d ${TEST_DIR} ]; then mkdir ${TEST_DIR}; fi

for i in {0..50}; do 
    echo 'GRIZZ{FLAG_$i}' > chal_$i.txt
    
