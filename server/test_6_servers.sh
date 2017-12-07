#!/bin/bash
for i in `seq 1 6`; do
for k in `seq 1 40`; do
curl -d 'entry=vessel='${i}' entry='${k} -X 'POST' 'http://10.1.0.'${i}':80/board' 
done
done
